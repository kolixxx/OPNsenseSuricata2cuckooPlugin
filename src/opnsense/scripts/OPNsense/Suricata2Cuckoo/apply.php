#!/usr/local/bin/php
<?php

/*
 * Suricata2Cuckoo apply script (configd action).
 *
 * - Generates /usr/local/etc/suricata/rules/file-extract.rules
 * - Ensures file-extract.rules is enabled in OPNsense IDS files list
 * - Enables IDS prerequisites requested by the plugin user
 * - Reloads IDS rules (configctl ids reload)
 * - Restarts suricata2cuckoo service
 */

require_once("script/load_phalcon.php");

use OPNsense\Core\Config;

const RULES_DIR = '/usr/local/etc/suricata/rules';
const FILE_EXTRACT_RULES = '/usr/local/etc/suricata/rules/file-extract.rules';
const FILESTORE_DIR = '/var/log/suricata/filestore';
const SURICATA2CUCKOO_CONF = '/usr/local/etc/suricata2cuckoo/suricata2cuckoo.conf';

const SID_BASE = 1000001;
const SID_MAX = 1000999;

function sh($cmd) {
    $output = [];
    $rc = 0;
    exec($cmd . " 2>&1", $output, $rc);
    return [$rc, implode("\n", $output)];
}

function ensure_dir($path, $mode) {
    if (!is_dir($path)) {
        @mkdir($path, $mode, true);
    }
    @chmod($path, $mode);
}

function norm_ext_list($raw) {
    $raw = trim((string)$raw);
    if ($raw === '') {
        return [];
    }
    $parts = preg_split('/[,\s]+/', $raw);
    $out = [];
    $seen = [];
    foreach ($parts as $p) {
        $p = strtolower(trim($p));
        if ($p === '') {
            continue;
        }
        if (substr($p, 0, 1) === '.') {
            $p = substr($p, 1);
        }
        $p = preg_replace('/[^a-z0-9]+/', '', $p);
        if ($p === '' || isset($seen[$p])) {
            continue;
        }
        $seen[$p] = true;
        $out[] = $p;
    }
    return $out;
}

function generate_rules($protocols, $exts) {
    $lines = [];
    $sid = SID_BASE;
    foreach ($protocols as $proto) {
        foreach ($exts as $ext) {
            if ($sid > SID_MAX) {
                throw new \RuntimeException("SID range exhausted (1000001–1000999). Reduce protocols/extensions.");
            }
            $msg = sprintf('FILESTORE .%s', strtoupper($ext));
            $lines[] = sprintf(
                'alert %s any any -> any any (msg:"%s"; fileext:"%s"; filestore; sid:%d; rev:1;)',
                $proto,
                $msg,
                $ext,
                $sid
            );
            $sid++;
        }
    }
    return implode("\n", $lines) . "\n";
}

function sx_child($parent, $name) {
    if (!isset($parent->$name)) {
        $parent->addChild($name);
    }
    return $parent->$name;
}

function sx_set($parent, $name, $value) {
    $child = sx_child($parent, $name);
    $child[0] = (string)$value;
    return $child;
}

try {
    $cfg = Config::getInstance()->object();

    // Read our plugin settings from config.xml
    $s2c = sx_child($cfg->OPNsense, 'suricata2cuckoo');
    $gen = sx_child($s2c, 'general');

    $enabled = ((string)($gen->Enabled ?? '0')) === '1';
    if (!$enabled) {
        echo json_encode(['result' => 'disabled']);
        exit(0);
    }

    // protocols (multi-select OptionField): stored as repeated nodes or csv depending on framework.
    // Handle both: <Protocols>http</Protocols><Protocols>smtp</Protocols> OR "http,smtp"
    $protocols = [];
    if (isset($gen->Protocols)) {
        foreach ($gen->Protocols as $p) {
            $p = strtolower(trim((string)$p));
            if ($p !== '') {
                $protocols[] = $p;
            }
        }
    }
    if (count($protocols) === 0) {
        $praw = trim((string)($gen->Protocols ?? ''));
        if ($praw !== '' && strpos($praw, ',') !== false) {
            foreach (explode(',', $praw) as $p) {
                $p = strtolower(trim($p));
                if ($p !== '') {
                    $protocols[] = $p;
                }
            }
        }
    }
    if (count($protocols) === 0) {
        $protocols = ['http'];
    }

    $exts = norm_ext_list((string)($gen->FileExtensions ?? 'doc,docx,pdf,zip,exe'));

    // Ensure directories / permissions (as in your docs)
    ensure_dir('/usr/local/etc/suricata2cuckoo', 0755);
    ensure_dir(RULES_DIR, 0755);
    ensure_dir(FILESTORE_DIR, 0755);

    // Render suricata2cuckoo.conf from template package
    [$rcTpl, $outTpl] = sh('/usr/local/sbin/configctl template reload OPNsense/Suricata2Cuckoo');
    if ($rcTpl !== 0) {
        throw new \RuntimeException("template reload failed: " . $outTpl);
    }
    @chmod(SURICATA2CUCKOO_CONF, 0644);

    // Generate rule file
    $rules = generate_rules($protocols, $exts);
    $tmp = FILE_EXTRACT_RULES . '.tmp';
    file_put_contents($tmp, $rules);
    rename($tmp, FILE_EXTRACT_RULES);
    @chmod(FILE_EXTRACT_RULES, 0644);

    // Ensure IDS contains file-extract.rules in <OPNsense><IDS><files>
    $ids = sx_child($cfg->OPNsense, 'IDS');
    $idsFiles = sx_child($ids, 'files');

    $found = false;
    if (isset($idsFiles->file)) {
        foreach ($idsFiles->file as $fileNode) {
            if ((string)$fileNode->filename === 'file-extract.rules') {
                sx_set($fileNode, 'enabled', '1');
                $found = true;
                break;
            }
        }
    }
    if (!$found) {
        $new = $idsFiles->addChild('file');
        $new->addAttribute('uuid', trim((string)exec('/usr/bin/uuidgen')));
        $new->addChild('filename', 'file-extract.rules');
        $new->addChild('enabled', '1');
    }

    // Enable IDS prerequisites (minimal subset, matching your config.xml structure)
    $idsGeneral = sx_child($ids, 'general');

    $enableEveSyslog = ((string)($gen->EnableEveSyslog ?? '1')) === '1';
    $enableEveHttp = ((string)($gen->EnableEveHttp ?? '1')) === '1';
    $enableEveFiles = ((string)($gen->EnableEveFiles ?? '1')) === '1';
    $enableFileStore = ((string)($gen->EnableFileStore ?? '1')) === '1';

    if ($enableEveSyslog) {
        sx_set($idsGeneral, 'syslog_eve', '1');
    }

    $eveLog = sx_child($idsGeneral, 'eveLog');
    $eveHttp = sx_child($eveLog, 'http');
    if ($enableEveHttp) {
        sx_set($eveHttp, 'enable', '1');
    }

    // These keys may not exist in stock config.xml, but OPNsense generator may pick them up if present.
    if ($enableEveFiles) {
        $eveFiles = sx_child($eveLog, 'files');
        sx_set($eveFiles, 'enable', '1');
        sx_set($eveFiles, 'force_magic', '1');
        sx_set($eveFiles, 'force_hash', 'md5,sha256');
    }
    if ($enableFileStore) {
        $fileStore = sx_child($idsGeneral, 'fileStore');
        sx_set($fileStore, 'enable', '1');
    }

    // Save config with an audit log entry
    Config::getInstance()->save([
        'username' => 'suricata2cuckoo',
        'time' => microtime(true),
        'description' => 'Suricata2Cuckoo apply',
    ]);

    // Reload IDS rules (as validated)
    [$rcIds, $outIds] = sh('/usr/local/sbin/configctl ids reload');
    if ($rcIds !== 0) {
        throw new \RuntimeException("ids reload failed: " . $outIds);
    }

    // Restart service
    sh('/usr/sbin/service suricata2cuckoo restart');

    echo json_encode(['result' => 'ok']);
    exit(0);
} catch (\Throwable $e) {
    echo json_encode(['error' => $e->getMessage()]);
    exit(1);
}

