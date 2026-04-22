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
const SURICATA_YAML = '/usr/local/etc/suricata/suricata.yaml';

const SID_BASE = 1000001;
const SID_MAX = 1000999;

function sh($cmd) {
    $output = [];
    $rc = 0;
    exec($cmd . " 2>&1", $output, $rc);
    return [$rc, implode("\n", $output)];
}

function suricata_yaml_filestore_enabled_state($path)
{
    if (!is_readable($path)) {
        return null;
    }
    $src = file_get_contents($path);
    if (preg_match('/^\\s*(?:-\\s*)?file-store:\\s*\\R(?:^\\s+.*\\R)*?^\\s+enabled:\\s*(\\S+)\\s*$/im', $src, $m)) {
        return strtolower(trim($m[1]));
    }
    return 'missing';
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

function patch_suricata_yaml_for_filestore($path)
{
    if (!is_readable($path)) {
        throw new \RuntimeException("suricata.yaml not readable: {$path}");
    }
    $src = file_get_contents($path);
    $orig = $src;

    // 1) Enable file-store output (handle both "- file-store:" and "file-store:")
    // Typical block:
    // - file-store:
    //   version: 2
    //   enabled: no|false|0
    $before = $src;
    $src = preg_replace(
        '/(^\\s*(?:-\\s*)?file-store:\\s*\\R(?:^\\s+.*\\R)*?^\\s+enabled:\\s*)(?:no|false|0)\\b/im',
        '$1yes',
        $src
    );

    // If file-store block exists but has no enabled line, insert enabled: yes after header
    if ($src === $before && preg_match('/^\\s*(?:-\\s*)?file-store:\\s*$/m', $src)) {
        $src = preg_replace(
            '/(^\\s*(?:-\\s*)?file-store:\\s*\\R)/m',
            "$1  enabled: yes\n",
            $src,
            1
        );
    }

    // If file-store output block is completely missing, add it under "outputs:"
    if (!preg_match('/^\\s*(?:-\\s*)?file-store:\\s*$/m', $src)) {
        if (preg_match('/^(\\s*)outputs:\\s*$/m', $src, $om)) {
            $o = $om[1];
            $insert =
                $o . "  - file-store:\n" .
                $o . "    enabled: yes\n" .
                $o . "    version: 2\n";
            $src = preg_replace('/^(\\s*)outputs:\\s*$/m', "$0\n" . $insert, $src, 1);
        }
    }

    // 2) Ensure eve-log "files" type is enabled with force-magic + force-hash
    // We patch the FIRST eve-log output block under "outputs:".
    // Find " - eve-log:" and inside its "types:" list ensure "- files:" exists and configured.
    if (preg_match('/(^\\s*-\\s*eve-log:\\s*\\R(?:^\\s+.*\\R)*?^\\s+types:\\s*\\R)([\\s\\S]*?)(^\\s*-\\s+[a-z0-9_-]+:\\s*\\R)/mi', $src, $m)) {
        $prefix = $m[1];
        $typesBlock = $m[2];
        $suffixStart = $m[3];
        $listIndent = "  ";
        if (preg_match('/^(\\s*)-\\s+/m', $typesBlock, $im)) {
            $listIndent = $im[1];
        }
        $childIndent = $listIndent . "  ";

        // if typesBlock already contains "- files:" keep it, but enforce settings
        if (preg_match('/^\\s*-\\s*files:\\s*\\R/m', $typesBlock)) {
            // ensure force-magic yes
            $typesBlock = preg_replace('/(^\\s*-\\s*files:\\s*\\R)(^\\s+force-magic:\\s*).*$/m', '$1$2 yes', $typesBlock, 1);
            // if force-magic line missing, insert it
            if (!preg_match('/^\\s+force-magic:\\s*/m', $typesBlock)) {
                $typesBlock = preg_replace('/(^\\s*-\\s*files:\\s*\\R)/m', "$1  force-magic: yes\n", $typesBlock, 1);
            }
            // ensure force-hash has md5, sha256
            if (preg_match('/^\\s+force-hash:\\s*\\[(.*?)\\]\\s*$/m', $typesBlock)) {
                $typesBlock = preg_replace('/^\\s+force-hash:\\s*\\[.*?\\]\\s*$/m', '  force-hash: [md5, sha256]', $typesBlock, 1);
            } else {
                $typesBlock = preg_replace('/(^\\s*-\\s*files:\\s*\\R(?:^\\s+.*\\R)*)/m', "$1  force-hash: [md5, sha256]\n", $typesBlock, 1);
            }
        } else {
            // Insert new files type at top of types list
            $typesBlock =
                $listIndent . "- files:\n" .
                $childIndent . "force-magic: yes\n" .
                $childIndent . "force-hash: [md5, sha256]\n" .
                $typesBlock;
        }

        $src = str_replace($prefix . $m[2] . $suffixStart, $prefix . $typesBlock . $suffixStart, $src);
    }

    if ($src !== $orig) {
        $tmp = $path . '.tmp';
        file_put_contents($tmp, $src);
        rename($tmp, $path);
    }
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

    // Restart IDS (this may regenerate suricata.yaml from config.xml)
    [$rcIdsRestart, $outIdsRestart] = sh('/usr/local/sbin/configctl ids restart');

    // OPNsense IDS generator may not expose file-store/eve files toggles.
    // Patch generated suricata.yaml after IDS restart, then restart Suricata to load it.
    patch_suricata_yaml_for_filestore(SURICATA_YAML);
    $stateAfterPatch = suricata_yaml_filestore_enabled_state(SURICATA_YAML);
    [$rcSuricataRestart, $outSuricataRestart] = sh('/usr/sbin/service suricata restart');

    // Restart service
    [$rcS2cRestart, $outS2cRestart] = sh('/usr/sbin/service suricata2cuckoo restart');

    echo json_encode([
        'result' => 'ok',
        'ids_reload' => ['rc' => $rcIds, 'out' => $outIds],
        'ids_restart' => ['rc' => $rcIdsRestart, 'out' => $outIdsRestart],
        'suricata_yaml_file_store_enabled' => $stateAfterPatch,
        'suricata_restart' => ['rc' => $rcSuricataRestart, 'out' => $outSuricataRestart],
        'suricata2cuckoo_restart' => ['rc' => $rcS2cRestart, 'out' => $outS2cRestart],
    ]);
    exit(0);
} catch (\Throwable $e) {
    echo json_encode(['error' => $e->getMessage()]);
    exit(1);
}

