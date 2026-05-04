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
const SURICATA_CUSTOM_YAML = '/usr/local/etc/suricata/custom.yaml';
const CONFIGD_ACTIONS = '/usr/local/etc/configd/actions.d/actions_suricata2cuckoo.conf';

const SID_BASE = 1000001;
const SID_MAX = 1000999;

function ensure_apply_runtime_ok(): void
{
    // Dev installs often lose +x on copied scripts; configd requires executable script actions.
    $self = __FILE__;
    if (is_file($self)) {
        $mode = fileperms($self);
        if ($mode !== false && (($mode & 0111) === 0)) {
            @chmod($self, 0755);
        }
    }

    if (!is_file(CONFIGD_ACTIONS)) {
        throw new \RuntimeException(
            "Missing configd actions file: " . CONFIGD_ACTIONS .
            " (copy src/opnsense/service/conf/actions.d/actions_suricata2cuckoo.conf and run: service configd restart)"
        );
    }
}

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

function suricata_custom_yaml_outputs_state($path): array
{
    if (!is_readable($path)) {
        return ['readable' => false];
    }
    $src = file_get_contents($path);
    $out = ['readable' => true];

    // file-store enabled?
    if (preg_match('/^\\s*-\\s*file-store:\\s*\\R(?:^\\s+.*\\R)*?^\\s+enabled:\\s*(\\S+)\\s*$/im', $src, $m)) {
        $out['file_store_enabled'] = strtolower(trim($m[1]));
    } else {
        $out['file_store_enabled'] = 'missing';
    }

    // eve-log files enabled? (presence of "- files:" under an eve-log types list)
    $out['eve_files_present'] = preg_match('/^\\s*-\\s*eve-log:\\s*\\R[\\s\\S]*?^\\s*types:\\s*\\R[\\s\\S]*?^\\s*-\\s*files:\\s*$/im', $src) ? 'yes' : 'no';

    return $out;
}

function write_suricata_custom_yaml($path, bool $enableFileStore, bool $enableEveFiles): void
{
    // Use Suricata's supported include mechanism: suricata.yaml has `include: - custom.yaml`.
    // Keep this file minimal and indentation-safe.
    $lines = [];
    // Suricata expects included YAML files to be standalone YAML documents.
    // Without these headers Suricata fails with:
    // "The configuration file must begin with the following two lines: %YAML 1.1 and ---"
    $lines[] = "%YAML 1.1";
    $lines[] = "---";
    $lines[] = "# Managed by OPNsense Suricata2Cuckoo plugin.";
    $lines[] = "# This file is included from /usr/local/etc/suricata/suricata.yaml (include: - custom.yaml).";
    $lines[] = "";
    $lines[] = "outputs:";
    if ($enableFileStore) {
        $lines[] = "  - file-store:";
        $lines[] = "      enabled: yes";
        $lines[] = "      version: 2";
    }
    if ($enableEveFiles) {
        $lines[] = "  - eve-log:";
        $lines[] = "      types:";
        $lines[] = "        - files:";
        $lines[] = "            force-magic: yes";
        $lines[] = "            force-hash: [md5, sha256]";
    }
    $lines[] = "";

    $tmp = $path . '.tmp';
    file_put_contents($tmp, implode("\n", $lines));
    rename($tmp, $path);
    @chmod($path, 0644);
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

    // Helper: compute indent for child keys under a YAML map key line.
    $childIndentFor = function (string $keyLine): string {
        if (preg_match('/^(\\s*)/', $keyLine, $m)) {
            return $m[1] . "  ";
        }
        return "  ";
    };

    // Helper: determine list item indent under "outputs:" (indent of "- ").
    $outputsListIndent = null;
    if (preg_match('/^(\\s*)outputs:\\s*$\\R(\\s*)-\\s+/m', $src, $om)) {
        $outputsListIndent = $om[2];
    }

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
        $src = preg_replace_callback(
            '/(^\\s*(?:-\\s*)?file-store:\\s*\\R)/m',
            function ($m) use ($childIndentFor) {
                $indent = $childIndentFor($m[1]);
                return $m[1] . $indent . "enabled: yes\n";
            },
            $src,
            1
        );
    }

    // If file-store output block is completely missing, add it under "outputs:"
    if (!preg_match('/^\\s*(?:-\\s*)?file-store:\\s*$/m', $src)) {
        if (preg_match('/^(\\s*)outputs:\\s*$/m', $src, $om)) {
            $o = $om[1];
            $li = $outputsListIndent ?? ($o . "  ");
            $ci = $li . "  ";
            $insert =
                $li . "- file-store:\n" .
                $ci . "enabled: yes\n" .
                $ci . "version: 2\n";
            $src = preg_replace('/^(\\s*)outputs:\\s*$/m', "$0\n" . $insert, $src, 1);
        }
    }

    // NOTE: This function is kept for backwards compatibility but should no longer be used.
    // We now write /usr/local/etc/suricata/custom.yaml instead (safe include-based override).

    if ($src !== $orig) {
        $tmp = $path . '.tmp';
        file_put_contents($tmp, $src);
        rename($tmp, $path);
    }
}

try {
    ensure_apply_runtime_ok();

    $cfg = Config::getInstance()->object();

    // Read our plugin settings from config.xml
    $s2c = sx_child($cfg->OPNsense, 'suricata2cuckoo');
    $gen = sx_child($s2c, 'general');

    $enabled = ((string)($gen->Enabled ?? '0')) === '1';
    if (!$enabled) {
        echo json_encode(['result' => 'disabled']);
        exit(0);
    }

    // protocols: TextField "http, smtp" / "http smtp"; legacy repeated <Protocols> nodes still accepted
    $protocols = [];
    if (isset($gen->Protocols)) {
        foreach ($gen->Protocols as $chunk) {
            $chunk = trim((string)$chunk);
            if ($chunk === '') {
                continue;
            }
            foreach (preg_split('/[\s,]+/', $chunk) as $part) {
                $part = strtolower(trim($part));
                if ($part !== '') {
                    $protocols[] = $part;
                }
            }
        }
    }
    $protocols = array_values(array_unique($protocols));
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

    // Write override file included by Suricata.
    write_suricata_custom_yaml(SURICATA_CUSTOM_YAML, $enableFileStore, $enableEveFiles);

    // Restart IDS (regenerates suricata.yaml; include reference stays intact)
    [$rcIdsRestart, $outIdsRestart] = sh('/usr/local/sbin/configctl ids restart');

    // Ensure file-store is enabled early enough (before rule load).
    // custom.yaml include is near the end of suricata.yaml on some versions, which is too late
    // to satisfy filestore rule prerequisites during rule parsing.
    patch_suricata_yaml_for_filestore(SURICATA_YAML);

    // Restart Suricata to pick up changes
    $yamlState = suricata_yaml_filestore_enabled_state(SURICATA_YAML);
    $customState = suricata_custom_yaml_outputs_state(SURICATA_CUSTOM_YAML);
    [$rcSuricataRestart, $outSuricataRestart] = sh('/usr/sbin/service suricata restart');

    // Restart service
    [$rcS2cRestart, $outS2cRestart] = sh('/usr/sbin/service suricata2cuckoo restart');

    echo json_encode([
        'result' => 'ok',
        'ids_reload' => ['rc' => $rcIds, 'out' => $outIds],
        'ids_restart' => ['rc' => $rcIdsRestart, 'out' => $outIdsRestart],
        'suricata_yaml_file_store_enabled' => $yamlState,
        'suricata_custom_yaml' => $customState,
        'suricata_restart' => ['rc' => $rcSuricataRestart, 'out' => $outSuricataRestart],
        'suricata2cuckoo_restart' => ['rc' => $rcS2cRestart, 'out' => $outS2cRestart],
    ]);
    exit(0);
} catch (\Throwable $e) {
    echo json_encode(['error' => $e->getMessage()]);
    exit(1);
}

