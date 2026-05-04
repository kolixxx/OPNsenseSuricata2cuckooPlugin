#!/usr/local/bin/php
<?php

/**
 * Ensure //OPNsense/suricata2cuckoo/general exists in config.xml with model defaults
 * so configctl template reload OPNsense/Suricata2Cuckoo can render suricata2cuckoo.conf
 * before the user ever opens the plugin GUI (dev-install / lab snapshots).
 *
 * Idempotent: only adds missing sibling tags under general; does not overwrite non-empty values.
 */

declare(strict_types=1);

chdir(dirname(__DIR__, 3) . '/www');
require_once 'script/load_phalcon.php';

use OPNsense\Core\Config;

function sx_child(\SimpleXMLElement $parent, string $name): \SimpleXMLElement
{
    if (!isset($parent->{$name})) {
        $parent->addChild($name);
    }

    return $parent->{$name};
}

function sx_set(\SimpleXMLElement $parent, string $name, string $value): void
{
    $v = (string) $value;
    if (!isset($parent->{$name})) {
        $parent->addChild($name, $v);

        return;
    }
    $el = dom_import_simplexml($parent->{$name});
    while ($el->firstChild !== null) {
        $el->removeChild($el->firstChild);
    }
    $el->appendChild($el->ownerDocument->createTextNode($v));
}

function opnsense_wrap(\SimpleXMLElement $root): \SimpleXMLElement
{
    foreach ($root->children() as $ch) {
        if (strcasecmp($ch->getName(), 'OPNsense') === 0) {
            return $ch;
        }
    }

    return sx_child($root, 'OPNsense');
}

$config = Config::getInstance();
$config->lock(true);

try {
    $root = $config->object();
    $wrap = opnsense_wrap($root);
    $s2c = sx_child($wrap, 'suricata2cuckoo');
    $gen = sx_child($s2c, 'general');

    $defaults = [
        'Enabled' => '0',
        'Protocols' => 'http',
        'FileExtensions' => 'doc,docx,pdf,zip,exe',
        'EnableEveFiles' => '1',
        'EnableFileStore' => '1',
        'FilestorePath' => '/var/log/suricata/filestore',
        'WatchMethod' => 'polling',
        'PollInterval' => '5',
        'FileSettleTime' => '2',
        'CuckooApiUrl' => 'http://127.0.0.1:8090',
        'CuckooApiToken' => '',
        'CuckooGuest' => 'Cuckoo1',
    ];

    foreach ($defaults as $key => $defaultVal) {
        if (!isset($gen->{$key})) {
            sx_set($gen, $key, $defaultVal);
            continue;
        }
        $cur = trim((string) $gen->{$key});
        if ($cur === '') {
            sx_set($gen, $key, $defaultVal);
        }
    }

    $config->save([
        'username' => 'suricata2cuckoo_ensure_defaults',
        'time' => microtime(true),
        'description' => 'Suricata2Cuckoo ensure_config_defaults',
    ]);
    fwrite(STDERR, "OK: suricata2cuckoo defaults present in config.xml\n");
} finally {
    $config->unlock();
}
