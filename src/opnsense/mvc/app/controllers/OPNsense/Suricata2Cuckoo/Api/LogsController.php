<?php

namespace OPNsense\Suricata2Cuckoo\Api;

use OPNsense\Base\ApiControllerBase;

class LogsController extends ApiControllerBase
{
    public function fileinfoAction()
    {
        $eve = '/var/log/suricata/eve.json';
        if (!is_readable($eve)) {
            return ['error' => 'eve.json not readable: ' . $eve];
        }

        $lines = (int)($this->request->get('lines') ?? 200);
        if ($lines < 10) {
            $lines = 10;
        }
        if ($lines > 2000) {
            $lines = 2000;
        }

        $cmd = sprintf(
            '/usr/bin/tail -n %d %s | /usr/bin/grep -E %s | /usr/bin/tail -n 50',
            $lines,
            escapeshellarg($eve),
            escapeshellarg('"event_type"[[:space:]]*:[[:space:]]*"fileinfo"|"fileinfo"')
        );

        $out = [];
        $rc = 0;
        exec($cmd . ' 2>&1', $out, $rc);

        return [
            'rc' => $rc,
            'lines' => $lines,
            'output' => implode("\n", $out),
        ];
    }
}
