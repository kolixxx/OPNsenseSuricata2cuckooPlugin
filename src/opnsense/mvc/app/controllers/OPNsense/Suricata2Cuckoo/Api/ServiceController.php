<?php

namespace OPNsense\Suricata2Cuckoo\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiControllerBase
{
    public function statusAction()
    {
        $backend = new Backend();
        $response = trim((string)$backend->configdRun('suricata2cuckoo status'));
        return ['status' => $response];
    }

    public function applyAction()
    {
        $backend = new Backend();
        $result = trim((string)$backend->configdRun('suricata2cuckoo apply'));
        return ['result' => $result ?: 'ok'];
    }

    public function restartAction()
    {
        $backend = new Backend();
        $result = trim((string)$backend->configdRun('suricata2cuckoo restart'));
        return ['result' => $result ?: 'ok'];
    }
}

