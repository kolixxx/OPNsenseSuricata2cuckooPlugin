<?php

namespace OPNsense\Suricata2Cuckoo\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiControllerBase
{
    public function statusAction()
    {
        try {
            $backend = new Backend();
            $response = trim((string)$backend->configdRun('suricata2cuckoo status'));
            return ['status' => $response];
        } catch (\Throwable $e) {
            return ['status' => 'error', 'error' => $e->getMessage()];
        }
    }

    public function applyAction()
    {
        try {
            $backend = new Backend();
            $result = trim((string)$backend->configdRun('suricata2cuckoo apply'));
            return ['result' => $result !== '' ? $result : 'ok'];
        } catch (\Throwable $e) {
            return ['result' => 'error', 'error' => $e->getMessage()];
        }
    }

    public function restartAction()
    {
        try {
            $backend = new Backend();
            $result = trim((string)$backend->configdRun('suricata2cuckoo restart'));
            return ['result' => $result !== '' ? $result : 'ok'];
        } catch (\Throwable $e) {
            return ['result' => 'error', 'error' => $e->getMessage()];
        }
    }
}

