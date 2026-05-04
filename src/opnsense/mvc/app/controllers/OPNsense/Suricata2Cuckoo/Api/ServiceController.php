<?php

namespace OPNsense\Suricata2Cuckoo\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiControllerBase
{
    private function decodeConfigdOutput(string $raw)
    {
        $raw = trim($raw);
        if ($raw === '') {
            return ['result' => 'ok'];
        }
        if ($raw[0] === '{' || $raw[0] === '[') {
            $decoded = json_decode($raw, true);
            if (json_last_error() === JSON_ERROR_NONE) {
                return $decoded;
            }
        }
        return ['result' => $raw];
    }

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
            return $this->decodeConfigdOutput($result);
        } catch (\Throwable $e) {
            return ['result' => 'error', 'error' => $e->getMessage()];
        }
    }

    public function restartAction()
    {
        try {
            $backend = new Backend();
            $result = trim((string)$backend->configdRun('suricata2cuckoo restart'));
            return $this->decodeConfigdOutput($result);
        } catch (\Throwable $e) {
            return ['result' => 'error', 'error' => $e->getMessage()];
        }
    }
}

