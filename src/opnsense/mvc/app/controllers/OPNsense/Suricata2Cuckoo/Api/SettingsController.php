<?php

namespace OPNsense\Suricata2Cuckoo\Api;

use OPNsense\Base\ApiMutableModelControllerBase;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelClass = 'OPNsense\\Suricata2Cuckoo\\Suricata2Cuckoo';
    protected static $internalModelName = 'suricata2cuckoo';

    /**
     * Expose WatchMethod as a proper option map for the GUI dropdown.
     *
     * If the serialized OptionField comes back empty ([]) or as a bare string, the web UI builds a select with no
     * &lt;option&gt; rows. suricata2cuckoo.pl only supports polling and kqueue.
     */
    protected function getModelNodes()
    {
        $nodes = parent::getModelNodes();
        if (!isset($nodes['general']) || !is_array($nodes['general'])) {
            return $nodes;
        }
        $wm = $nodes['general']['WatchMethod'] ?? null;
        if ($this->watchMethodOptionsNeedRepair($wm)) {
            $nodes['general']['WatchMethod'] = $this->buildWatchMethodOptions($this->readWatchMethodValue());
        }
        return $nodes;
    }

    private function watchMethodOptionsNeedRepair($wm): bool
    {
        if ($wm === null || $wm === []) {
            return true;
        }
        if (is_string($wm)) {
            return true;
        }
        if (!is_array($wm)) {
            return true;
        }
        $strKeys = 0;
        foreach ($wm as $k => $_) {
            if (is_string($k) && $k !== '') {
                $strKeys++;
            }
        }
        return $strKeys < 2;
    }

    private function readWatchMethodValue(): string
    {
        $node = $this->getModel()->getNodeByReference('general.WatchMethod');
        if ($node === null) {
            return 'polling';
        }
        $v = strtolower(trim((string)$node->getValue()));
        if ($v === 'kqueue' || $v === 'polling') {
            return $v;
        }
        return 'polling';
    }

    private function buildWatchMethodOptions(string $current): array
    {
        return [
            'polling' => [
                'value' => gettext('Polling (works on all platforms)'),
                'selected' => $current === 'polling' ? 1 : 0,
            ],
            'kqueue' => [
                'value' => gettext('kqueue (BSD only; requires IO::KQueue Perl module)'),
                'selected' => $current === 'kqueue' ? 1 : 0,
            ],
        ];
    }
}

