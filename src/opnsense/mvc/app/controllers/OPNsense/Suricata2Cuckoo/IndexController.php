<?php

namespace OPNsense\Suricata2Cuckoo;

class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->pick('OPNsense/Suricata2Cuckoo/index');
        $this->view->generalForm = $this->getForm('general');
    }
}

