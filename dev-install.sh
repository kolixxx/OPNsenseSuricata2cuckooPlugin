#!/bin/sh
set -eu

# Suricata2Cuckoo - developer install helper for OPNsense (copy/paste friendly).
#
# Usage (on OPNsense as root):
#   fetch https://raw.githubusercontent.com/kolixxx/OPNsenseSuricata2cuckooPlugin/main/dev-install.sh -o /root/dev-install.sh
#   sh /root/dev-install.sh
#
# Or if you already cloned the repo:
#   cd /root/OPNsenseSuricata2cuckooPlugin && sh ./dev-install.sh

REPO_URL="${REPO_URL:-https://github.com/kolixxx/OPNsenseSuricata2cuckooPlugin.git}"
INSTALL_DIR="${INSTALL_DIR:-/root/OPNsenseSuricata2cuckooPlugin}"

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: run as root on OPNsense" >&2
  exit 1
fi

if ! command -v git >/dev/null 2>&1; then
  echo "Installing git..." >&2
  pkg update -q
  pkg install -y git
fi

if [ ! -d "$INSTALL_DIR/.git" ]; then
  echo "Cloning repo to: $INSTALL_DIR" >&2
  rm -rf "$INSTALL_DIR"
  git clone "$REPO_URL" "$INSTALL_DIR"
fi

echo "Updating repo..." >&2
git -C "$INSTALL_DIR" pull --ff-only

echo "Installing plugin files..." >&2
cp -a "$INSTALL_DIR/src/opnsense/"* /usr/local/opnsense/
cp -a "$INSTALL_DIR/src/etc/"* /usr/local/etc/

echo "Setting permissions..." >&2
chmod 0755 /usr/local/etc/rc.d/suricata2cuckoo
chmod 0755 /usr/local/etc/suricata2cuckoo/suricata2cuckoo.pl
chmod 0755 /usr/local/opnsense/scripts/OPNsense/Suricata2Cuckoo/apply.php
chmod 0644 /usr/local/etc/configd/actions.d/actions_suricata2cuckoo.conf 2>/dev/null || true

echo "Restarting configd + clearing caches..." >&2
service configd restart
rm -f /tmp/opnsense_menu_cache.xml
rm -f /usr/local/opnsense/mvc/app/cache/*.php

echo "Rendering /usr/local/etc/suricata2cuckoo/suricata2cuckoo.conf from template..." >&2
if [ -x /usr/local/sbin/configctl ]; then
  if /usr/local/sbin/configctl template reload OPNsense/Suricata2Cuckoo; then
    echo "Template OK." >&2
  else
    echo "WARNING: template reload failed — open Services -> Suricata2Cuckoo, enable plugin, Save + Apply once." >&2
  fi
else
  echo "WARNING: configctl not found; create config via GUI Apply." >&2
fi

echo
echo "OK: Suricata2Cuckoo dev files installed."
echo "Next:"
echo "  1) Services -> Intrusion Detection -> Settings: enable IDS, pick interfaces, Apply"
echo "  2) Services -> Suricata2Cuckoo: configure + Apply"
echo "  3) If you change IDS settings later, click Apply in Suricata2Cuckoo once afterwards"
