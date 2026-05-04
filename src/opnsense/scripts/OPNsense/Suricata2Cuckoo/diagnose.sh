#!/bin/sh
# Suricata2Cuckoo — full on-box diagnostics (OPNsense / FreeBSD).
# Run as root, copy the ENTIRE terminal output and share it when asking for help.
set -eu

SCRIPT="/usr/local/etc/suricata2cuckoo/suricata2cuckoo.pl"
CONF="/usr/local/etc/suricata2cuckoo/suricata2cuckoo.conf"
PIDF="/var/run/suricata2cuckoo.pid"
LOGF="/var/log/suricata2cuckoo.log"
PERL="/usr/local/bin/perl"

echo "========== suricata2cuckoo diagnose =========="
echo "date: $(date -Iseconds 2>/dev/null || date)"
echo

echo "---------- 1) identity / kernel ----------"
id
uname -a 2>/dev/null || true
echo

echo "---------- 2) rc.d (must contain: perl ... --no-fork) ----------"
if [ -f /usr/local/etc/rc.d/suricata2cuckoo ]; then
  ls -la /usr/local/etc/rc.d/suricata2cuckoo
  grep -n daemon /usr/local/etc/rc.d/suricata2cuckoo || true
else
  echo "MISSING: /usr/local/etc/rc.d/suricata2cuckoo"
fi
echo

echo "---------- 3) sysrc ----------"
sysrc suricata2cuckoo_enable 2>/dev/null || echo "(suricata2cuckoo_enable not set)"
echo

echo "---------- 4) plugin files ----------"
ls -la "$SCRIPT" "$CONF" 2>&1 || true
if [ -f "$CONF" ]; then
  echo "--- first lines of $CONF ---"
  sed -n '1,12p' "$CONF"
fi
echo

echo "---------- 5) Perl modules (script imports) ----------"
$PERL -e 'require LWP::UserAgent; require HTTP::Request::Common; require XML::XPath; print "OK: LWP+HTTP+XML::XPath\n"' 2>&1 || echo "FAIL: install pkg p5-libwww p5-HTTP-Message p5-XML-XPath"
$PERL -e 'require File::LibMagic; print "OK: File::LibMagic\n"' 2>&1 || echo "NOTE: File::LibMagic optional (pkg p5-File-LibMagic)"
echo

echo "---------- 6) perl -c syntax ----------"
$PERL -c "$SCRIPT" 2>&1 || true
echo

echo "---------- 7) filestore dir (script exits if missing) ----------"
echo "default path /var/log/suricata/filestore (override in suricata2cuckoo.conf if different):"
ls -la /var/log/suricata/filestore 2>&1 || echo "MISSING — mkdir -p /var/log/suricata/filestore or fix IDS/file-store + Apply in plugin"
echo

echo "---------- 8) short foreground run (4s, then kill) ----------"
FGLOG="/tmp/suricata2cuckoo_fg_test.log"
rm -f "$FGLOG"
set +e
$PERL "$SCRIPT" -c "$CONF" --no-fork >"$FGLOG" 2>&1 &
FGPID=$!
sleep 4
kill "$FGPID" 2>/dev/null || true
wait "$FGPID" 2>/dev/null || true
set -e
echo "--- $FGLOG ---"
cat "$FGLOG" 2>/dev/null || echo "(empty)"
echo

echo "---------- 9) service stop / start / status ----------"
service suricata2cuckoo stop 2>/dev/null || true
sleep 1
echo ">>> service suricata2cuckoo start"
set +e
service suricata2cuckoo start 2>&1
START_RC=$?
set -e
echo "start exit code: $START_RC"
sleep 2
echo ">>> ls pid + log"
ls -la "$PIDF" "$LOGF" 2>&1 || true
echo ">>> service suricata2cuckoo status"
set +e
service suricata2cuckoo status 2>&1
STATUS_RC=$?
set -e
echo "status exit code: $STATUS_RC"
echo ">>> pgrep"
pgrep -af suricata2cuckoo 2>/dev/null || echo "(no pgrep matches)"
echo

echo "---------- 10) tail daemon log (if any) ----------"
tail -40 "$LOGF" 2>&1 || echo "(no $LOGF)"
echo

echo "---------- 11) syslog lines (common log files) ----------"
FOUND=0
for f in /var/log/system.log /var/log/messages /var/log/all.log; do
  if [ -f "$f" ]; then
    echo "--- grep in $f ---"
    grep -i suricata2cuckoo "$f" 2>/dev/null | tail -25 || echo "(no matches)"
    FOUND=1
  fi
done
if [ "$FOUND" -eq 0 ]; then
  echo "No known log file — use GUI System → Log Files, or: ls /var/log/*.log"
fi
echo

echo "---------- 12) apply.php + configd ----------"
ls -la /usr/local/opnsense/scripts/OPNsense/Suricata2Cuckoo/apply.php 2>&1 || true
ls -la /usr/local/etc/configd/actions.d/actions_suricata2cuckoo.conf 2>&1 || true
echo

echo "---------- 13) optional: one-shot apply (JSON) ----------"
if [ -x /usr/local/sbin/configctl ]; then
  set +e
  OUT=$(/usr/local/sbin/configctl suricata2cuckoo apply 2>&1)
  AC=$?
  set -e
  echo "$OUT"
  echo "configctl suricata2cuckoo apply exit: $AC"
else
  echo "no configctl"
fi
echo

echo "========== end of diagnose =========="
