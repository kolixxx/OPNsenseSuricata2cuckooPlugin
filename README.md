## Suricata2Cuckoo (OPNsense plugin)

This repository contains an OPNsense plugin that:

- Generates Suricata file-extraction rules (`file-extract.rules`) for selected protocols and file extensions
- Lets you mirror **EVE fileinfo** and **file-store** into IDS from the plugin; **EVE syslog** and **EVE HTTP** must be enabled manually under **IDS → Administration**
- Runs `suricata2cuckoo` daemon to submit extracted files to Cuckoo Sandbox via REST API

## Installation

### Step-by-step (GUI)

1. Install the plugin
   - GUI: **System → Firmware → Plugins**
   - Find and install the plugin package (name will start with `os-`)

2. Enable IDS and select interface(s)
   - Open **Services → Intrusion Detection → Settings**
   - Set **Enabled** = ON
   - Select **Interfaces** (required)
   - Click **Apply**

2b. IDS logging (manual, required for typical HTTP/file extraction)
   - Open **Services → Intrusion Detection → Administration**
   - Under **Logging**, enable **Enable eve syslog output** and **Enable eve HTTP logging**
   - Click **Apply** on the IDS page

3. Configure Suricata2Cuckoo
   - Open **Services → Suricata2Cuckoo**
   - Set **Enable Suricata2Cuckoo** = ON
   - Select **Protocols** (multi-select, e.g. HTTP)
   - Set **File extensions** (comma-separated; you may type `.docx` or `docx`)
   - Fill:
     - **Cuckoo Sandbox URL API** (example: `http://192.168.1.100:8090`)
     - **Cuckoo Sandbox API Token** (optional)
     - **Cuckoo Sandbox Guest VM** (example: `Cuckoo1`)
   - Click **Apply**

What “Apply” does:
- Renders `/usr/local/etc/suricata2cuckoo/suricata2cuckoo.conf` from the OPNsense template (`configctl template reload OPNsense/Suricata2Cuckoo`)
- Generates `/usr/local/etc/suricata/rules/file-extract.rules`
- Ensures `file-extract.rules` is enabled in IDS
- Mirrors into IDS only **EVE fileinfo (files)** and **file-store** from the plugin (syslog + HTTP are step 2b above)
- Runs `configctl ids reload` (reload IDS rules)
- Restarts the `suricata2cuckoo` service

Important:
- If you change anything under **Services → Intrusion Detection** and click **Apply** there, run **Apply** once in **Services → Suricata2Cuckoo** afterwards.
  This ensures the plugin prerequisites (especially `file-store` for filestore rules) are re-applied reliably.

### Verify it works

1. Generate traffic that contains a file (HTTP is the easiest)
2. Check Suricata filestore:
   - Shell: `ls -la /var/log/suricata/filestore/`
   - Hash-style subdirs (e.g. `00/ff/`) only appear after Suricata has stored at least one file; the directory may be empty until then
3. Check IDS EVE log has fileinfo events:
   - Shell: `tail -f /var/log/suricata/eve.json | grep fileinfo`
4. Check suricata2cuckoo logs:
   - GUI: **Services → Intrusion Detection → Log File**
   - Look for lines containing `suricata2cuckoo` like “Submitting …” / “Cuckoo API OK …”

## Files and paths

- Rule file: `/usr/local/etc/suricata/rules/file-extract.rules`
- Filestore: `/var/log/suricata/filestore/`
- Daemon config: `/usr/local/etc/suricata2cuckoo/suricata2cuckoo.conf`

Reserved SID range: **1000001–1000999**.

## Optional: IO::KQueue (kqueue watcher)

By default the daemon can use `polling` (works everywhere).
If you want `kqueue` watcher mode (recommended on FreeBSD/OPNsense):

```sh
pkg install p5-CPAN
cpan IO::KQueue
```

Confirm the module is available:

```sh
perl -MIO::KQueue -e 'print "IO::KQueue available\n"'
```

Enable it in the plugin GUI:

1. Open **Services → Suricata2Cuckoo**
2. Set **Watch method** = `kqueue`
3. Click **Apply** (this restarts the service)

If you want to restart manually:

```sh
service suricata2cuckoo restart
```

## Common issues

- **`ERROR: config not found: …/suricata2cuckoo.conf`** — the daemon config is written by the OPNsense template when **Apply** succeeds in **Services → Suricata2Cuckoo** (plugin must be **enabled**). Manually: `configctl template reload OPNsense/Suricata2Cuckoo`. The `dev-install.sh` script runs this reload at the end of an install.
- **Empty `/var/log/suricata/filestore/`** — expected until there is matching traffic and Suricata extracts at least one file.

## Diagnose `suricata2cuckoo` (shell)

On the firewall as **root**, run:

```sh
sysrc suricata2cuckoo_enable
service suricata2cuckoo status
ls -la /usr/local/etc/rc.d/suricata2cuckoo /usr/local/etc/suricata2cuckoo/suricata2cuckoo.pl /usr/local/etc/suricata2cuckoo/suricata2cuckoo.conf
tail -n 80 /var/log/suricata2cuckoo.log
ls -la /var/run/suricata2cuckoo.pid 2>/dev/null; pgrep -af suricata2cuckoo
ls -la /usr/local/opnsense/scripts/OPNsense/Suricata2Cuckoo/apply.php
/usr/local/sbin/configctl suricata2cuckoo apply
perl -c /usr/local/etc/suricata2cuckoo/suricata2cuckoo.pl
```

Foreground test (runs until you press Ctrl+C; useful to see Perl errors on the terminal):

```sh
/usr/local/etc/suricata2cuckoo/suricata2cuckoo.pl -c /usr/local/etc/suricata2cuckoo/suricata2cuckoo.conf
```

If `configctl … apply` fails, confirm **configd** picked up the actions file: `service configd restart` after copying `actions_suricata2cuckoo.conf`, and that `apply.php` is executable (`chmod 0755`).

## Developer install (no package, for testing)

This installs the plugin files directly onto an OPNsense host (use only for development/testing).

### Easiest: one script (recommended)

On OPNsense as **root**:

```sh
fetch https://raw.githubusercontent.com/kolixxx/OPNsenseSuricata2cuckooPlugin/main/dev-install.sh -o /root/dev-install.sh
sh /root/dev-install.sh
```

Notes:
- The script clones/updates the repo under `/root/OPNsenseSuricata2cuckooPlugin` (not `/tmp`, because `/tmp` may be cleared on reboot).
- After copying files it runs `configctl template reload OPNsense/Suricata2Cuckoo` so `suricata2cuckoo.conf` exists (if that fails, open the plugin in the GUI once and click **Apply** with the plugin enabled).
- If you prefer manual steps, use the section below.

### 1) Install prerequisites

```sh
pkg update
pkg install -y git p5-libwww p5-HTTP-Message p5-XML-XPath p5-File-LibMagic
```

### 2) Clone this repository

```sh
cd /root
rm -rf OPNsenseSuricata2cuckooPlugin
git clone https://github.com/kolixxx/OPNsenseSuricata2cuckooPlugin.git
cd OPNsenseSuricata2cuckooPlugin
```

### 3) Copy files into the correct locations

```sh
# MVC + configd + templates + scripts
cp -a src/opnsense/* /usr/local/opnsense/

# /usr/local/etc (rc.d + suricata2cuckoo.pl)
cp -a src/etc/* /usr/local/etc/

chmod 0755 /usr/local/etc/rc.d/suricata2cuckoo
chmod 0755 /usr/local/etc/suricata2cuckoo/suricata2cuckoo.pl
chmod 0755 /usr/local/opnsense/scripts/OPNsense/Suricata2Cuckoo/apply.php
chmod 0644 /usr/local/etc/configd/actions.d/actions_suricata2cuckoo.conf
```

### 4) Restart services and clear caches

```sh
service configd restart

# menu cache
rm -f /tmp/opnsense_menu_cache.xml

# clear mvc view cache (safe)
rm -f /usr/local/opnsense/mvc/app/cache/*.php

# daemon config (otherwise service suricata2cuckoo start complains the file is missing)
configctl template reload OPNsense/Suricata2Cuckoo
```

Now log out/in to the web UI (or hard refresh the browser).

### 5) Verify the menu files exist

```sh
ls -la /usr/local/opnsense/mvc/app/models/OPNsense/Suricata2Cuckoo/Menu/Menu.xml
ls -la /usr/local/opnsense/mvc/app/controllers/OPNsense/Suricata2Cuckoo/IndexController.php
```

If these files are present but the menu still does not show up, rebooting the firewall once is the quickest way to ensure all caches are cold.

