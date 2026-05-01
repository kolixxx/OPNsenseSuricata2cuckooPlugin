## Suricata2Cuckoo (OPNsense plugin)

This repository contains an OPNsense plugin that:

- Generates Suricata file-extraction rules (`file-extract.rules`) for selected protocols and file extensions
- Ensures required IDS prerequisites (EVE syslog + EVE HTTP + EVE files + file-store)
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
- Generates `/usr/local/etc/suricata/rules/file-extract.rules`
- Ensures `file-extract.rules` is enabled in IDS
- Enables required IDS prerequisites (EVE syslog + EVE HTTP + EVE files + file-store)
- Runs `configctl ids reload` (reload IDS rules)
- Restarts the `suricata2cuckoo` service

Important:
- If you change anything under **Services → Intrusion Detection** and click **Apply** there, run **Apply** once in **Services → Suricata2Cuckoo** afterwards.
  This ensures the plugin prerequisites (especially `file-store` for filestore rules) are re-applied reliably.

### Verify it works

1. Generate traffic that contains a file (HTTP is the easiest)
2. Check Suricata filestore:
   - Shell: `ls -la /var/log/suricata/filestore/`
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

## Developer install (no package, for testing)

This installs the plugin files directly onto an OPNsense host (use only for development/testing).

### 1) Install prerequisites

```sh
pkg update
pkg install -y git p5-libwww p5-HTTP-Message p5-XML-XPath p5-File-LibMagic
```

### 2) Clone this repository

```sh
cd /tmp
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
```

### 4) Restart services and clear caches

```sh
service configd restart

# menu cache
rm -f /tmp/opnsense_menu_cache.xml

# clear mvc view cache (safe)
rm -f /usr/local/opnsense/mvc/app/cache/*.php
```

Now log out/in to the web UI (or hard refresh the browser).

### 5) Verify the menu files exist

```sh
ls -la /usr/local/opnsense/mvc/app/models/OPNsense/Suricata2Cuckoo/Menu/Menu.xml
ls -la /usr/local/opnsense/mvc/app/controllers/OPNsense/Suricata2Cuckoo/IndexController.php
```

If these files are present but the menu still does not show up, rebooting the firewall once is the quickest way to ensure all caches are cold.

