## Suricata2Cuckoo (плагин OPNsense)

Этот репозиторий содержит плагин для OPNsense, который:

- Генерирует правила Suricata для file-extraction (`file-extract.rules`) по выбранным протоколам и типам файлов
- Переносит в IDS из плагина только **EVE fileinfo (files)** и **file-store**; **EVE syslog** и **EVE HTTP** нужно включить вручную в **IDS → Administration**
- Запускает демон `suricata2cuckoo`, который отправляет извлечённые файлы в Cuckoo Sandbox через REST API

## Установка

### Пошагово (GUI)

1. Установите плагин
   - GUI: **System → Firmware → Plugins**
   - Найдите и установите пакет плагина (название будет начинаться с `os-`)

2. Включите IDS и выберите интерфейс(ы)
   - Откройте **Services → Intrusion Detection → Settings**
   - Включите **Enabled**
   - Выберите **Interfaces** (обязательно)
   - Нажмите **Apply**

2b. Логирование IDS (вручную, нужно для типичного HTTP/файлов)
   - Откройте **Services → Intrusion Detection → Administration**
   - В разделе **Logging** включите **Enable eve syslog output** и **Enable eve HTTP logging**
   - Нажмите **Apply** на странице IDS

3. Настройте Suricata2Cuckoo
   - Откройте **Services → Suricata2Cuckoo**
   - Включите **Enable Suricata2Cuckoo**
   - Выберите **Protocols** (можно несколько, например HTTP)
   - Укажите **File extensions** (через запятую; можно вводить `.docx` или `docx`)
   - Заполните:
     - **Cuckoo Sandbox URL API** (пример: `http://192.168.1.100:8090`)
     - **Cuckoo Sandbox API Token** (опционально)
     - **Cuckoo Sandbox Guest VM** (пример: `Cuckoo1`)
   - Нажмите **Apply**

Что делает “Apply”:
- Рендерит `/usr/local/etc/suricata2cuckoo/suricata2cuckoo.conf` из шаблона OPNsense (`configctl template reload OPNsense/Suricata2Cuckoo`)
- Генерирует `/usr/local/etc/suricata/rules/file-extract.rules`
- Убеждается, что `file-extract.rules` включён в IDS
- Записывает в IDS только **EVE fileinfo** и **file-store** из плагина (syslog и HTTP — шаг 2b выше)
- Выполняет `configctl ids reload` (перезагрузка правил IDS)
- Перезапускает сервис `suricata2cuckoo`

Важно:
- Если вы меняете что‑то в **Services → Intrusion Detection** и нажимаете там **Apply**, после этого один раз нажмите **Apply** в **Services → Suricata2Cuckoo**.
  Это гарантирует, что prerequisites плагина (особенно `file-store` для filestore‑правил) будут переустановлены.

### Как проверить, что всё работает

1. Сгенерируйте трафик с передачей файла (самое простое — HTTP)
2. Проверьте filestore Suricata:
   - Shell: `ls -la /var/log/suricata/filestore/`
   - Подкаталоги в стиле `00/ff/` появляются только после первого успешно извлечённого файла; до этого каталог может быть пустым
3. Проверьте, что в EVE появляются fileinfo-события:
   - Shell: `tail -f /var/log/suricata/eve.json | grep fileinfo`
4. Проверьте логи `suricata2cuckoo`:
   - GUI: **Services → Intrusion Detection → Log File**
   - Найдите строки `suricata2cuckoo` (“Submitting …” / “Cuckoo API OK …”)

## Пути

- Файл правил: `/usr/local/etc/suricata/rules/file-extract.rules`
- Filestore: `/var/log/suricata/filestore/`
- Конфиг демона: `/usr/local/etc/suricata2cuckoo/suricata2cuckoo.conf`

Диапазон SID зарезервирован: **1000001–1000999**.

## Опционально: IO::KQueue (режим kqueue)

По умолчанию демон может работать в режиме `polling` (везде работает).
Если нужен режим `kqueue` (рекомендуется для FreeBSD/OPNsense):

```sh
pkg install p5-CPAN
cpan IO::KQueue
```

Проверьте, что модуль доступен:

```sh
perl -MIO::KQueue -e 'print "IO::KQueue available\n"'
```

Включите в GUI плагина:

1. Откройте **Services → Suricata2Cuckoo**
2. Выставьте **Watch method** = `kqueue`
3. Нажмите **Apply** (сервис будет перезапущен автоматически)

Если нужно перезапустить вручную:

```sh
service suricata2cuckoo restart
```

## Частые проблемы

- **`ERROR: config not found: …/suricata2cuckoo.conf`** — конфиг не создаётся «сам по себе»: его пишет шаблон при успешном **Apply** в **Services → Suricata2Cuckoo** (плагин должен быть **включён**). Вручную: `configctl template reload OPNsense/Suricata2Cuckoo`. Скрипт `dev-install.sh` после установки пытается выполнить этот reload автоматически.
- **Пустой `/var/log/suricata/filestore/`** — нормально, пока не было трафика с файлами, попадающими под ваши правила/расширения и пока Suricata не извлекла ни одного файла.

## Диагностика `suricata2cuckoo` (терминал)

На firewall под **root**:

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

Запуск в переднем плане (пока не остановите Ctrl+C — видны ошибки Perl в терминале):

```sh
/usr/local/etc/suricata2cuckoo/suricata2cuckoo.pl -c /usr/local/etc/suricata2cuckoo/suricata2cuckoo.conf
```

Если `configctl … apply` падает: после копирования `actions_suricata2cuckoo.conf` сделайте `service configd restart` и проверьте `chmod 0755` на `apply.php`.

## Установка для разработки (без пакета, для тестов)

Это dev-установка: файлы плагина копируются напрямую на OPNsense (только для разработки/тестов).

### Самый простой путь: один скрипт (рекомендуется)

На OPNsense под **root**:

```sh
fetch https://raw.githubusercontent.com/kolixxx/OPNsenseSuricata2cuckooPlugin/main/dev-install.sh -o /root/dev-install.sh
sh /root/dev-install.sh
```

Замечания:
- Скрипт клонирует/обновляет репозиторий в `/root/OPNsenseSuricata2cuckooPlugin` (не в `/tmp`, потому что `/tmp` может очищаться после перезагрузки).
- **Важно:** на firewall копируется то, что лежит **на GitHub** в `REPO_URL` (по умолчанию `kolixxx/OPNsenseSuricata2cuckooPlugin`), после `git pull`. Локальная папка на Windows/Mac **не участвует**, пока вы не сделали `git push` в этот репозиторий (или не указали свой форк: `REPO_URL=https://github.com/ВЫ/Репо.git sh /root/dev-install.sh`). В конце установки скрипт печатает строку `Using plugin git commit: …` — по ней видно, какая версия реально установлена.
- После копирования файлов выполняется `configctl template reload OPNsense/Suricata2Cuckoo`, чтобы появился `suricata2cuckoo.conf` (если reload не удался — один раз откройте плагин в GUI и нажмите **Apply** с включённым плагином).
- Если хотите вручную — используйте блок ниже.

### 1) Установить зависимости

```sh
pkg update
pkg install -y git p5-libwww p5-HTTP-Message p5-XML-XPath p5-File-LibMagic
```

### 2) Склонировать репозиторий

```sh
cd /root
rm -rf OPNsenseSuricata2cuckooPlugin
git clone https://github.com/kolixxx/OPNsenseSuricata2cuckooPlugin.git
cd OPNsenseSuricata2cuckooPlugin
```

### 3) Скопировать файлы в правильные места

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

### 4) Перезапустить сервисы и сбросить кэши

```sh
service configd restart

# кэш меню
rm -f /tmp/opnsense_menu_cache.xml

# кэш шаблонов MVC (безопасно)
rm -f /usr/local/opnsense/mvc/app/cache/*.php

# конфиг демона (иначе service suricata2cuckoo start ругается на отсутствие файла)
configctl template reload OPNsense/Suricata2Cuckoo
```

После этого выйдите/войдите в web UI (или сделайте hard refresh в браузере).

### 5) Проверить, что файлы меню на месте

```sh
ls -la /usr/local/opnsense/mvc/app/models/OPNsense/Suricata2Cuckoo/Menu/Menu.xml
ls -la /usr/local/opnsense/mvc/app/controllers/OPNsense/Suricata2Cuckoo/IndexController.php
```

Если файлы на месте, но меню всё равно не появилось — самый быстрый способ “обнулить” все кэши: один раз перезагрузить firewall.

