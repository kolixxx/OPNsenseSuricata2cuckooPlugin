## Suricata2Cuckoo (плагин OPNsense)

Этот репозиторий содержит плагин для OPNsense, который:

- Генерирует правила Suricata для file-extraction (`file-extract.rules`) по выбранным протоколам и типам файлов
- Включает необходимые prerequisites в IDS (EVE syslog + EVE HTTP + EVE files + file-store)
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
- Генерирует `/usr/local/etc/suricata/rules/file-extract.rules`
- Убеждается, что `file-extract.rules` включён в IDS
- Включает необходимые prerequisites IDS (EVE syslog + EVE HTTP + EVE files + file-store)
- Выполняет `configctl ids reload` (перезагрузка правил IDS)
- Перезапускает сервис `suricata2cuckoo`

### Как проверить, что всё работает

1. Сгенерируйте трафик с передачей файла (самое простое — HTTP)
2. Проверьте filestore Suricata:
   - Shell: `ls -la /var/log/suricata/filestore/`
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

