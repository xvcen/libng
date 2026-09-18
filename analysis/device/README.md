# Как полностью «расшифровать» libng.so на рутованном телефоне (Termux)

Ниже — рабочая процедура. Она опирается на главный вывод анализа: **код в файле не зашифрован, но данные расшифровываются лениво в памяти**, а целостность проверяется по хэшу **уже загруженного** образа. Значит, правильный путь — **снять дамп памяти живого процесса** (патчить файл бесполезно и опасно: сломается `.ark`-проверка).

```
Файл на диске                Память после загрузки
.text  (открытый код)  ──►   тот же код (проверяется хэшем)
.data  (мусор + консты) ──►  124 конструктора → расшифрованные таблицы
.rodata (строки+пул)   ──►   строки расшифровываются по месту (use-site)
```

---

## 0. Что подготовить (5 минут)

Нужны три `.so` из APK приложения (arm64-v8a): **`libng.so`**, **`libshadowhook.so`**, **`libc++_shared.so`**
(последние два — обязательные зависимости, без них `dlopen` не сработает).

```bash
pkg update && pkg install -y python clang binutils tsu unzip
pip install capstone frida frida-tools
mkdir -p /sdcard/ngdump /data/local/tmp/ng

# достать из APK
unzip -o base.apk 'lib/arm64-v8a/*' -d /sdcard/ng
# ...или прямо с устройства:
su -c "find /data/app -name 'libng.so' -path '*arm64*'"
su -c "cp /sdcard/ng/*.so /data/local/tmp/ng/ && chmod 755 /data/local/tmp/ng/*.so"
```

Скопируйте на телефон скрипты из этой папки (`loader.c`, `procmem_dump.py`, `postprocess.py`, `frida_dump.js`, `frida_host.py`, `ark_verify.py`, `elf.py`).

---

## Вариант A — Frida (самый полный)

Даёт: дамп модуля + heap, **вызов экспортов** с любыми аргументами, брутфорс `ng_ioctl`, повторные дампы.

```bash
# 1) frida-server под arm64 → /data/local/tmp, запуск от root
su -c "/data/local/tmp/frida-server -D &"

# 2) с ПК (или из Termux, если frida-tools стоят там)
python3 frida_host.py -U -n <пакет> --dump after_load      # прицепиться и снять дамп
python3 frida_host.py -U -f <пакет> --probe                # запустить, прогреть API, дамп
python3 frida_host.py -U -n <пакет> --ioctl 0 0x400        # брутфорс команд ng_ioctl
```

Что произойдёт: `frida_dump.js` найдёт `libng.so`, сольёт все его регионы (`r--/r-x/rw-`) + `[heap]`/malloc-арены в `ngdump/frida_<tag>.bin` + `.json`.

⚠️ Античит может ловить Frida (`dl_iterate_phdr` импортируется). Если приложение падает/ругается — используйте Вариант B, а Frida оставьте для «доброго» теста (например, на копии приложения или в отдельном процессе с `loader`).

---

## Вариант B — только root, без инъекции (тихий)

Годится, когда Frida палится: библиотека ничего не заметит, потому что мы не лезем в её процесс, а **читаем ` /proc/<pid>/mem`** от root.

```bash
tsu                            # root-shell с окружением Termux
setenforce 0                   # при необходимости (SELinux)
python3 procmem_dump.py --pkg <пакет> --rounds 40 --interval 4 \
        --orig /data/local/tmp/ng/libng.so --out /sdcard/ngdump
```

Скрипт каждые N секунд снимает снапшот регионов модуля + heap и накапливает **новые** (отсутствовавшие в файле) ASCII/UTF-16 строки → `strings_runtime.csv`.
**Пока он работает — играйте/тыкайте UI**: каждая ветка кода расшифровывает свои строки (ленивая CSE), так что чем больше действий, тем больше строк.

---

## Вариант C — свой харнесс (`loader.c`), полный прогон команд

Изолированный процесс, который сам грузит библиотеку и перебирает команды, **переживая падения** (per-call `sigsetjmp` + `alarm`), и дампит себя после каждого этапа.

```bash
cd /sdcard/ng
clang -O2 -fPIE -pie loader.c -o loader -ldl -llog
su -c "cd /data/local/tmp/ng && LD_LIBRARY_PATH=. /sdcard/ng/loader ./libng.so 0 0x400"
# → ngdump_after_init.bin/.json, ngdump_after_api.*, ngdump_brute.*, ngdump_final.*
```

Плюс: в изолированном процессе можно безнаказанно брутфорсить `ng_ioctl(cmd)` и подсовывать мусорные аргументы — приложение не пострадает.
Минус: нет реального контекста Java/ART (как и в эмуляторе, `JNI_OnLoad` вернёт «отказ»), но **расшифровка таблиц и большинства строк в конструкторах всё равно произойдёт** (в Unicorn так и было: 123/124 конструктора отработали).

---

## 3. Сборка результатов

```bash
python3 postprocess.py /sdcard/ngdump --orig /data/local/tmp/ng/libng.so
# -> /sdcard/ngdump/decrypted_strings.csv   (addr, section, string)
```

Плюс проверка, что файл не пропатчен: `python3 ark_verify.py /data/local/tmp/ng/libng.so`
(должно быть `14535 verified single-block checksums`).

---

## 4. Что делать с дампом (я делаю это на своей стороне)

Пришлите мне:
1. `decrypted_strings.csv` (или сами `ng_*.bin/.json` — они сжимаются в разы);
2. `ngdump_after_api.json` / `ngdump_final.json`;
3. вывод `python3 postprocess.py` (топ строк).

Я по адресам восстановленных строк соберу таблицу «строка → функция/сайт использования» (адрес в `.data`/`.bss` даёт привязку к объекту, а через `ark_sites.csv` — к конкретной функции), и это даст **осмысленные имена и сообщения** для тел под FLA.

Дополнительно уже сейчас можно «снять» obfuscation переходов в IDA:
* `analysis/out/ark_sites.csv` — 11 873 сайта: `site_va → record_index → target_va`;
* `analysis/device/ida_ark.py` — IDAPython-скрипт: ставит комментарии и **код-ссылки** на реальные цели (декомпилятор начинает видеть настоящие вызовы). 10 578 из 23 143 записей уже развязаны статически, остальные — из дампов.

---

## 5. Порядок действий (коротко)

| Шаг | Команда | Что получаем |
|---|---|---|
| 1 | `unzip base.apk 'lib/arm64-v8a/*'` | `libng.so` + зависимости |
| 2 | `python3 ark_verify.py` | подтверждение «оригинальности» файла |
| 3 | запуск приложения | конструкторы расшифровали `.data/.bss` |
| 4 | Вариант A **или** B **или** C | дампы памяти |
| 5 | `postprocess.py` | `decrypted_strings.csv` |
| 6 | `ida_ark.py` в IDA | развёрнутые защищённые переходы |
| 7 | прислать мне дампы/CSV | восстановление логики (дефлаттенинг + имена) |

### Если что-то не идёт
* `dlopen failed: library "libshadowhook.so" not found` → положите её рядом и `LD_LIBRARY_PATH=.`
* приложение падает сразу после старта Frida → Вариант B (без инъекции) или переименуйте frida-server (`-D` + `--rename`/`patchelf`).
* пустой дамп (все регионы `r-x`) → вы читаете процесс до загрузки libng.so: дождитесь `module_loaded` / сделайте несколько раундов с интервалом.
* `запрещено чтение /proc/pid/mem` → нужен именно root-shell (`tsu`) + `setenforce 0`.
