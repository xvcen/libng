#!/data/data/com.termux/files/usr/bin/bash
# setup_termux.sh — подготовка Termux для снятия рантайма libng.so
set -e
echo "[*] пакеты..."
pkg update -y
pkg install -y python clang binutils tsu termux-api git

echo "[*] python-модули..."
pip install --upgrade pip >/dev/null
pip install capstone frida frida-tools

mkdir -p /sdcard/ngdump /data/local/tmp/ng
echo "[*] проверка root:"
su -c id || echo "  (root не отвечает — проверь Magisk)"

cat <<'EOT'

[+] Готово. Дальше:

1) Достать из APK приложения три библиотеки (arm64-v8a):
      libng.so  libshadowhook.so  libc++_shared.so
   Пример:
      unzip -o base.apk 'lib/arm64-v8a/*' -d /sdcard/ng
   или из самого устройства (если приложение установлено):
      su -c "find /data/app -name 'libng.so' -path '*arm64*'"

2) Положить их в /data/local/tmp/ng и дать права:
      su -c "mkdir -p /data/local/tmp/ng && cp /sdcard/ng/*.so /data/local/tmp/ng/ && chmod 755 /data/local/tmp/ng/*.so"

3) Собрать лоадер (вариант C — без Frida):
      cd /sdcard/ng && clang -O2 -fPIE -pie loader.c -o loader -ldl -llog
      su -c "cd /data/local/tmp/ng && LD_LIBRARY_PATH=. /sdcard/ng/loader ./libng.so 0 0x400"

4) Вариант A (Frida): скачать frida-server под arm64 и запустить от root:
      # на ПК: pip install frida-tools
      # frida-server-XX.X.X-android-arm64  -> /data/local/tmp/
      su -c "/data/local/tmp/frida-server -D &"
      # и потом с ПК: python3 frida_host.py -U -f <пакет> --probe

5) Вариант B (без инъекции, только root):
      tsu
      python3 procmem_dump.py --pkg <пакет> --rounds 40 --interval 4 \
          --orig /data/local/tmp/ng/libng.so --out /sdcard/ngdump

6) Сбор результатов:
      python3 postprocess.py /sdcard/ngdump --orig /data/local/tmp/ng/libng.so
      # -> decrypted_strings.csv (адрес, секция, строка)

7) Прислать мне: decrypted_strings.csv + ngdump_*.json (или сами дампы) — я дострою
   таблицу строк/функций и перейду к дефлаттенингу.
EOT
