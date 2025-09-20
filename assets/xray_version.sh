#!/bin/bash

set -euo pipefail

iran_server="$1"
proxy_url="$2"
xray_version="${3:-latest}"
host="$4"

# اعمال تنظیمات پراکسی برای apt و محیط فقط اگر سرور در ایران باشد و proxy_url مشخص باشد
if [ "$iran_server" = true ] && [ -n "$proxy_url" ]; then
  echo -e "Acquire::http::Proxy \"$proxy_url\";\nAcquire::https::Proxy \"$proxy_url\";" \
    | sudo tee /etc/apt/apt.conf.d/95proxy

  unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY
  export ALL_PROXY="$proxy_url"
  export HTTP_PROXY="$proxy_url"
  export HTTPS_PROXY="$proxy_url"
fi

# نصب بی‌صدای پکیج‌ها
export DEBIAN_FRONTEND=noninteractive
apt-get update -y -qq
apt-get install -y -qq apt-utils git unzip wget curl

cd /var/lib/marznode/data || { echo "Error: /var/lib/marznode/data does not exist"; exit 1; }

# دانلود و استخراج Xray
if [ "$xray_version" = "latest" ]; then
    xray_url="https://github.com/XTLS/Xray-core/releases/$xray_version/download/Xray-linux-64.zip"
else
    xray_url="https://github.com/XTLS/Xray-core/releases/download/$xray_version/Xray-linux-64.zip"
fi

wget --quiet --show-progress -O Xray-linux-64.zip "$xray_url"
[ -s Xray-linux-64.zip ] || { echo "Download failed"; exit 1; }

unzip -o -q Xray-linux-64.zip
[ -f xray ] || { echo "Extraction failed"; exit 1; }

rm -f Xray-linux-64.zip
chmod +x xray

# بازگردانی تنظیمات پراکسی
if [ "$iran_server" = true ] && [ -n "$proxy_url" ]; then
  cd
  sudo rm -f /etc/apt/apt.conf.d/95proxy
  unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY
  apt-get update -y
  cd /var/lib/marznode/data
fi

cp -f /var/lib/marznode/data/xray /var/lib/marznode/xray

# راه‌اندازی Docker
if [ "$host" = "local" ]; then
    cd /etc/opt/marzneshin || { echo "Error: Directory /etc/opt/marzneshin does not exist"; exit 1; }
    docker compose stop marznode && docker compose rm -f marznode && docker compose up -d marznode
else
    cd ~/marznode || { echo "Error: Directory marznode does not exist"; exit 1; }
    docker compose down && docker compose up -d
fi
