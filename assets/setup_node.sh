#!/bin/bash

set -euo pipefail

iran_server="$1"
proxy_url="$2"
node_cert="$3"
xray_version="${4:-latest}"
node_port="$5"

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

# نصب Docker
curl -fsSL https://get.docker.com | sh

# کلون کردن مخزن
if [ ! -d marznode ]; then
  git clone --quiet https://github.com/khodedawsh/marznode
fi
cd marznode || { echo "Error: directory marznode not found"; exit 1; }

# تنظیم پراکسی برای Docker فقط اگر سرور ایران باشد
if [ "$iran_server" = true ] && [ -n "$proxy_url" ]; then
  sudo mkdir -p /etc/systemd/system/docker.service.d
  cat <<EOF | sudo tee /etc/systemd/system/docker.service.d/http-proxy.conf
[Service]
Environment="HTTP_PROXY=$proxy_url"
Environment="HTTPS_PROXY=$proxy_url"
Environment="NO_PROXY=localhost,127.0.0.1,$(hostname -I | awk '{print $1}')"
EOF
  echo "Docker proxy configuration written."
fi

sudo systemctl daemon-reload
sudo systemctl restart docker

echo "Pulling hello-world image (test)..."
docker pull --quiet hello-world || { echo "Docker test image pull failed"; exit 1; }

echo "Pulling marznode images quietly..."
docker compose --no-ansi pull --quiet
echo "Starting marznode with docker compose..."
docker compose --no-ansi up -d

# Decode و ذخیره فایل client.pem اگر آرگومان سوم موجود باشد
if [ -n "$node_cert" ]; then
  sudo mkdir -p /var/lib/marznode
  echo "$node_cert" | base64 -d | sudo tee /var/lib/marznode/client.pem > /dev/null
  sudo chmod 600 /var/lib/marznode/client.pem
  echo "client.pem written to /var/lib/marznode/"
fi

# آماده‌سازی مسیر Xray
mkdir -p /var/lib/marznode/data
cd /var/lib/marznode/data || exit 1

# دانلود و استخراج Xray
if [ "$xray_version" = "latest" ]; then
    xray_url="https://github.com/XTLS/Xray-core/releases/$xray_version/download/Xray-linux-64.zip"
else
    xray_url="https://github.com/XTLS/Xray-core/releases/download/$xray_version/Xray-linux-64.zip"
fi

echo "Downloading Xray version: $xray_version..."
wget --quiet --show-progress -O Xray-linux-64.zip "$xray_url"
[ -s Xray-linux-64.zip ] || { echo "Download failed"; exit 1; }

echo "Unzipping Xray..."
unzip -q Xray-linux-64.zip
[ -f xray ] || { echo "Extraction failed"; exit 1; }

rm -f Xray-linux-64.zip
chmod +x xray
echo "Xray downloaded and extracted (version: $xray_version)"

# بازگردانی تنظیمات پراکسی
if [ "$iran_server" = true ] && [ -n "$proxy_url" ]; then
  cd
  sudo rm -f /etc/apt/apt.conf.d/95proxy
  unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY
  apt-get update -y
  sudo rm -f /etc/systemd/system/docker.service.d/http-proxy.conf
  cd /var/lib/marznode/data
fi

# کپی فایل‌های پیکربندی
cp /root/marznode/xray_config.json /var/lib/marznode/xray_config.json
cp /var/lib/marznode/data/xray /var/lib/marznode/xray

cd ~/marznode || { echo "Error: ~/marznode not found"; exit 1; }

rm -f compose.yml

# ایجاد فایل docker-compose.yml با مقدار پورت از آرگومان پنجم
if [ -n "$node_port" ]; then
  sudo tee compose.yml > /dev/null <<EOL
services:
  marznode:
    image: dawsh/marznode:latest
    restart: always
    network_mode: host
    command: [ "sh", "-c", "sleep 10 && python3 marznode.py" ]

    environment:
      SERVICE_PORT: "$node_port"
      XRAY_EXECUTABLE_PATH: "/var/lib/marznode/xray"
      XRAY_ASSETS_PATH: "/var/lib/marznode/data"
      XRAY_CONFIG_PATH: "/var/lib/marznode/xray_config.json"
      SSL_CLIENT_CERT_FILE: "/var/lib/marznode/client.pem"
      SSL_KEY_FILE: "./server.key"
      SSL_CERT_FILE: "./server.cert"

    volumes:
      - /var/lib/marznode:/var/lib/marznode
EOL

  echo "compose.yml written with SERVICE_PORT=$node_port"
fi

docker compose down || true
docker compose up -d

# چاپ IP و PORT
ip=$(ip -4 a | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v 127 | head -1)
g="\033[1;32m"; r="\033[0m"
w=29
bar() { printf "$1$(printf '─%.0s' $(seq 1 $w))$2\n"; }
line() { printf "│%-${w}s│\n" "$1"; }

echo -e "\n$g"
bar "┌" "┐"; line "IP:   $ip"; bar "├" "┤"; line "Port: $node_port"; bar "└" "┘"
echo -e "$r"
