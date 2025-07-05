#!/bin/bash

set -e
set +H

iran_server="$1"
proxy_url="$2"
node_cert="$3"
xray_version="${4:-latest}"
node_port="$5"

# اعمال تنظیمات پراکسی برای apt و محیط فقط اگر سرور در ایران باشد و proxy_url مشخص باشد
if [ "$iran_server" = true ] && [ -n "$proxy_url" ]; then
  echo -e "Acquire::http::Proxy \"$proxy_url\";\nAcquire::https::Proxy \"$proxy_url\";" | sudo tee /etc/apt/apt.conf.d/95proxy

  unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY

  export ALL_PROXY="$proxy_url"
  export HTTP_PROXY="$proxy_url"
  export HTTPS_PROXY="$proxy_url"
fi

sleep 1

# نصب بی‌صدای پکیج‌ها
export DEBIAN_FRONTEND=noninteractive
yes | apt-get update
yes | apt-get install git unzip apt-utils wget curl

# نصب Docker
curl -fsSL https://get.docker.com | sh

# کلون کردن مخزن و ورود به آن
git clone https://github.com/khodedawsh/marznode

sleep 2

cd marznode

sleep 3

# تنظیم پراکسی برای Docker فقط اگر سرور ایران باشد
if [ "$iran_server" = true ] && [ -n "$proxy_url" ]; then
  sudo mkdir -p /etc/systemd/system/docker.service.d
  echo -e "[Service]\nEnvironment=\"HTTP_PROXY=$proxy_url\"\nEnvironment=\"HTTPS_PROXY=$proxy_url\"\nEnvironment=\"NO_PROXY=localhost,127.0.0.1,$(hostname -I | awk '{print $1}')\"" \
    | sudo tee /etc/systemd/system/docker.service.d/http-proxy.conf
  echo "Docker proxy configuration written."
fi

sleep 2

sudo systemctl daemon-reload

sudo systemctl restart docker

sleep 1

docker pull hello-world

sleep 5

cd marznode && docker compose up -d

# Decode و ذخیره فایل client.pem اگر آرگومان سوم موجود باشد
if [ -n "$node_cert" ]; then
  sudo mkdir -p /var/lib/marznode
  echo "$node_cert" | base64 -d | sudo tee /var/lib/marznode/client.pem > /dev/null
  sudo chmod 600 /var/lib/marznode/client.pem
  echo "client.pem written to /var/lib/marznode/"
fi

sleep 1

cd && mkdir -p /var/lib/marznode/data && cd /var/lib/marznode/data

sleep 1

# دانلود و استخراج Xray
if [ "$xray_version" = "latest" ]; then
    xray_url="https://github.com/XTLS/Xray-core/releases/download/$xray_version/Xray-linux-64.zip"
else
    xray_url="https://github.com/XTLS/Xray-core/releases/$xray_version/download/Xray-linux-64.zip"
fi

wget "$xray_url"

sleep 1

unzip Xray-linux-64.zip
rm Xray-linux-64.zip

sleep 1

chmod +x xray

echo "Xray downloaded and extracted (version: $xray_version)"

sleep 1

if [ "$iran_server" = true ] && [ -n "$proxy_url" ]; then
  cd && sudo rm -f /etc/apt/apt.conf.d/95proxy && \
  unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY && \
  sudo apt update -y && \
  sudo rm -f /etc/systemd/system/docker.service.d/http-proxy.conf && \
  cd /var/lib/marznode/data
fi

sleep 1

cp /root/marznode/xray_config.json /var/lib/marznode/xray_config.json

sleep 1

cp /var/lib/marznode/data/xray /var/lib/marznode/xray

sleep 1

cd && cd marznode

sleep 1

rm -rf compose.yml

sleep 1

# ایجاد فایل docker-compose.yml با مقدار پورت از آرگومان چهارم
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

sleep 3

docker compose down && docker compose up -d

sleep 2

# چاپ IP و PORT
ip=$(ip -4 a | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v 127 | head -1)
g="\033[1;32m"; r="\033[0m"
w=29
bar() { printf "$1$(printf '─%.0s' $(seq 1 $w))$2\n"; }
line() { printf "│%-${w}s│\n" "$1"; }

echo -e "\n$g"
bar "┌" "┐"; line "IP:   $ip"; bar "├" "┤"; line "Port: $node_port"; bar "└" "┘"
echo -e "$r"
