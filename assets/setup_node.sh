#!/bin/bash

# Exit on error
set -e

# --- Default Values ---
USE_PROXY="false"
PROXY_ADDRESS=""
PROXY_USER=""
PROXY_PASS=""
XRAY_VERSION="latest" # Default to latest, can be overridden
NODE_PORT="5566"     # Default port, can be overridden
CLIENT_PEM_CONTENT=""
SERVER_IP_FOR_OUTPUT=""

# --- Validate Critical Inputs ---
if [[ ! "$NODE_PORT" =~ ^[0-9]+$ ]] || [ "$NODE_PORT" -lt 1 ] || [ "$NODE_PORT" -gt 65535 ]; then
  echo "ERROR: Invalid NODE_PORT: $NODE_PORT. Must be a number between 1 and 65535." >&2
  exit 1
fi

# --- Parse Command Line Arguments ---
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --use-proxy) USE_PROXY="true"; shift ;;
    --proxy-address) PROXY_ADDRESS="$2"; shift 2 ;;
    --proxy-user) PROXY_USER="$2"; shift 2 ;;
    --proxy-pass) PROXY_PASS="$2"; shift 2 ;;
    --xray-version) XRAY_VERSION="$2"; shift 2 ;;
    --node-port) NODE_PORT="$2"; shift 2 ;;
    --client-pem-base64) CLIENT_PEM_CONTENT_BASE64="$2"; shift 2 ;;
    --server-ip) SERVER_IP_FOR_OUTPUT="$2"; shift 2 ;;
    *) echo "ERROR: Unknown parameter: $1" >&2; exit 1 ;;
  esac
done

# Decode client.pem from base64 if provided
if [[ -n "$CLIENT_PEM_CONTENT_BASE64" ]]; then
  CLIENT_PEM_CONTENT=$(echo "$CLIENT_PEM_CONTENT_BASE64" | base64 -d)
  if [[ $? -ne 0 ]]; then
    echo "ERROR: Failed to decode client.pem from base64." >&2
    exit 1
  fi
fi

# --- Setup Proxy if enabled ---
PROXY_URL=""
if [[ "$USE_PROXY" == "true" && -n "$PROXY_ADDRESS" ]]; then
  echo "INFO: Proxy is enabled. Setting up proxy: $PROXY_ADDRESS"
  if [[ -n "$PROXY_USER" && -n "$PROXY_PASS" ]]; then
    PROXY_URL="socks5h://$PROXY_USER:$PROXY_PASS@$PROXY_ADDRESS"
  else
    PROXY_URL="socks5h://$PROXY_ADDRESS"
  fi
  echo -e "Acquire::http::Proxy \"$PROXY_URL/\";\nAcquire::https::Proxy \"$PROXY_URL/\";" | tee /etc/apt/apt.conf.d/95proxy
  export ALL_PROXY="$PROXY_URL"
  export HTTP_PROXY="$PROXY_URL"
  export HTTPS_PROXY="$PROXY_URL"
else
  echo "INFO: Proxy is not used or address not provided."
fi

# --- Install dependencies ---
echo "INFO: Updating packages and installing dependencies..."
apt-get update -y && apt-get install -y git curl apt-transport-https ca-certificates software-properties-common unzip apt-utils

# Install Docker
if ! command -v docker >/dev/null 2>&1; then
  echo "INFO: Installing Docker..."
  curl -fsSL https://get.docker.com | sh
fi

echo "INFO: Cloning marznode repository..."
rm -rf ~/marznode # Remove if exists
git clone https://github.com/khodedawsh/marznode ~/marznode
cd ~/marznode

# --- Configure Docker Proxy if needed ---
if [[ "$USE_PROXY" == "true" && -n "$PROXY_URL" ]]; then
  echo "INFO: Configuring proxy for Docker service..."
  mkdir -p /etc/systemd/system/docker.service.d
  echo -e "[Service]\nEnvironment=\"HTTP_PROXY=$PROXY_URL\"\nEnvironment=\"HTTPS_PROXY=$PROXY_URL\"\nEnvironment=\"NO_PROXY=localhost,127.0.0.1,$PROXY_ADDRESS\"" | tee /etc/systemd/system/docker.service.d/http-proxy.conf
  systemctl daemon-reload
  systemctl restart docker
  echo "INFO: Docker proxy configured and Docker restarted."
fi

# --- Create client.pem ---
echo "INFO: Setting up client.pem..."
MARZNODE_LIB_DIR="/var/lib/marznode"
mkdir -p "$MARZNODE_LIB_DIR"
if [[ -n "$CLIENT_PEM_CONTENT" ]]; then
  echo "$CLIENT_PEM_CONTENT" | tee "$MARZNODE_LIB_DIR/client.pem" > /dev/null
  echo "INFO: client.pem created with provided content."
else
  echo "INFO: client.pem content not provided, creating empty file."
  touch "$MARZNODE_LIB_DIR/client.pem"
fi

# --- Download and Setup Xray ---
DATA_DIR="$MARZNODE_LIB_DIR/data"
mkdir -p "$DATA_DIR"
cd "$DATA_DIR"

ARCH=$(uname -m)
XRAY_ZIP_FILE=""
if [[ "$ARCH" == "x86_64" ]]; then
  XRAY_ZIP_FILE="Xray-linux-64.zip"
elif [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then
  XRAY_ZIP_FILE="Xray-linux-arm64.zip"
else
  echo "ERROR: Unsupported CPU architecture: $ARCH" >&2
  exit 1
fi

# If XRAY_VERSION is 'latest', fetch the actual latest tag name
if [[ "$XRAY_VERSION" == "latest" ]]; then
  echo "INFO: Fetching latest Xray version tag..."
  LATEST_TAG=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep 'tag_name' | cut -d\" -f4)
  if [[ -z "$LATEST_TAG" ]]; then
    echo "ERROR: Could not fetch latest Xray version tag." >&2
    exit 1
  fi
  XRAY_VERSION=$LATEST_TAG
  echo "INFO: Latest Xray version is $XRAY_VERSION"
fi

echo "INFO: Downloading Xray version $XRAY_VERSION ($XRAY_ZIP_FILE)..."
rm -f "$XRAY_ZIP_FILE" xray # Clean up previous versions
wget -q "https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION/$XRAY_ZIP_FILE" -O "$XRAY_ZIP_FILE"
if [[ $? -ne 0 ]]; then
  echo "ERROR: Download failed for Xray $XRAY_VERSION ($XRAY_ZIP_FILE)" >&2
  exit 1
fi
unzip -o "$XRAY_ZIP_FILE"
rm "$XRAY_ZIP_FILE"
if [[ ! -f xray ]]; then
  echo "ERROR: xray binary not found after unzipping." >&2
  exit 1
fi
cp xray "$MARZNODE_LIB_DIR/xray"
chmod +x "$MARZNODE_LIB_DIR/xray"
echo "INFO: Xray version $XRAY_VERSION installed to $MARZNODE_LIB_DIR/xray"

# --- Prepare Marznode Configs ---
echo "INFO: Preparing Marznode configurations..."
if [[ ! -f ~/marznode/xray_config.json ]]; then
  echo "ERROR: ~/marznode/xray_config.json not found after cloning repository." >&2
  exit 1
fi
cp ~/marznode/xray_config.json "$MARZNODE_LIB_DIR/xray_config.json"

cd ~/marznode
rm -f compose.yml docker-compose.yml # Remove both for compatibility

# --- Create docker-compose.yml ---
echo "INFO: Creating docker-compose.yml with NODE_PORT: $NODE_PORT..."
tee docker-compose.yml > /dev/null << EOL
services:
  marznode:
    image: dawsh/marznode:latest
    restart: always
    network_mode: host
    command: [ "sh", "-c", "sleep 5 && python3 marznode.py" ]
    environment:
      NODE_PORT: "$NODE_PORT"
      XRAY_EXECUTABLE_PATH: "/var/lib/marznode/xray"
      XRAY_ASSETS_PATH: "/var/lib/marznode/data"
      XRAY_CONFIG_PATH: "/var/lib/marznode/xray_config.json"
      SSL_CLIENT_CERT_FILE: "/var/lib/marznode/client.pem"
      # SSL_KEY_FILE and SSL_CERT_FILE are typically generated by marznode or expected in /var/lib/marznode.
      # If user-provided, they should be handled similarly to client.pem (e.g., via base64 input).
      # Ensure they are present in ~/marznode or /var/lib/marznode if generated by the panel or image.
    volumes:
      - /var/lib/marznode:/var/lib/marznode
EOL

# --- Run Docker Compose ---
echo "INFO: Running docker compose down (if exists) and up -d..."
if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: Docker is not installed or not in PATH." >&2
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: Docker Compose V2 is not available. Please install/update Docker." >&2
  exit 1
fi

docker compose down --remove-orphans || true # Ignore error if not running
docker compose up -d

# --- Clean up proxy settings if used ---
if [[ "$USE_PROXY" == "true" && -n "$PROXY_URL" ]]; then
  echo "INFO: Cleaning up proxy settings..."
  rm -f /etc/apt/apt.conf.d/95proxy
  unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY
  if [[ -f /etc/systemd/system/docker.service.d/http-proxy.conf ]]; then
    rm -f /etc/systemd/system/docker.service.d/http-proxy.conf
    systemctl daemon-reload
    systemctl restart docker
  fi
fi

# --- Final Output ---
FINAL_SERVER_IP=${SERVER_IP_FOR_OUTPUT:-$(curl -s ifconfig.me || hostname -I | awk '{print $1}' || echo "UNKNOWN_IP")}
echo "SETUP_SUCCESS"
echo "Server_IP: $FINAL_SERVER_IP"
echo "Node_Port: $NODE_PORT"

exit 0
