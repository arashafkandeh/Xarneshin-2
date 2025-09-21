#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -euo pipefail

# --- Arguments ---
iran_server="$1"
proxy_url="$2"
node_cert="$3"
xray_version="${4:-latest}"
node_port="$5"

# --- Main Setup Function ---
main() {
  echo "--- Starting Node Setup ---"

  # --- 1. System & Dependencies ---
  echo "Updating package lists and installing dependencies..."
  export DEBIAN_FRONTEND=noninteractive
  if [ "$iran_server" = true ] && [ -n "$proxy_url" ]; then
    echo "Applying proxy for APT..."
    echo -e "Acquire::http::Proxy \"$proxy_url\";\nAcquire::https::Proxy \"$proxy_url\";" | tee /etc/apt/apt.conf.d/95proxy
  fi
  apt-get update -y -qq
  apt-get install -y -qq --no-install-recommends apt-utils git unzip wget curl
  
  # --- 2. Install Docker ---
  echo "Installing Docker..."
  if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com | sh
  else
    echo "Docker is already installed."
  fi
  systemctl start docker
  systemctl enable docker

  # --- 3. Prepare Directories & Files ---
  echo "Preparing directories and files in /var/lib/marznode..."
  XRAY_INSTALL_DIR="/var/lib/marznode"
  mkdir -p "$XRAY_INSTALL_DIR/data" # For Xray assets like geoip.dat

  # Create client.pem certificate
  if [ -n "$node_cert" ]; then
    echo "Writing client.pem certificate..."
    echo "$node_cert" | base64 -d > "$XRAY_INSTALL_DIR/client.pem"
    chmod 600 "$XRAY_INSTALL_DIR/client.pem"
  fi

  # Download and Install Xray
  echo "Downloading and installing Xray version: $xray_version..."
  local xray_zip_path="/tmp/Xray-linux-64.zip"
  local xray_url
  if [ "$xray_version" = "latest" ]; then
      xray_url="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
  else
      xray_url="https://github.com/XTLS/Xray-core/releases/download/$xray_version/Xray-linux-64.zip"
  fi
  wget -O "$xray_zip_path" "$xray_url"
  
  set +e # Temporarily disable exit on error for unzip
  unzip -o "$xray_zip_path" -d "$XRAY_INSTALL_DIR"
  local unzip_exit_code=$?
  set -e # Re-enable exit on error
  
  if [[ "$unzip_exit_code" -ne 0 && "$unzip_exit_code" -ne 1 ]]; then
    echo "ERROR: Unzip command failed with critical error code: $unzip_exit_code" >&2
    exit 1
  fi
  
  chmod +x "$XRAY_INSTALL_DIR/xray"
  rm "$xray_zip_path"
  echo "Xray installed successfully."
  
  # --- 4. Clone Repo & Set up Docker Compose ---
  echo "Cloning repository and setting up Docker..."
  local repo_dir="/root/marznode"
  if [ ! -d "$repo_dir" ]; then
    git clone --quiet https://github.com/marzneshin/marznode "$repo_dir"
  fi
  cd "$repo_dir"

  # Copy config from repo to the final destination
  cp "$repo_dir/xray_config.json" "$XRAY_INSTALL_DIR/xray_config.json"

  # Create Docker Compose file
  echo "Creating Docker Compose file..."
  cat > "$repo_dir/compose.yml" <<EOL
services:
  marznode:
    image: dawsh/marznode:latest
    restart: always
    network_mode: host
    command: [ "sh", "-c", "sleep 10 && python3 marznode.py" ]
    environment:
      SERVICE_PORT: "$node_port"
      XRAY_EXECUTABLE_PATH: "$XRAY_INSTALL_DIR/xray"
      XRAY_ASSETS_PATH: "$XRAY_INSTALL_DIR"
      XRAY_CONFIG_PATH: "$XRAY_INSTALL_DIR/xray_config.json"
      SSL_CLIENT_CERT_FILE: "$XRAY_INSTALL_DIR/client.pem"
      SSL_KEY_FILE: "./server.key"
      SSL_CERT_FILE: "./server.cert"
    volumes:
      - "$XRAY_INSTALL_DIR:$XRAY_INSTALL_DIR"
EOL

  # --- 5. Run Docker Compose ---
  echo "Pulling Docker images..."
  docker compose --no-ansi pull --quiet

  # Stop/remove quietly (suppress normal stdout; errors still on stderr)
  echo "Starting services with Docker Compose..."
  docker compose down --remove-orphans >/dev/null
  
  # Start detached; suppress pull/build progress and normal stdout; errors still on stderr
  docker compose --no-ansi up -d

  # --- 6. Cleanup ---
  if [ "$iran_server" = true ] && [ -n "$proxy_url" ]; then
    echo "Cleaning up proxy settings..."
    rm -f /etc/apt/apt.conf.d/95proxy
  fi

  echo "--- Node setup completed successfully! ---"
}

sudo rm /root/setup_node.sh

# Run the main function, redirecting all output to stderr to ensure it's logged
# by the parent Python script.
main >&2
