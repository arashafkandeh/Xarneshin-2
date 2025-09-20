#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status.
set -e

###############################################################################
#                           ANSI COLOR CONSTANTS                              #
###############################################################################
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[0;36m'
NC='\033[0m'

###############################################################################
#                         GLOBAL VARS & FILE PATHS                            #
###############################################################################
INSTALL_DIR="/opt/Xenon.xray"
SOURCE_DIR="/root/Xenon.xray" # This script assumes it's run from here after git clone
ENV_FILE="/etc/opt/marzneshin/.env"
SERVICE_FILE="/etc/systemd/system/xarneshin.service"
CLI_PATH="/usr/local/bin/xarneshin"
PORTS_FILE="$INSTALL_DIR/ports.json"
LOG_FILE="/tmp/xarneshin_install.log"

# Clear previous log file
> "$LOG_FILE"

###############################################################################
#                            SPINNER FUNCTION                                 #
###############################################################################
spinner() {
  local pid="$1"
  local spin='-\|/'
  local i=0
  while kill -0 "$pid" 2>/dev/null; do
    i=$(( (i+1) % 4 ))
    printf "\r${CYAN}[Action]${NC} ${GREEN}Installing...${NC} ${spin:$i:1} Please wait..."
    sleep 0.15
  done
  printf "\r\033[K" # Clear the line after spinner stops
}

###############################################################################
#                              CHECK FOR ROOT                                 #
###############################################################################
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}ERROR: This script must be run as root.${NC}"
  exit 1
fi

# Set non-interactive frontend for apt to prevent prompts
export DEBIAN_FRONTEND=noninteractive

echo -e "${CYAN}[Action]${NC} ${GREEN}Performing initial setup...${NC}"
echo -e "  - Making files ready..."

###############################################################################
#                MOVE /root/Xenon.xray -> /opt/Xenon.xray IF FIRST RUN        #
###############################################################################
if [[ -d "$SOURCE_DIR" && ! -d "$INSTALL_DIR" ]]; then
  echo -e "  - Moving source files to $INSTALL_DIR"
  mv "$SOURCE_DIR" "$INSTALL_DIR"
  
  # Apply dos2unix and chmod +x to .sh files and python scripts
  echo -e "  - Applying file corrections (dos2unix, chmod)..."
  find "$INSTALL_DIR" -type f \( -name "*.sh" -o -name "*.py" \) -exec sed -i 's/\r$//' {} \; -exec chmod +x {} \;

elif [[ -d "$INSTALL_DIR" ]]; then
    echo -e "${YELLOW}Warning:${NC} Installation directory $INSTALL_DIR already exists. Skipping move."
elif [[ ! -d "$SOURCE_DIR" ]]; then
  echo -e "${RED}ERROR: Source directory $SOURCE_DIR not found. Did the git clone fail? Exiting.${NC}"
  exit 1
fi

###############################################################################
#           INSTALL PYTHON + DEPENDENCIES                                      #
###############################################################################
echo -e "\n${CYAN}[Action]${NC} ${GREEN}Installing Python and dependencies...${NC}"
echo "Installation logs are being saved to $LOG_FILE"

# Function to run the installation process
install_dependencies() {
    echo "--- Starting Dependency Installation ---" >> "$LOG_FILE"
    
    # Step 1: Update package lists
    echo "Updating package lists..." >> "$LOG_FILE"
    apt-get update -y >> "$LOG_FILE" 2>&1
    
    # Step 2: Install packages with automatic yes to prompts
    echo "Installing system packages..." >> "$LOG_FILE"
    apt-get install -y --no-install-recommends python3 python3-pip curl jq >> "$LOG_FILE" 2>&1
    
    # Step 3: Upgrade pip first
    echo "Upgrading pip..." >> "$LOG_FILE"
    python3 -m pip install --upgrade pip >> "$LOG_FILE" 2>&1 || true
    
    # Step 4: Install Python packages
    echo "Installing Python packages..." >> "$LOG_FILE"
    
    # Try regular installation first
    if python3 -m pip install flask requests cryptography websockets psutil blinker paramiko PySocks >> "$LOG_FILE" 2>&1; then
        echo "Python packages installed successfully" >> "$LOG_FILE"
        return 0
    else
        echo "Regular pip installation failed, trying with --break-system-packages..." >> "$LOG_FILE"
        
        # Install additional dependencies for compilation
        apt-get install -y --no-install-recommends python3-dev python3-venv build-essential libssl-dev libffi-dev python3-setuptools >> "$LOG_FILE" 2>&1
        
        # Remove conflicting package if exists
        apt-get purge -y python3-blinker >> "$LOG_FILE" 2>&1 || true
        
        # Try with --break-system-packages flag (for newer systems)
        if python3 -m pip install --break-system-packages flask requests cryptography websockets psutil blinker paramiko PySocks >> "$LOG_FILE" 2>&1; then
            echo "Python packages installed with --break-system-packages" >> "$LOG_FILE"
            return 0
        else
            # Last resort: force installation
            echo "Trying force installation..." >> "$LOG_FILE"
            python3 -m pip install --force-reinstall --no-deps flask requests cryptography websockets psutil blinker paramiko PySocks >> "$LOG_FILE" 2>&1
            return $?
        fi
    fi
}

# Run installation in the background to show spinner
install_dependencies &
bg_pid=$!
spinner "$bg_pid"

# Wait for the background process and check its exit code
wait "$bg_pid"
install_status=$?

if [[ $install_status -eq 0 ]]; then
    echo -e "  - Successfully installed dependencies."
else
    echo -e "\n${YELLOW}Warning: Some dependencies may not have installed correctly.${NC}"
    echo -e "${YELLOW}Continuing with installation...${NC}"
    echo -e "${YELLOW}Please check the log file for details: ${CYAN}$LOG_FILE${NC}"
fi

###############################################################################
#                    DETERMINE MARZNESHIN PANEL PORT & PROTOCOL              #
###############################################################################
echo -e "\n${CYAN}[Action]${NC} ${GREEN}Determining main panel settings from $ENV_FILE...${NC}"
PANEL_PORT_DEFAULT=8000
panel_use_https=false

if [[ -f "$ENV_FILE" ]]; then
  raw_port=$(grep '^UVICORN_PORT' "$ENV_FILE" | sed -E 's/.*UVICORN_PORT[[:space:]]*=[[:space:]]*([0-9]+).*/\1/')
  if [[ "$raw_port" =~ ^[0-9]+$ ]]; then
    panel_port="$raw_port"
    echo -e "  - Found Marzneshin's panel port: ${GREEN}$panel_port${NC}"
  else
    panel_port="$PANEL_PORT_DEFAULT"
    echo -e "  - Could not parse UVICORN_PORT. Using default: ${GREEN}$panel_port${NC}"
  fi

  # Check SSL settings
  ssl_cert=$(grep -E "^\s*UVICORN_SSL_CERTFILE\s*=" "$ENV_FILE" | grep -v "^\s*#")
  ssl_key=$(grep -E "^\s*UVICORN_SSL_KEYFILE\s*=" "$ENV_FILE" | grep -v "^\s*#")
  if [[ -n "$ssl_cert" && -n "$ssl_key" ]]; then
    panel_use_https=true
    echo -e "  - Detected HTTPS for panel (SSL cert and key present)"
  else
    echo -e "  - No SSL settings found. Using HTTP for panel"
  fi
else
  panel_port="$PANEL_PORT_DEFAULT"
  echo -e "  - Marzneshin .env file not found. Using default panel port: ${GREEN}$panel_port${NC} and HTTP"
fi

###############################################################################
#                     CONFIGURE XARNESHIN FLASK PORT                          #
###############################################################################
echo -e "\n-------- Configuring Xarneshin Port --------"
echo -e "${BLUE}Choose Xarneshin (this panel) port:${NC}"
echo -e "${GREEN}1${NC}- Set a random port (Recommended)"
echo -e "${GREEN}2${NC}- Set a custom port"

# Check if we're in a non-interactive mode (piped input)
if [ -t 0 ]; then
    read -p "Please enter your choice [1 or 2, default=2]: " choice
    choice=${choice:-2} # Set default to 2 if empty
else
    echo "Non-interactive mode detected, using default choice: 2"
    choice=2
fi

if [[ "$choice" == "1" ]]; then
  flask_port=$(( (RANDOM % 45535 ) + 20000 ))
  echo -e "  - Using random port: ${GREEN}$flask_port${NC}"
else
  if [ -t 0 ]; then
      read -p "Enter custom Flask port [default: 42689]: " user_port
      flask_port=${user_port:-42689} # Set default port if empty
  else
      flask_port=42689
      echo "Non-interactive mode: Using default Flask port: $flask_port"
  fi
  echo -e "  - Using custom port: ${GREEN}$flask_port${NC}"
fi

# Ensure install directory exists (in case it already existed and wasn't created by mv)
mkdir -p "$INSTALL_DIR"

# Write JSON with panel protocol
cat <<EOF > "$PORTS_FILE"
{
  "panel_port": $panel_port,
  "flask_port": $flask_port,
  "panel_use_https": $panel_use_https,
  "use_https": false,
  "domain": "",
  "cert_file": "",
  "key_file": ""
}
EOF

###############################################################################
#                        CREATE SYSTEMD SERVICE                               #
###############################################################################
echo -e "\n${CYAN}[Action]${NC} ${GREEN}Creating systemd service: $SERVICE_FILE...${NC}"

cat << EOF > "$SERVICE_FILE"
[Unit]
Description=Xarneshin Flask App by Arash Afkandeh
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/xenon.py
Restart=always
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable xarneshin.service
systemctl restart xarneshin.service

###############################################################################
#                        CREATE XARNESHIN CLI TOOL                            #
###############################################################################
echo -e "\n${CYAN}[Action]${NC} ${GREEN}Creating Xarneshin CLI tool...${NC}"

cat << 'EOS' > "$CLI_PATH"
#!/usr/bin/env bash

# Exit on error
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[0;36m'
NC='\033[0m'

INSTALL_DIR="/opt/Xenon.xray"
PORTS_FILE="$INSTALL_DIR/ports.json"
SERVICE="xarneshin.service"
ENV_FILE="/etc/opt/marzneshin/.env"

declare -A GEOFILES=(
  ["https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"]="geoip.dat"
  ["https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"]="geosite.dat"
  ["https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geoip.dat"]="geoip_IR.dat"
  ["https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geosite.dat"]="geosite_IR.dat"
  ["https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat"]="geoip_RU.dat"
  ["https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat"]="geosite_RU.dat"
)

function get_ipv4() {
  # Try multiple sources for robustness
  curl -4 -s ifconfig.me || curl -4 -s api.ipify.org || echo "N/A"
}

function get_uptime() {
  if ! systemctl is-active --quiet "$SERVICE"; then
    echo "N/A"
    return
  fi
  local start_ts=$(systemctl show "$SERVICE" -p ActiveEnterTimestamp --value | sed 's/^\w\+\s*//')
  if [[ -z "$start_ts" || "$start_ts" == "n/a" ]]; then
    echo "N/A"
    return
  fi
  local start_sec=$(date -d "$start_ts" +%s 2>/dev/null)
  local now_sec=$(date +%s)
  if [[ -z "$start_sec" || "$start_sec" -gt "$now_sec" ]]; then
    echo "N/A"
    return
  fi
  local diff=$(( now_sec - start_sec ))
  local d=$(( diff / 86400 ))
  local h=$(( (diff % 86400) / 3600 ))
  local m=$(( (diff % 3600) / 60 ))
  local s=$(( diff % 60 ))
  local out=""
  [[ $d -gt 0 ]] && out+="${d}d "
  [[ $h -gt 0 ]] && out+="${h}h "
  [[ $m -gt 0 ]] && out+="${m}m "
  out+="${s}s"
  echo "$out"
}

function get_mode() {
  if [[ ! -f "$PORTS_FILE" ]]; then
    echo "Unknown"
    return
  fi
  local use_https=$(jq -r '.use_https' "$PORTS_FILE" 2>/dev/null)
  if [[ "$use_https" == "true" ]]; then
    echo "HTTPS"
  else
    echo "HTTP"
  fi
}

function get_panel_mode() {
  if [[ ! -f "$PORTS_FILE" ]]; then
    echo "Unknown"
    return
  fi
  local panel_use_https=$(jq -r '.panel_use_https' "$PORTS_FILE" 2>/dev/null)
  if [[ "$panel_use_https" == "true" ]]; then
    echo "HTTPS"
  else
    echo "HTTP"
  fi
}

function short_status() {
  systemctl is-active --quiet "$SERVICE"
  local active=$?
  local status_str
  if [[ $active -eq 0 ]]; then
    status_str="${GREEN}Running${NC}"
  else
    status_str="${RED}Not Running${NC}"
  fi
  local up=$(get_uptime)
  local mode=$(get_mode)
  local panel_mode=$(get_panel_mode)
  echo -e "${GREEN}Xarneshin Manager${NC}"
  echo -e "Xarneshin Mode Protocol:  [${CYAN}$mode${NC}]"
  echo -e "Marzneshin Mode Protocol: [${CYAN}$panel_mode${NC}]"
  echo -e "Status:                   [${status_str}]"
  echo -e "Uptime:                   [${CYAN}$up${NC}]"
}

function detail_status() {
  systemctl status "$SERVICE" --no-pager
}

function show_access_address() {
  if [[ ! -f "$PORTS_FILE" ]]; then
    echo -e "${RED}ports.json not found!${NC}"
    return
  fi
  local flask_port=$(jq -r '.flask_port' "$PORTS_FILE")
  local use_https=$(jq -r '.use_https' "$PORTS_FILE")
  local domain=$(jq -r '.domain' "$PORTS_FILE")
  local ip4=$(get_ipv4)
  local proto="http"
  local host="$ip4"
  if [[ "$use_https" == "true" && -n "$domain" ]]; then
    proto="https"
    host="$domain"
  fi
  if [[ -z "$ip4" || "$ip4" == "N/A" ]]; then
    echo -e "${YELLOW}Cannot detect IPv4 automatically.${NC}"
  else
    echo -e "${GREEN}Access URL:${NC} $proto://$host:$flask_port"
  fi
}

function change_ports_submenu() {
  while true; do
    echo -e "${BLUE}\nChange Ports${NC}"
    echo -e "${GREEN}0)${NC} Back"
    echo -e "${GREEN}1)${NC} Automatically fetch Marzneshin panel port from .env"
    echo -e "${GREEN}2)${NC} Change Xarneshin Flask port"
    read -p "Choose [0-2, default=2]: " cchoice
    cchoice=${cchoice:-2}
    case "$cchoice" in
      0) return ;;
      1)
        if [[ ! -f "$ENV_FILE" ]]; then
          echo -e "${RED}$ENV_FILE not found!${NC}"
          continue
        fi
        local raw_port=$(grep '^UVICORN_PORT' "$ENV_FILE" | sed -E 's/.*UVICORN_PORT[[:space:]]*=[[:space:]]*([0-9]+).*/\1/')
        if [[ "$raw_port" =~ ^[0-9]+$ ]]; then
          jq --argjson new_port "$raw_port" '.panel_port = $new_port' "$PORTS_FILE" > "${PORTS_FILE}.tmp" && mv "${PORTS_FILE}.tmp" "$PORTS_FILE"
          echo -e "${GREEN}Updated panel_port to $raw_port${NC}"
          systemctl restart "$SERVICE"
        else
          echo -e "${YELLOW}Could not parse UVICORN_PORT from $ENV_FILE${NC}"
        fi
        ;;
      2)
        echo -e "${BLUE}\nChange Xarneshin Flask port${NC}"
        echo -e "${GREEN}0)${NC} Back"
        echo -e "${GREEN}1)${NC} Random port"
        echo -e "${GREEN}2)${NC} Manual port"
        read -p "Choose [0-2, default=2]: " fchoice
        fchoice=${fchoice:-2}
        local new_flask_port
        case "$fchoice" in
          0) continue ;;
          1)
            new_flask_port=$(( (RANDOM % 45535 ) + 20000 ))
            echo -e "${GREEN}Random Flask port chosen: $new_flask_port${NC}"
            ;;
          2)
            read -p "Enter Flask port: " new_flask_port
            if [[ ! "$new_flask_port" =~ ^[0-9]+$ ]]; then
              echo -e "${RED}Invalid numeric input.${NC}"
              continue
            fi
            ;;
          *) echo -e "${RED}Invalid choice.${NC}"; continue ;;
        esac
        jq --argjson new_port "$new_flask_port" '.flask_port = $new_port' "$PORTS_FILE" > "${PORTS_FILE}.tmp" && mv "${PORTS_FILE}.tmp" "$PORTS_FILE"
        echo -e "${GREEN}Flask port changed to $new_flask_port${NC}"
        echo -e "${GREEN}Restarting Xarneshin...${NC}"
        systemctl restart "$SERVICE"
        show_access_address
        ;;
      *) echo -e "${RED}Invalid choice.${NC}" ;;
    esac
  done
}

function change_panel_protocol() {
  while true; do
    echo -e "${BLUE}\nConfigure Panel Protocol${NC}"
    echo -e "${GREEN}0)${NC} Back"
    echo -e "${GREEN}1)${NC} Use HTTPS for panel (insecure mode, bypass SSL verification)"
    echo -e "${GREEN}2)${NC} Use HTTP for panel"
    read -p "Choose [0-2, default=2]: " pchoice
    pchoice=${pchoice:-2}
    case "$pchoice" in
      0) return ;;
      1 | 2)
        local new_https_val=false
        local msg="Panel protocol set to HTTP"
        if [[ "$pchoice" == "1" ]]; then
            new_https_val=true
            msg="Panel protocol set to HTTPS (insecure mode)"
        fi
        jq --argjson new_val "$new_https_val" '.panel_use_https = $new_val' "$PORTS_FILE" > "${PORTS_FILE}.tmp" && mv "${PORTS_FILE}.tmp" "$PORTS_FILE"
        echo -e "${GREEN}$msg${NC}"
        systemctl restart "$SERVICE"
        break
        ;;
      *) echo -e "${RED}Invalid choice.${NC}" ;;
    esac
  done
}

function change_https_settings() {
  while true; do
    echo -e "${BLUE}\nConfigure HTTPS Settings${NC}"
    echo -e "${GREEN}0)${NC} Back"
    echo -e "${GREEN}1)${NC} Enable HTTPS"
    echo -e "${GREEN}2)${NC} Disable HTTPS (switch to HTTP)"
    read -p "Choose [0-2, default=2]: " hchoice
    hchoice=${hchoice:-2}
    case "$hchoice" in
      0) return ;;
      1)
        read -p "Enter domain or IP (e.g., example.com): " domain
        read -p "Enter path to certificate file (e.g., /path/to/cert.pem): " cert_file
        read -p "Enter path to private key file (e.g., /path/to/private.key): " key_file
        if [[ -n "$domain" && -f "$cert_file" && -f "$key_file" ]]; then
          jq --arg new_domain "$domain" --arg new_cert "$cert_file" --arg new_key "$key_file" \
             '.use_https = true | .domain = $new_domain | .cert_file = $new_cert | .key_file = $new_key' \
             "$PORTS_FILE" > "${PORTS_FILE}.tmp" && mv "${PORTS_FILE}.tmp" "$PORTS_FILE"
          echo -e "${GREEN}HTTPS enabled with domain: $domain${NC}"
        else
          echo -e "${RED}Invalid input or files not found. No changes made.${NC}"
          continue
        fi
        systemctl restart "$SERVICE"
        show_access_address
        break
        ;;
      2)
        jq '.use_https = false | .domain = "" | .cert_file = "" | .key_file = ""' \
           "$PORTS_FILE" > "${PORTS_FILE}.tmp" && mv "${PORTS_FILE}.tmp" "$PORTS_FILE"
        echo -e "${GREEN}Switched to HTTP${NC}"
        systemctl restart "$SERVICE"
        show_access_address
        break
        ;;
      *) echo -e "${RED}Invalid choice.${NC}" ;;
    esac
  done
}

function update_geofiles_cmd() {
  while true; do
    echo -e "${BLUE}\nUpdate Geo Files${NC}"
    echo -e "${GREEN}0)${NC} Back"
    echo -e "${GREEN}1)${NC} Use default directory (/var/lib/marznode)"
    echo -e "${GREEN}2)${NC} Use custom directory"
    read -p "Choose [0-2, default=1]: " gfchoice
    gfchoice=${gfchoice:-1}
    case "$gfchoice" in
      0) return ;;
      1 | 2)
        local target_directory="/var/lib/marznode"
        if [[ "$gfchoice" == "2" ]]; then
          read -p "Enter custom directory path: " custom_dir
          if [[ -n "$custom_dir" ]]; then
            target_directory="$custom_dir"
          fi
        fi
        mkdir -p "$target_directory"
        echo -e "${GREEN}Downloading geo files into: $target_directory${NC}"
        for url in "${!GEOFILES[@]}"; do
          local filename="${GEOFILES[$url]}"
          local dest="$target_directory/$filename"
          echo -e "Downloading ${YELLOW}$url${NC} to ${GREEN}$dest${NC}"
          if curl -L -s --fail "$url" -o "$dest"; then
            echo -e "   ${GREEN}Success${NC}"
          else
            echo -e "   ${RED}Failed to download: $url${NC}"
          fi
        done
        echo -e "${GREEN}All geo file downloads completed (where successful).${NC}"
        break
        ;;
      *) echo -e "${RED}Invalid choice.${NC}" ;;
    esac
  done
}

function restart_cmd() {
  echo -e "${BLUE}Restarting $SERVICE...${NC}"
  systemctl restart "$SERVICE"
  echo -e "${GREEN}Service restarted.${NC}"
}

function uninstall_cmd() {
  echo -ne "${RED}Are you sure you want to uninstall Xarneshin? This is IRREVERSIBLE. (y/N): ${NC}"
  read answer
  if [[ "$answer" =~ ^[Yy]$ ]]; then
    echo -e "${RED}Uninstalling Xarneshin...${NC}"
    systemctl stop "$SERVICE" &>/dev/null || true
    systemctl disable "$SERVICE" &>/dev/null || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    echo -e "${RED}Removing installation directory $INSTALL_DIR...${NC}"
    rm -rf "$INSTALL_DIR"
    echo -e "${RED}Removing CLI tool $CLI_PATH...${NC}"
    rm -f "$CLI_PATH"
    echo -e "${GREEN}Uninstallation complete.${NC}"
  else
    echo -e "${YELLOW}Uninstall canceled.${NC}"
  fi
}

function menu() {
  while true; do
    short_status
    echo -e "──────────────────────────────"
    echo -e "${GREEN}1)${NC} Show Service detailed status"
    echo -e "${GREEN}2)${NC} Change Ports"
    echo -e "${GREEN}3)${NC} Update Geo Files"
    echo -e "${GREEN}4)${NC} Restart Xarneshin"
    echo -e "${GREEN}5)${NC} Show Access address"
    echo -e "${GREEN}6)${NC} Configure Xarneshin HTTPS"
    echo -e "${GREEN}7)${NC} Configure Marzneshin Panel Protocol"
    echo -e "${RED}8)${NC} Uninstall"
    echo -e "${YELLOW}9)${NC} Exit"
    read -p "Choose [1-9]: " choice
    case "$choice" in
      1) detail_status ;;
      2) change_ports_submenu ;;
      3) update_geofiles_cmd ;;
      4) restart_cmd ;;
      5) show_access_address ;;
      6) change_https_settings ;;
      7) change_panel_protocol ;;
      8) uninstall_cmd; break ;;
      9) echo -e "${GREEN}Bye.${NC}"; break ;;
      *) echo -e "${RED}Invalid choice.${NC}" ;;
    esac
    echo
  done
}

# Main execution logic
if [[ $# -eq 0 ]]; then
  menu
else
  case "$1" in
    status) short_status ;;
    detail) detail_status ;;
    change-ports) change_ports_submenu ;;
    update-geofiles) update_geofiles_cmd ;;
    restart) restart_cmd ;;
    show-address) show_access_address ;;
    uninstall) uninstall_cmd ;;
    *) echo -e "${YELLOW}Usage: $0 [status|detail|change-ports|update-geofiles|restart|show-address|uninstall]${NC}" >&2; exit 1 ;;
  esac
fi
EOS

chmod +x "$CLI_PATH"

###############################################################################
#                            FINAL INSTALL REPORT                             #
###############################################################################
ipv4=$(curl -4 -s ifconfig.me || curl -4 -s api.ipify.org || echo "N/A")
echo -e "\n${CYAN}=====================================================${NC}"
echo -e "${GREEN}      Xarneshin Installation Complete!${NC}"
echo -e "${CYAN}=====================================================${NC}\n"
printf "  ${BLUE}%-20s${NC} %s\n" "Service name:" "xarneshin.service"
printf "  ${BLUE}%-20s${NC} %s\n" "CLI command:" "xarneshin"
printf "  ${BLUE}%-20s${NC} %s\n" "Main panel port:" "$panel_port"
printf "  ${BLUE}%-20s${NC} %s\n" "Xarneshin port:" "$flask_port"
if [[ "$ipv4" != "N/A" ]]; then
    printf "  ${BLUE}%-20s${NC} %s\n" "Server IPv4:" "$ipv4"
    printf "  ${BLUE}%-20s${NC} ${GREEN}http://$ipv4:$flask_port${NC}\n" "Access URL:"
fi
echo -e "\n  ${YELLOW}Run 'xarneshin' to manage the service.${NC}"
echo -e "  ${YELLOW}Note:${NC} For secure access, use '${GREEN}xarneshin${NC}' (option 6) to enable HTTPS."
echo -e "  ${YELLOW}Installation logs:${NC} $LOG_FILE\n"
