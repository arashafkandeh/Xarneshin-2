import json
import os
import logging

logger = logging.getLogger(__name__)

# Attempt to determine the base directory of the project if installed,
# otherwise assume a development structure.
# This logic might need refinement based on the actual deployment.
INSTALLED_BASE_DIR = "/opt/Xenon.xray"
DEV_BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))) # Should point to xenon_project

# Check if running in an installed environment
if os.path.exists(os.path.join(INSTALLED_BASE_DIR, "xenon")):
    BASE_DIR = INSTALLED_BASE_DIR
    CONFIG_FILE_PATH = os.path.join(BASE_DIR, "ports.json")
    TEMPLATES_DIR_PATH = os.path.join(BASE_DIR, "templates")
    STATIC_DIR_PATH = os.path.join(BASE_DIR, "static") # if you add a static folder at root
    ASSETS_DIR_PATH = os.path.join(BASE_DIR, "assets")
else:
    BASE_DIR = DEV_BASE_DIR
    CONFIG_FILE_PATH = os.path.join(BASE_DIR, "ports.json") # Create this for dev
    TEMPLATES_DIR_PATH = os.path.join(BASE_DIR, "xenon", "templates")
    STATIC_DIR_PATH = os.path.join(BASE_DIR, "xenon", "static")
    ASSETS_DIR_PATH = os.path.join(BASE_DIR, "assets")


DEFAULT_CONFIG = {
    "panel_port": 8000,
    "flask_port": 42689,
    "panel_use_https": False,
    "use_https": False,
    "domain": "",
    "cert_file": "",
    "key_file": ""
}

def get_config():
    logger.info(f"Attempting to load config from: {CONFIG_FILE_PATH}")
    if os.path.exists(CONFIG_FILE_PATH):
        try:
            with open(CONFIG_FILE_PATH, "r") as f:
                data = json.load(f)
                config = {**DEFAULT_CONFIG, **data}
                logger.info(f"Config loaded successfully from {CONFIG_FILE_PATH}: {config}")
                return config
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading {CONFIG_FILE_PATH}: {e}. Using default config.")
            return DEFAULT_CONFIG
    else:
        logger.warning(f"{CONFIG_FILE_PATH} not found. Using default config.")
        # For development, create a default ports.json if it doesn't exist
        if BASE_DIR == DEV_BASE_DIR and not os.path.exists(CONFIG_FILE_PATH):
            try:
                with open(CONFIG_FILE_PATH, "w") as f:
                    json.dump(DEFAULT_CONFIG, f, indent=2)
                logger.info(f"Created default config file at {CONFIG_FILE_PATH}")
            except IOError as e:
                logger.error(f"Could not create default config file at {CONFIG_FILE_PATH}: {e}")
        return DEFAULT_CONFIG

app_config = get_config()

PANEL_PORT = app_config["panel_port"]
FLASK_PORT = app_config["flask_port"]
PANEL_USE_HTTPS = app_config["panel_use_https"]
USE_HTTPS = app_config["use_https"]
DOMAIN = app_config["domain"]
CERT_FILE = app_config["cert_file"] # Should be absolute path or relative to BASE_DIR
KEY_FILE = app_config["key_file"]   # Should be absolute path or relative to BASE_DIR
HOST = "0.0.0.0"

API_BASE_URL = f"{'https' if PANEL_USE_HTTPS else 'http'}://127.0.0.1:{PANEL_PORT}/api"

# Ensure CERT_FILE and KEY_FILE are absolute paths if provided
if USE_HTTPS:
    if CERT_FILE and not os.path.isabs(CERT_FILE):
        CERT_FILE = os.path.join(BASE_DIR, CERT_FILE)
    if KEY_FILE and not os.path.isabs(KEY_FILE):
        KEY_FILE = os.path.join(BASE_DIR, KEY_FILE)

logger.info(f"Base directory determined as: {BASE_DIR}")
logger.info(f"Templates directory: {TEMPLATES_DIR_PATH}")
logger.info(f"Assets directory: {ASSETS_DIR_PATH}")
logger.info(f"API Base URL: {API_BASE_URL}")
if USE_HTTPS:
    logger.info(f"Flask SSL enabled. Cert: {CERT_FILE}, Key: {KEY_FILE}")

# Path for xrayc.sh
XRAYC_SH_PATH = os.path.join(ASSETS_DIR_PATH, "xrayc.sh")
WARP_PY_PATH = os.path.join(ASSETS_DIR_PATH, "warp.py") # Keeping original warp.py for now
                                                        # Will be replaced by xenon/tools/warp.py logic later.
                                                        # For now, tools/warp.py will just call this script.
                                                        # The plan is to eventually make tools/warp.py self-sufficient.
python_executable = "python3" # Or sys.executable for current python
