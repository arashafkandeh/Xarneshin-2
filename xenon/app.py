import logging
import secrets # For Flask secret_key
import os

from flask import Flask, session, redirect, url_for, request, render_template

# --- Configuration ---
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s') # DEBUG for dev
logger = logging.getLogger(__name__)

try:
    from .config import (
        FLASK_PORT, HOST, USE_HTTPS, DOMAIN, CERT_FILE, KEY_FILE,
        TEMPLATES_DIR_PATH, STATIC_DIR_PATH, BASE_DIR, CONFIG_FILE_PATH
    )
    logger.info("Successfully imported configuration from .config")
except ImportError:
    logger.critical("Failed to import configuration from .config. Ensure config.py exists and is correct.", exc_info=True)
    FLASK_PORT, HOST, USE_HTTPS, DOMAIN, CERT_FILE, KEY_FILE = 8080, "0.0.0.0", False, "", "", ""
    TEMPLATES_DIR_PATH = os.path.join(os.path.dirname(__file__), "templates")
    STATIC_DIR_PATH = os.path.join(os.path.dirname(__file__), "static")
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    CONFIG_FILE_PATH = os.path.join(BASE_DIR, "ports.json_fallback")
    logger.warning("Using fallback default configurations due to import error.")


# --- Flask App Initialization ---
app = Flask(
    __name__,
    template_folder=TEMPLATES_DIR_PATH,
    static_folder=STATIC_DIR_PATH
)

app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(16))

# --- Register Blueprints ---
try:
    from xenon.auth import auth_bp
    from xenon.nodes import nodes_bp
    from xenon.core import core_bp
    from xenon.xray_config import (
        xray_general_bp, inbounds_bp, outbounds_bp, dns_bp,
        routing_bp, balancers_bp, reverse_bp
    )
    from xenon.tools import tools_bp
    from xenon.system_info import system_info_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(nodes_bp)
    app.register_blueprint(core_bp) # core_bp routes are defined with their full paths or node_id context

    app.register_blueprint(xray_general_bp)
    app.register_blueprint(inbounds_bp)
    app.register_blueprint(outbounds_bp)
    app.register_blueprint(dns_bp)
    app.register_blueprint(routing_bp)
    app.register_blueprint(balancers_bp)
    app.register_blueprint(reverse_bp)

    app.register_blueprint(tools_bp)
    app.register_blueprint(system_info_bp)

    logger.info("All blueprints registered successfully.")

except ImportError as e:
    logger.critical(f"Failed to import or register blueprints: {e}", exc_info=True)

# --- Global Error Handlers (Optional) ---
@app.errorhandler(404)
def page_not_found(e):
    logger.warning(f"404 Not Found: {request.path} - {e}")
    return render_template('404.html', error=e), 404

@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"500 Internal Server Error: {request.path} - Original error: {e}", exc_info=True)
    return render_template('500.html', error=e), 500

@app.before_request
def log_request_info():
    logger.debug(f"Request: {request.method} {request.url} from {request.remote_addr}")


# --- Main Execution ---
def run_app():
    ssl_context_val = None
    if USE_HTTPS:
        if CERT_FILE and KEY_FILE and os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
            ssl_context_val = (CERT_FILE, KEY_FILE)
            logger.info(f"Starting HTTPS server on https://{DOMAIN or HOST}:{FLASK_PORT}")
        else:
            logger.error(f"USE_HTTPS is true, but cert_file ('{CERT_FILE}') or key_file ('{KEY_FILE}') is missing or invalid. Falling back to HTTP.")

    if not ssl_context_val:
        logger.info(f"Starting HTTP server on http://{HOST}:{FLASK_PORT}")

    app_debug_mode = os.environ.get("FLASK_DEBUG", "False").lower() == "true"
    logger.info(f"Flask debug mode is set to: {app_debug_mode}")
    app.run(host=HOST, port=FLASK_PORT, ssl_context=ssl_context_val, debug=app_debug_mode)

if __name__ == "__main__":
    logger.info("Application starting in development mode via __main__.")
    run_app()
