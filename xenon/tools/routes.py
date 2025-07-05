from flask import Blueprint, request, jsonify, session
import logging

# Relative imports
from ..auth.decorators import login_required
from .cert_utils import ( # from . for same package
    generate_self_signed_cert,
    generate_reality_keypair,
    generate_hex_short_ids
)
from .warp import generate_warp_config_external
from .network_tests import perform_full_connection_test
# For SS password, if we decide to centralize its logic:
# from ..utils import shared_generate_ss_password_logic
# Or if it stays in inbounds.py and is called from here:
from ..xray_config.inbounds import _generate_ss_password_logic as generate_ss_pass_from_inbounds


logger = logging.getLogger(__name__)

tools_bp = Blueprint('tools', __name__, url_prefix='/tools')

# --- Certificate and Key Generation Routes ---
@tools_bp.route("/generate_cert", methods=["POST"])
@login_required
def api_generate_cert():
    logger.info("API request to generate self-signed certificate.")
    cert_pem, key_pem = generate_self_signed_cert()
    if cert_pem and key_pem: return jsonify({"certificate": cert_pem, "private_key": key_pem})
    else: logger.error("Failed to generate self-signed certificate."); return jsonify({"error": "Failed to generate certificate"}), 500

@tools_bp.route("/generate_reality_keys", methods=["POST"])
@login_required
def api_generate_reality_keys():
    logger.info("API request to generate REALITY key pair.")
    private_key_b64, public_key_b64 = generate_reality_keypair()
    if private_key_b64 and public_key_b64: return jsonify({"private_key": private_key_b64, "public_key": public_key_b64})
    else: logger.error("Failed to generate REALITY key pair."); return jsonify({"error": "Failed to generate REALITY keys"}), 500

@tools_bp.route("/generate_shortids", methods=["POST"])
@login_required
def api_generate_shortids():
    logger.info("API request to generate REALITY short IDs.")
    short_ids_list = generate_hex_short_ids()
    if short_ids_list: return jsonify({"short_ids": ",".join(short_ids_list)})
    else: logger.error("Failed to generate short IDs."); return jsonify({"error": "Failed to generate short IDs"}), 500

@tools_bp.route("/generate_ss_password", methods=["POST"])
@login_required
def api_generate_ss_password():
    data = request.get_json()
    if not data or "method" not in data: logger.warning("SS Password generation request missing 'method'."); return jsonify({"error": "Encryption method not provided."}), 400
    method_str = data.get("method", "none")
    logger.info(f"API request to generate SS password for method: {method_str}")
    # Using the imported logic from inbounds.py for now
    password = generate_ss_pass_from_inbounds(method_str)
    return jsonify({"password": password})

# --- Warp Configuration Generation ---
@tools_bp.route("/generate_warp", methods=["GET", "POST"])
@login_required
def api_generate_warp_config():
    logger.info("API request to generate Warp configuration.")
    warp_config_dict, error_msg = generate_warp_config_external() # from .warp
    if error_msg: logger.error(f"Failed to generate Warp config: {error_msg}"); return jsonify({"error": error_msg}), 500
    if warp_config_dict: return jsonify(warp_config_dict)
    else: logger.error("Warp config generation returned None without specific error message."); return jsonify({"error": "Failed to generate Warp configuration for an unknown reason."}), 500

# --- Network Connection Test Route ---
@tools_bp.route("/test_full_connection", methods=["POST"])
@login_required
def api_test_full_connection():
    logger.info("API request for full connection test.")
    data = request.get_json()
    if not data: logger.warning("Test full connection request with no data."); return jsonify({"success": False, "message": "No data provided."}), 400

    results = perform_full_connection_test( # from .network_tests
        ssh_ip=data.get("ssh_ip"), ssh_port_str=data.get("ssh_port"), ssh_user=data.get("ssh_user"), ssh_pass=data.get("ssh_pass"),
        use_proxy=data.get("use_proxy", False), proxy_ip=data.get("proxy_ip"), proxy_port_str=data.get("proxy_port"),
        proxy_user=data.get("proxy_user"), proxy_pass=data.get("proxy_pass")
    )
    # Consider appropriate HTTP status based on results, e.g., 400 if input validation inside perform_full_connection_test fails.
    # For now, returning 200 and detailed JSON.
    return jsonify(results), 200
