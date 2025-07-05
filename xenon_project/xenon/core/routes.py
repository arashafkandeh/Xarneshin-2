from flask import Blueprint, jsonify, request, session, Response, stream_with_context
import logging

# Relative imports for modules within xenon package
from ..auth.decorators import login_required
from .utils import ( # .utils for same package (core)
    get_available_xray_versions,
    change_xray_core_version_streamed,
    is_local_node,
    restart_node_xray_core,
    restart_all_nodes_xray_cores
)
from ..nodes.utils import get_nodes # ..nodes to go up to xenon then into nodes

logger = logging.getLogger(__name__)

# core_bp routes are defined with full paths or relative to node_id,
# so no url_prefix is defined here.
# Registration in app.py will determine any global prefix if necessary.
core_bp = Blueprint('core', __name__)

@core_bp.route("/get_xray_versions", methods=["GET"])
@login_required
def api_get_xray_versions():
    logger.debug("API call to get Xray versions.")
    versions, error_msg = get_available_xray_versions()
    if error_msg:
        logger.error(f"Failed to get Xray versions: {error_msg}")
        return jsonify({"error": error_msg}), 500
    if versions is None:
        return jsonify({"error": "Failed to retrieve versions for an unknown reason."}), 500

    logger.info(f"Returning {len(versions)} Xray versions.")
    return jsonify({"versions": versions})

@core_bp.route("/change_core/<int:node_id>", methods=["POST"])
@login_required
def api_change_core(node_id):
    # This route was originally /change_core/<node_id>
    # It implies the node_id is passed and checked if it's local.
    logger.info(f"API call to change Xray core for node_id: {node_id}")

    if not is_local_node(session["token"], node_id): # is_local_node is in core.utils
        logger.warning(f"Core change rejected: Node {node_id} is not the local node.")
        return jsonify({"error": "This operation is only allowed on the local node"}), 403

    data = request.get_json()
    if not data or "version" not in data or not isinstance(data["version"], str) or not data["version"].startswith("v"):
        logger.error(f"Invalid or missing version in request for core change: {data}")
        return jsonify({"error": "Valid version (e.g., v1.8.0) must be provided as a string."}), 400

    selected_version = data["version"]
    logger.info(f"Requested Xray core version change to: {selected_version} for local node {node_id}")

    return Response(
        stream_with_context(change_xray_core_version_streamed(selected_version)),
        mimetype="text/event-stream",
        headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"}
    )

@core_bp.route("/node/<int:node_id>/restart_cores", methods=["POST"])
@login_required
def api_restart_cores(node_id):
    # This route was originally /node/<node_id>/restart_cores
    logger.info(f"API call to restart cores for node_id: {node_id}")
    data = request.get_json()
    if not data or "cores" not in data:
        logger.error("Restart cores request missing 'cores' field.")
        return jsonify({"error": "No cores specified"}), 400

    cores_to_restart = data["cores"]
    # Original logic only supports 'xray'
    if not isinstance(cores_to_restart, list) or 'xray' not in cores_to_restart:
        logger.warning(f"Restart cores request for unsupported cores: {cores_to_restart}")
        return jsonify({"error": "Only 'xray' core restart is supported via this endpoint."}), 400

    result = restart_node_xray_core(session["token"], node_id) # from core.utils
    results_wrapper = {"xray": result}

    if result.get("status") == "error":
        return jsonify(results_wrapper), 500

    return jsonify(results_wrapper)


@core_bp.route("/restart_all_nodes_cores", methods=["POST"])
@login_required
def api_restart_all_nodes_cores():
    # This route was originally /restart_all_nodes_cores
    logger.info("API call to restart Xray core on all nodes.")

    all_nodes_data = get_nodes(session["token"]) # from nodes.utils
    if not all_nodes_data:
        logger.error("Failed to fetch node list for restarting all cores.")
        return jsonify({"error": "Failed to fetch nodes list"}), 500

    results = restart_all_nodes_xray_cores(session["token"], all_nodes_data) # from core.utils

    if any(result_dict.get("xray", {}).get("status") == "error" for node_id, result_dict in results.items()):
        # Consider returning 207 Multi-Status if there are partial failures
        # For now, let client parse individual statuses, return 200 if overall process ran.
        pass
    return jsonify(results)
