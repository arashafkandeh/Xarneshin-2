import subprocess
import os
import json
import logging
import requests # For restarting cores by re-PUTting config

# Relative imports for modules within xenon package
from ..config import XRAYC_SH_PATH, API_BASE_URL
from ..nodes.utils import get_node
from ..auth.utils import api_session
from ..xray_config.utils import get_xray_config

logger = logging.getLogger(__name__)

def get_available_xray_versions(count=20):
    if not os.path.isfile(XRAYC_SH_PATH) or not os.access(XRAYC_SH_PATH, os.X_OK):
        logger.error(f"xrayc.sh script not found or not executable at {XRAYC_SH_PATH}")
        return None, "Version fetch script not available"
    try:
        logger.debug(f"Fetching {count} Xray versions using {XRAYC_SH_PATH}")
        result = subprocess.run(
            ['sudo', XRAYC_SH_PATH, '-list', str(count)],
            capture_output=True, text=True, check=True, timeout=30
        )
        versions_raw = result.stdout.strip()
        if not versions_raw:
            logger.warning("xrayc.sh -list returned empty output.")
            return [], "No versions returned"
        if versions_raw.startswith('{"status": "error"'):
            try:
                error_json = json.loads(versions_raw)
                logger.error(f"xrayc.sh returned error: {error_json.get('message')}")
                return None, error_json.get('message', "Unknown error from script")
            except json.JSONDecodeError:
                logger.error(f"xrayc.sh returned non-JSON error string: {versions_raw}")
                return None, "Script returned an unparsable error"
        versions = versions_raw.split('\n')
        logger.info(f"Successfully fetched {len(versions)} Xray versions.")
        return versions, None
    except subprocess.CalledProcessError as e:
        logger.error(f"xrayc.sh -list failed: {e.stderr or e.stdout}")
        return None, f"Failed to execute version script: {e.stderr or e.stdout}"
    except subprocess.TimeoutExpired:
        logger.error("Timeout expired while fetching Xray versions.")
        return None, "Timeout fetching versions"
    except Exception as e:
        logger.error(f"Unexpected error fetching Xray versions: {str(e)}", exc_info=True)
        return None, f"Unexpected error: {str(e)}"

def change_xray_core_version_streamed(selected_version):
    if not os.path.isfile(XRAYC_SH_PATH) or not os.access(XRAYC_SH_PATH, os.X_OK):
        logger.error(f"xrayc.sh script not found or not executable at {XRAYC_SH_PATH}")
        yield f"data: {json.dumps({'progress': 100, 'message': 'Error: Core change script not available', 'error': True})}\n\n"
        return
    import select
    args = ['sudo', 'stdbuf', '-oL', XRAYC_SH_PATH, selected_version]
    logger.info(f"Starting Xray core change process with command: {' '.join(args)}")
    process = subprocess.Popen(
        args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1, universal_newlines=True,
        env=dict(os.environ, PYTHONUNBUFFERED="1")
    )
    yield f"data: {json.dumps({'progress': 0, 'message': 'Initializing core update...'})}\n\n"
    streams = [process.stdout, process.stderr]
    while True:
        if process.poll() is not None:
            logger.debug(f"xrayc.sh process ended with code {process.returncode}")
            break
        ready_streams, _, _ = select.select(streams, [], [], 0.2)
        for stream in ready_streams:
            line = stream.readline().strip()
            if line:
                if stream == process.stdout:
                    logger.debug(f"xrayc.sh STDOUT: {line}")
                    try:
                        data = json.loads(line)
                        yield f"data: {json.dumps(data)}\n\n"
                    except json.JSONDecodeError:
                        logger.warning(f"xrayc.sh produced non-JSON stdout: {line}")
                elif stream == process.stderr:
                    logger.error(f"xrayc.sh STDERR: {line}")
                    yield f"data: {json.dumps({'progress': 100, 'message': f'Error: {line}', 'error': True})}\n\n"
    for stream_obj in [process.stdout, process.stderr]:
        remaining_output = stream_obj.read()
        for line in remaining_output.splitlines():
            line = line.strip()
            if line:
                if stream_obj == process.stdout:
                    logger.debug(f"xrayc.sh final STDOUT: {line}")
                    try:
                        data = json.loads(line)
                        yield f"data: {json.dumps(data)}\n\n"
                    except json.JSONDecodeError:
                         logger.warning(f"xrayc.sh produced final non-JSON stdout: {line}")
                elif stream_obj == process.stderr:
                    logger.error(f"xrayc.sh final STDERR: {line}")
                    yield f"data: {json.dumps({'progress': 100, 'message': f'Error: {line}', 'error': True})}\n\n"
    process.stdout.close()
    process.stderr.close()
    logger.info("Xray core change process finished.")

def restart_node_xray_core(token, node_id):
    logger.info(f"Attempting to restart Xray core for node_id: {node_id}")
    node_data = get_node(token, node_id)
    if not node_data:
        logger.error(f"Failed to fetch node details for node {node_id}, cannot restart core.")
        return {"status": "error", "message": "Failed to fetch node details"}
    if not any(backend.get("name") == "xray" for backend in node_data.get("backends", [])):
        logger.warning(f"Xray core not found in node {node_id}. Nothing to restart.")
        return {"status": "skipped", "message": "Xray core not found in node"}

    current_xray_config_resp = get_xray_config(token, node_id)
    if not current_xray_config_resp or "config" not in current_xray_config_resp:
        logger.error(f"Failed to fetch current Xray config for node {node_id}.")
        return {"status": "error", "message": "Failed to fetch current Xray config"}
    config_json_str = current_xray_config_resp["config"]
    url = f"{API_BASE_URL}/nodes/{node_id}/xray/config"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    body = {"config": config_json_str, "format": 1}
    try:
        put_response = api_session.post(url, headers=headers, data=json.dumps(body), timeout=15) # Original used PUT
        # Correcting to use PUT as per original and typical REST for update
        put_response = api_session.put(url, headers=headers, data=json.dumps(body), timeout=15)
        put_response.raise_for_status()
        logger.info(f"Xray core for node {node_id} restarted successfully.")
        return {"status": "success"}
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error restarting Xray core for node {node_id}: {http_err} - Response: {put_response.text if 'put_response' in locals() else 'N/A'}")
        return {"status": "error", "message": f"API error (status: {put_response.status_code if 'put_response' in locals() else 'Unknown'})"}
    except Exception as e:
        logger.error(f"Unexpected error restarting Xray core for node {node_id}: {e}", exc_info=True)
        return {"status": "error", "message": f"Unexpected error: {str(e)}"}

def restart_all_nodes_xray_cores(token, all_nodes_data):
    if not all_nodes_data or "items" not in all_nodes_data:
        logger.error("No nodes data provided to restart_all_nodes_xray_cores.")
        return {}
    results = {}
    for node_item in all_nodes_data["items"]:
        node_id = node_item["id"]
        node_name = node_item.get("name", f"Node {node_id}")
        logger.info(f"Processing restart for node: {node_name} (ID: {node_id})")
        if not any(backend.get("name") == "xray" for backend in node_item.get("backends", [])):
            logger.info(f"Node {node_name} does not have an Xray backend. Skipping restart.")
            results[node_id] = {"xray": {"status": "skipped", "message": "Xray not present"}}
            continue
        restart_result = restart_node_xray_core(token, node_id)
        results[node_id] = {"xray": restart_result}
    logger.info("Finished restarting Xray cores for all applicable nodes.")
    return results

def is_local_node(token, node_id):
    node_data = get_node(token, node_id) # from ..nodes.utils
    if node_data and node_data.get("name") == "local":
        return True
    logger.debug(f"Node {node_id} is not local. Name: {node_data.get('name') if node_data else 'N/A'}")
    return False
