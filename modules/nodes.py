import sys
import logging
logger = logging.getLogger(__name__)
import json
import time
import os
import subprocess
import select
import socket
import base64
import requests
import paramiko
import socks
import sentry_sdk
from flask import (
    Blueprint, request, render_template, session, redirect, url_for,
    jsonify, flash, Response, stream_with_context
)
from . import database

# Define a Blueprint for node management
nodes_bp = Blueprint('nodes', __name__)

database.init_db()

###############################################################################
#                   LOAD DYNAMIC CONFIG FROM ports.json                       #
###############################################################################

CONFIG_FILE = "/opt/Xenon.xray/ports.json"

def get_config():
    """Reads and returns configuration from the JSON file."""
    logger.debug(f"Attempting to read configuration from {CONFIG_FILE}")
    try:
        with open(CONFIG_FILE, "r") as f:
            data = json.load(f)
            config_data = {
                "panel_port": data.get("panel_port", 8000),
                "panel_use_https": data.get("panel_use_https", False),
            }
            logger.info(f"Configuration loaded successfully: {config_data}")
            return config_data
    except FileNotFoundError:
        logger.error(f"Configuration file not found at {CONFIG_FILE}. Using default values.")
        return {"panel_port": 8000, "panel_use_https": False}
    except json.JSONDecodeError:
        logger.error(f"Error decoding JSON from {CONFIG_FILE}. Using default values.")
        return {"panel_port": 8000, "panel_use_https": False}
    except Exception as e:
        logger.error(f"An unexpected error occurred while reading config: {e}")
        sentry_sdk.capture_exception(e)
        return {"panel_port": 8000, "panel_use_https": False}


config = get_config()
PANEL_PORT = config["panel_port"]
PANEL_USE_HTTPS = config["panel_use_https"]

###############################################################################
#                           GLOBAL REQUESTS SESSION                           #
###############################################################################
api_session = requests.Session()
API_BASE_URL = f"{'https' if PANEL_USE_HTTPS else 'http'}://127.0.0.1:{PANEL_PORT}/api"
api_session.verify = not PANEL_USE_HTTPS
logger.info(f"API Base URL configured to: {API_BASE_URL}")

###############################################################################
#                              API BRIDGE FUNCTIONS                           #
###############################################################################
def get_nodes(token):
    """Fetches all nodes from the Marzban API."""
    url = f"{API_BASE_URL}/nodes?page=1&size=100&descending=true&order_by=created_at"
    headers = {"Authorization": f"Bearer {token}"}
    logger.info("Attempting to fetch all nodes from API.")
    try:
        r = api_session.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            logger.info("Successfully fetched nodes from API.")
            return r.json()
        else:
            logger.error(f"Failed to fetch nodes. Status: {r.status_code}, Response: {r.text}")
            return None
    except requests.RequestException as e:
        logger.error(f"Exception while fetching nodes from API: {e}")
        sentry_sdk.capture_exception(e)
        return None

def get_node(token, node_id):
    """Retrieves a single node's details from the API."""
    url = f"{API_BASE_URL}/nodes/{node_id}"
    headers = {"Authorization": f"Bearer {token}"}
    logger.info(f"Attempting to fetch details for node ID: {node_id}")
    try:
        r = api_session.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            logger.info(f"Successfully fetched details for node ID: {node_id}")
            return r.json()
        else:
            logger.error(f"Failed to fetch node ID {node_id}. Status: {r.status_code}, Response: {r.text}")
            return None
    except requests.RequestException as e:
        logger.error(f"Exception while fetching node ID {node_id}: {e}")
        sentry_sdk.capture_exception(e)
        return None

def create_node_api(token, node_payload):
    """Creates a new node in the Marzban panel via the API."""
    url = f"{API_BASE_URL}/nodes"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    node_name = node_payload.get('name', 'N/A')
    logger.info(f"Attempting to create node '{node_name}' via API.")
    try:
        r = api_session.post(url, headers=headers, json=node_payload, timeout=15)
        
        if r.status_code in [200, 201]:
            logger.info(f"Successfully created node '{node_name}' via API. Status: {r.status_code}")
            return r.json()
        else:
            logger.error(f"Failed to create node '{node_name}' via API. Status: {r.status_code}, Response: {r.text}")
            try:
                if r.status_code == 409:
                    error_detail = r.json().get('detail', 'Conflict: Resource already exists.')
                    return {"error": error_detail, "status_code": 409}
                
                error_detail = r.json().get('detail', r.text)
                return {"error": error_detail}
            except json.JSONDecodeError:
                return {"error": r.text}
    except requests.RequestException as e:
        logger.error(f"Exception while creating node '{node_name}' via API: {e}")
        sentry_sdk.capture_exception(e)
        return None

def update_node_api(token, node_id, node_payload):
    """Updates an existing node in the Marzban panel via the API."""
    url = f"{API_BASE_URL}/nodes/{node_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    logger.info(f"Attempting to update node ID {node_id} via API.")
    try:
        # The Marzban API expects the full node object for updates
        r = api_session.put(url, headers=headers, json=node_payload, timeout=15)
        
        if r.status_code == 200:
            logger.info(f"Successfully updated node ID {node_id} via API.")
            return r.json()
        else:
            logger.error(f"Failed to update node ID {node_id} via API. Status: {r.status_code}, Response: {r.text}")
            try:
                error_detail = r.json().get('detail', r.text)
                return {"error": error_detail}
            except json.JSONDecodeError:
                return {"error": r.text}
    except requests.RequestException as e:
        logger.error(f"Exception while updating node ID {node_id} via API: {e}")
        sentry_sdk.capture_exception(e)
        return None

###############################################################################
#                               ROUTES & LOGIC                                #
###############################################################################

@nodes_bp.route("/nodes")
def show_nodes():
    """Displays the list of nodes."""
    logger.debug("Request received for /nodes page.")
    if "token" not in session:
        logger.warning("Access to /nodes denied. No token in session.")
        return redirect("/")
    
    nodes = get_nodes(session["token"])
    if not nodes:
        flash("Failed to fetch nodes from the panel.")
        logger.error("Failed to fetch nodes for display, redirecting.")
        return redirect("/")
    
    logger.info("Rendering nodes page.")
    return render_template("nodes.html", nodes=nodes)

# ### START: MODIFIED add_node_to_panel ROUTE ###
@nodes_bp.route("/add_node_to_panel", methods=["POST"])
def add_node_to_panel():
    """Adds a pre-configured node directly to the Marzban panel."""
    logger.debug("Request received to add a node to the panel.")
    if "token" not in session:
        logger.warning("Unauthorized attempt to add node to panel.")
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json()
    if not data or not all(k in data for k in ["name", "address", "port"]):
        logger.error(f"Missing required details in add_node_to_panel request. Data: {data}")
        return jsonify({"success": False, "message": "Missing node details"}), 400

    node_name = data.get("name")
    server_ip = data.get("address")
    node_xray_port_str = data.get("port")
    force_new = data.get("force_new", False)
    
    if not node_xray_port_str:
        logger.error("Node Xray Port is missing in request.")
        return jsonify({"success": False, "message": "Node Xray Port is required."}), 400

    try:
        node_api_port = int(node_xray_port_str)
    except (ValueError, TypeError):
        logger.error(f"Invalid Node Xray Port provided: {node_xray_port_str}")
        return jsonify({"success": False, "message": f"Invalid Node Xray Port: {node_xray_port_str}"}), 400

    try:
        all_nodes_data = get_nodes(session["token"])
        if not all_nodes_data:
            logger.error("Could not fetch existing nodes to check for duplicates.")
            return jsonify({"success": False, "message": "Could not fetch existing nodes from the panel."}), 500
        
        existing_nodes = all_nodes_data.get('items', [])
        existing_node = next((node for node in existing_nodes if node['name'] == node_name), None)

        if existing_node and not force_new:
            conflict_message = f"A node named '{node_name}' already exists."
            logger.warning(conflict_message)
            return jsonify({
                "success": False,
                "conflict": True,
                "message": conflict_message,
                "existing_node": { "id": existing_node['id'], "name": existing_node['name'] }
            }), 409

        final_node_name = node_name
        if existing_node and force_new:
            logger.info(f"Node '{node_name}' exists, finding a new unique name as force_new is true.")
            counter = 2
            existing_names = {node['name'] for node in existing_nodes}
            while True:
                new_name = f"{node_name} {counter}"
                if new_name not in existing_names:
                    final_node_name = new_name
                    logger.info(f"Found unique name: '{final_node_name}'")
                    break
                counter += 1
        
        node_payload = {
            "name": final_node_name,
            "address": server_ip,
            "port": node_api_port,
            "status": "connected",
            "api_port": node_api_port,
            "usage_coefficient": 1.0,
            "add_as_new_server": True
        }

        logger.info(f"Attempting to add node '{final_node_name}' to panel via API.")
        api_response = create_node_api(session["token"], node_payload)

        if api_response and "error" not in api_response:
            final_msg = f"Node '{final_node_name}' successfully added to the Marzban panel."
            logger.info(final_msg)
            return jsonify({"success": True, "message": final_msg})
        else:
            api_error_msg = api_response.get("error", "An unknown API error occurred.") if api_response else "API call failed."
            final_error_msg = f"Failed to add node '{final_node_name}' to the panel. API Error: {api_error_msg}"
            logger.error(final_error_msg)
            return jsonify({"success": False, "message": final_error_msg}), 500

    except Exception as e:
        import traceback
        logger.error(f"Unexpected error while adding node to panel: {str(e)}\n{traceback.format_exc()}")
        sentry_sdk.capture_exception(e)
        return jsonify({"success": False, "message": f"An unexpected server error occurred: {str(e)}"}), 500
# ### END: MODIFIED add_node_to_panel ROUTE ###


# ### START: NEW ROUTE FOR UPDATING ###
@nodes_bp.route("/update_existing_node", methods=["POST"])
def update_existing_node():
    """Updates an existing node in the panel with new IP and Port."""
    logger.debug("Request received to update an existing node.")
    if "token" not in session:
        logger.warning("Unauthorized attempt to update a node.")
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json()
    if not data or not all(k in data for k in ["id", "address", "port"]):
        logger.error(f"Missing required details in update_existing_node request. Data: {data}")
        return jsonify({"success": False, "message": "Missing node update details"}), 400

    node_id = data.get("id")
    new_address = data.get("address")
    new_port_str = data.get("port")

    try:
        new_port = int(new_port_str)
    except (ValueError, TypeError):
        logger.error(f"Invalid port format for node update: {new_port_str}")
        return jsonify({"success": False, "message": f"Invalid port format: {new_port_str}"}), 400

    try:
        logger.info(f"Fetching full details for node ID {node_id} before updating.")
        node_data = get_node(session["token"], node_id)
        if not node_data or "error" in node_data:
            logger.error(f"Could not find node with ID {node_id} to update.")
            return jsonify({"success": False, "message": f"Could not find existing node with ID {node_id}."}), 404

        # Update the necessary fields
        node_data['address'] = new_address
        node_data['port'] = new_port
        node_data['api_port'] = new_port
        
        # Now, send the full updated object back to the API
        api_response = update_node_api(session["token"], node_id, node_data)
        
        if api_response and "error" not in api_response:
            success_msg = f"Node '{node_data['name']}' (ID: {node_id}) has been updated successfully."
            logger.info(success_msg)
            return jsonify({"success": True, "message": success_msg})
        else:
            api_error_msg = api_response.get("error", "An unknown API error occurred.") if api_response else "API call failed."
            error_msg = f"Failed to update node {node_id}. API Error: {api_error_msg}"
            logger.error(error_msg)
            return jsonify({"success": False, "message": error_msg}), 500

    except Exception as e:
        import traceback
        logger.error(f"Unexpected error while updating node {node_id}: {str(e)}\n{traceback.format_exc()}")
        sentry_sdk.capture_exception(e)
        return jsonify({"success": False, "message": f"An unexpected server error occurred: {str(e)}"}), 500
# ### END: NEW ROUTE FOR UPDATING ###


#################### core v changer ####################
@nodes_bp.route("/get_xray_versions", methods=["GET"])
def get_xray_versions():
    """Fetches the latest 20 stable Xray versions using a shell script."""
    logger.debug("Request received to get Xray versions.")
    if "token" not in session:
        logger.warning("Unauthorized attempt to get Xray versions.")
        return jsonify({"error": "Unauthorized"}), 401

    script_path = "/opt/Xenon.xray/assets/xrayc.sh"
    if not os.path.isfile(script_path) or not os.access(script_path, os.X_OK):
        logger.error(f"Xray version script not found or not executable at {script_path}")
        return jsonify({"error": "Version fetch script not available"}), 500

    try:
        logger.info("Executing xrayc.sh to fetch versions.")
        result = subprocess.run(
            ['sudo', script_path, '-list', '20'],
            capture_output=True,
            text=True,
            check=True,
            timeout=30
        )
        versions = result.stdout.strip().split('\n')
        if not versions or versions[0].startswith('{"status": "error"'):
            logger.error(f"Script returned an error when fetching versions: {versions[0] if versions else 'No output'}")
            error_json = json.loads(versions[0])
            return jsonify({"error": error_json["message"]}), 500
        
        logger.info(f"Successfully fetched {len(versions)} Xray versions.")
        return jsonify({"versions": versions})
    except subprocess.CalledProcessError as e:
        logger.error(f"Subprocess failed while fetching Xray versions: {e.stderr}")
        return jsonify({"error": f"Failed to fetch versions: {e.stderr}"}), 500
    except Exception as e:
        logger.error(f"Unexpected error fetching Xray versions: {str(e)}")
        sentry_sdk.capture_exception(e)
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500

@nodes_bp.route("/change_core/<int:node_id>", methods=["POST"])
def change_core(node_id):
    """Changes the Xray core version for the local node."""
    logger.debug(f"Starting change_core for node_id: {node_id}")
    if "token" not in session:
        logger.warning(f"Unauthorized attempt to change core for node {node_id}.")
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    if not data or "version" not in data or not isinstance(data["version"], str):
        logger.error(f"Invalid or missing version in change_core request. Data: {data}")
        return jsonify({"error": "Version must be a non-empty string"}), 400

    selected_version = data["version"]
    token = session["token"]
    logger.info(f"Request to change core for node {node_id} to version {selected_version}.")

    node_data = get_node(token, node_id)
    if not node_data or node_data.get("name") != "local":
        logger.error(f"Invalid node or not local for core change. Node data: {node_data}")
        return jsonify({"error": "This operation is only allowed on the local node"}), 403

    script_path = "/opt/Xenon.xray/assets/xrayc.sh"
    logger.debug(f"Using script path: {script_path}")

    if not os.path.isfile(script_path) or not os.access(script_path, os.X_OK):
        logger.error(f"Core change script not found or not executable at {script_path}")
        return Response(
            f"data: {{\"progress\": 100, \"message\": \"Error: Script not found or not executable at {script_path}\", \"error\": true}}\n\n",
            mimetype="text/event-stream"
        )

    def generate():
        args = ['sudo', 'stdbuf', '-oL', script_path, selected_version]
        logger.debug(f"Executing change_core subprocess with args: {args}")
        process = None
        try:
            process = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True,
                env={"PYTHONUNBUFFERED": "1", "PATH": os.environ["PATH"]}
            )
            logger.debug(f"Subprocess for core change started with PID: {process.pid}")

            yield "data: {\"progress\": 0, \"message\": \"Initializing core change...\"}\n\n"

            while process.poll() is None:
                ready, _, _ = select.select([process.stdout, process.stderr], [], [], 0.1)
                for s in ready:
                    line = s.readline().strip()
                    if line:
                        if s == process.stdout:
                            logger.debug(f"Realtime STDOUT from xrayc.sh: {line}")
                            try:
                                data = json.loads(line)
                                yield f"data: {json.dumps(data)}\n\n"
                            except json.JSONDecodeError:
                                logger.warning(f"Ignoring non-JSON stdout from script: {line}")
                        else: # s == process.stderr
                            logger.error(f"Realtime STDERR from xrayc.sh: {line}")
                            yield f"data: {json.dumps({'progress': 100, 'message': f'Error: {line}', 'error': True})}\n\n"
            
            # Read any remaining output
            for line in process.stdout.read().splitlines():
                if line:
                    logger.debug(f"Final STDOUT from xrayc.sh: {line}")
                    try:
                        data = json.loads(line)
                        yield f"data: {json.dumps(data)}\n\n"
                    except json.JSONDecodeError:
                        logger.warning(f"Ignoring final non-JSON stdout: {line}")

            for line in process.stderr.read().splitlines():
                 if line:
                    logger.error(f"Final STDERR from xrayc.sh: {line}")
                    yield f"data: {json.dumps({'progress': 100, 'message': f'Error: {line}', 'error': True})}\n\n"

            logger.info(f"Core change script finished with exit code: {process.returncode}")

        except Exception as e:
            logger.error(f"Exception during core change stream generation: {e}")
            sentry_sdk.capture_exception(e)
            yield f"data: {json.dumps({'progress': 100, 'message': f'An unexpected error occurred: {e}', 'error': True})}\n\n"
        finally:
            if process:
                if process.stdout: process.stdout.close()
                if process.stderr: process.stderr.close()

    return Response(stream_with_context(generate()), mimetype="text/event-stream", headers={"X-Accel-Buffering": "no"})

####################### Restart core section #######################
@nodes_bp.route("/node/<int:node_id>/restart_cores", methods=["POST"])
def restart_cores(node_id):
    """Restarts the Xray core for a specific node by re-applying its config."""
    logger.info(f"Request received to restart xray core for node ID: {node_id}")
    if "token" not in session:
        logger.warning(f"Unauthorized attempt to restart core for node {node_id}.")
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    if not data or "cores" not in data:
        logger.error("Restart cores request is missing 'cores' field.")
        return jsonify({"error": "No cores specified"}), 400

    cores = data["cores"]
    if not isinstance(cores, list) or 'xray' not in cores:
        logger.error(f"Invalid cores specified for restart: {cores}. Only 'xray' is supported.")
        return jsonify({"error": "Only 'xray' core restart is supported"}), 400

    token = session["token"]
    results = {}

    node_data = get_node(token, node_id)
    if not node_data or "backends" not in node_data:
        logger.error(f"Failed to fetch details for node {node_id} to restart core.")
        return jsonify({"error": "Failed to fetch node details"}), 500
    
    if not any(backend["name"] == "xray" for backend in node_data["backends"]):
        results["xray"] = {"status": "error", "message": "Xray core not found in node"}
        logger.warning(f"Attempted to restart xray on node {node_id}, but it has no xray backend.")
        return jsonify(results)

    url = f"{API_BASE_URL}/nodes/{node_id}/xray/config"
    headers = {"Authorization": f"Bearer {token}"}

    try:
        logger.debug(f"Fetching xray config for node {node_id}.")
        response = api_session.get(url, headers=headers)
        if response.status_code != 200:
            msg = f"Failed to fetch config for node {node_id} (status: {response.status_code})"
            results["xray"] = {"status": "error", "message": msg}
            logger.error(msg)
            return jsonify(results)
    except requests.RequestException as e:
        msg = f"Error fetching config for node {node_id}: {str(e)}"
        results["xray"] = {"status": "error", "message": msg}
        logger.error(msg)
        sentry_sdk.capture_exception(e)
        return jsonify(results)

    config_data = response.json()
    if "config" not in config_data:
        msg = f"Config not found in API response for node {node_id}."
        results["xray"] = {"status": "error", "message": msg}
        logger.error(msg)
        return jsonify(results)

    try:
        logger.info(f"Re-applying config to restart xray core for node {node_id}.")
        put_response = api_session.put(
            url,
            headers=headers,
            json={"config": config_data["config"], "format": 1}
        )
        if put_response.status_code == 200:
            results["xray"] = {"status": "success"}
            logger.info(f"Successfully restarted xray core for node {node_id}.")
        else:
            msg = f"Failed to update config for node {node_id} (status: {put_response.status_code})"
            results["xray"] = {"status": "error", "message": msg}
            logger.error(msg)
    except requests.RequestException as e:
        msg = f"Error updating config for node {node_id}: {str(e)}"
        results["xray"] = {"status": "error", "message": msg}
        logger.error(msg)
        sentry_sdk.capture_exception(e)

    return jsonify(results)

@nodes_bp.route("/restart_all_nodes_cores", methods=["POST"])
def restart_all_nodes_cores():
    """Restarts the Xray core for all nodes in the panel."""
    logger.info("Request received to restart xray cores for ALL nodes.")
    if "token" not in session:
        logger.warning("Unauthorized attempt to restart all cores.")
        return jsonify({"error": "Unauthorized"}), 401

    token = session["token"]
    nodes_data = get_nodes(token)
    if not nodes_data or "items" not in nodes_data:
        logger.error("Failed to fetch node list for restarting all cores.")
        return jsonify({"error": "Failed to fetch nodes"}), 500

    results = {}
    logger.info(f"Found {len(nodes_data['items'])} nodes. Iterating to restart xray cores.")
    for node in nodes_data["items"]:
        node_id = node["id"]
        node_name = node["name"]
        node_results = {}
        logger.debug(f"Processing node '{node_name}' (ID: {node_id}).")
        if any(backend["name"] == "xray" for backend in node["backends"]):
            url = f"{API_BASE_URL}/nodes/{node_id}/xray/config"
            headers = {"Authorization": f"Bearer {token}"}
            try:
                response = api_session.get(url, headers=headers)
                if response.status_code != 200:
                    node_results["xray"] = {"status": "error", "message": f"Fetch failed (status: {response.status_code})"}
                else:
                    config_data = response.json()
                    if "config" not in config_data:
                        node_results["xray"] = {"status": "error", "message": "Config not found"}
                    else:
                        put_response = api_session.put(url, headers=headers, json={"config": config_data["config"], "format": 1})
                        if put_response.status_code == 200:
                            node_results["xray"] = {"status": "success"}
                            logger.info(f"Successfully restarted xray for node '{node_name}'.")
                        else:
                            node_results["xray"] = {"status": "error", "message": f"Update failed (status: {put_response.status_code})"}
            except requests.RequestException as e:
                node_results["xray"] = {"status": "error", "message": f"Error: {str(e)}"}
                sentry_sdk.capture_exception(e)
        else:
            node_results["xray"] = {"status": "skipped", "message": "Xray not present"}
            logger.debug(f"Skipping node '{node_name}' as it has no xray backend.")
        results[node_id] = node_results

    logger.info("Finished restarting all node cores.")
    return jsonify(results)

###############################################################################
#                         TEST PROXY & SSH CONNECTION                         #
###############################################################################
@nodes_bp.route("/test_full_connection", methods=["POST"])
def test_full_connection():
    """Tests Proxy and SSH connections based on user input or stored credentials."""
    logger.info("Request received to test full connection (Proxy/SSH).")
    if "token" not in session:
        logger.warning("Unauthorized attempt to test connection.")
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json()
    if not data:
        logger.error("Test connection request received with no data.")
        return jsonify({"success": False, "message": "No data provided."}), 400

    results = {
        "proxy_status": "not_attempted", "proxy_message": "Proxy not used or not tested.", "proxy_seen_ip": None,
        "ssh_status": "not_attempted", "ssh_message": "SSH connection not attempted."
    }

    use_custom_ssh = data.get("use_custom_ssh", False)
    ssh_creds = {}

    if use_custom_ssh:
        logger.info("Using custom SSH credentials from user input for test.")
        ssh_creds['ip'] = data.get("ssh_ip")
        ssh_creds['port_str'] = data.get("ssh_port")
        ssh_creds['user'] = data.get("ssh_user")
        ssh_creds['pass'] = data.get("ssh_pass")
        if not all(ssh_creds.values()):
            results["ssh_message"] = "Custom SSH IP, Port, User, and Password are required."
            results["ssh_status"] = "failed_input"
            logger.error("Missing custom SSH credentials.")
            return jsonify(results), 400
    else:
        logger.info("Using stored SSH credentials from database for test.")
        node_id = data.get("node_id")
        if not node_id:
            results["ssh_message"] = "Node ID is required for testing with stored credentials."
            results["ssh_status"] = "failed_input"
            logger.error("Node ID missing for stored credential test.")
            return jsonify(results), 400
        
        node_api_data = get_node(session["token"], node_id)
        if not node_api_data:
            results["ssh_message"] = f"Node with ID {node_id} not found."
            results["ssh_status"] = "failed_input"
            logger.error(f"Node not found in panel for ID {node_id}.")
            return jsonify(results), 404
            
        node_name = node_api_data.get("name")
        node_db_data = database.get_installed_node_by_name(node_name)
        if not node_db_data:
            results["ssh_message"] = f"SSH details not found in local DB for node '{node_name}'."
            results["ssh_status"] = "failed_input"
            logger.error(f"Node details for '{node_name}' not found in local DB.")
            return jsonify(results), 404
        
        ssh_creds['ip'] = node_db_data.get('server_ip')
        ssh_creds['port_str'] = str(node_db_data.get('ssh_port'))
        ssh_creds['user'] = node_db_data.get('ssh_user')
        ssh_creds['pass'] = node_db_data.get('ssh_password')
        if not all(ssh_creds.values()):
            results["ssh_message"] = f"Incomplete SSH credentials found in local DB for '{node_name}'."
            results["ssh_status"] = "failed_input"
            logger.error(f"Incomplete credentials for '{node_name}' in DB.")
            return jsonify(results), 400
    
    ssh_ip = ssh_creds['ip']
    ssh_port_str = ssh_creds['port_str']
    ssh_user = ssh_creds['user']
    ssh_pass = ssh_creds['pass']

    use_proxy = data.get("use_proxy", False)
    proxy_ip = data.get("proxy_ip")
    proxy_port_str = data.get("proxy_port")
    proxy_user = data.get("proxy_user")
    proxy_pass = data.get("proxy_pass")

    try:
        ssh_port = int(ssh_port_str)
        if not (1 <= ssh_port <= 65535): raise ValueError("Invalid SSH port")
    except (ValueError, TypeError):
        results["ssh_message"] = "Invalid SSH Port."
        results["ssh_status"] = "failed_input"
        logger.error(f"Invalid SSH port in input: {ssh_port_str}")
        return jsonify(results), 400

    if use_proxy:
        if not proxy_ip or not proxy_port_str:
            results["proxy_status"] = "failed_input"
            results["proxy_message"] = "Proxy IP and Port are required when 'Use Proxy' is enabled."
            results["ssh_status"] = "not_attempted"
            results["ssh_message"] = "SSH test skipped due to proxy input error."
            logger.error("Proxy enabled but IP/Port are missing.")
            return jsonify(results), 400
        try:
            proxy_port_int = int(proxy_port_str)
            if not (1 <= proxy_port_int <= 65535): raise ValueError("Invalid proxy port")
        except (ValueError, TypeError):
            results["proxy_status"] = "failed_input"
            results["proxy_message"] = "Invalid Proxy Port."
            results["ssh_status"] = "not_attempted"
            results["ssh_message"] = "SSH test skipped due to proxy input error."
            logger.error(f"Invalid Proxy port in input: {proxy_port_str}")
            return jsonify(results), 400

        proxy_url_display = f"socks5://{proxy_ip}:{proxy_port_int}"
        proxies_for_requests = { "http": f"socks5h://{proxy_ip}:{proxy_port_int}", "https": f"socks5h://{proxy_ip}:{proxy_port_int}" }
        if proxy_user:
            auth_str = f"{requests.utils.quote(proxy_user)}"
            if proxy_pass:
                auth_str += f":{requests.utils.quote(proxy_pass)}"
            proxies_for_requests["http"] = f"socks5h://{auth_str}@{proxy_ip}:{proxy_port_int}"
            proxies_for_requests["httpss"] = f"socks5h://{auth_str}@{proxy_ip}:{proxy_port_int}"
            proxy_url_display = f"socks5://{proxy_user}:***@{proxy_ip}:{proxy_port_int}"

        logger.info(f"Testing proxy connection: {proxy_url_display}")
        try:
            response = requests.get("http://httpbin.org/ip", proxies=proxies_for_requests, timeout=10)
            response.raise_for_status()
            r_json = response.json()
            results["proxy_seen_ip"] = r_json.get("origin")
            results["proxy_status"] = "success"
            results["proxy_message"] = f"Proxy OK. IP via proxy: {results['proxy_seen_ip']}"
            logger.info(f"Proxy test successful. IP seen: {results['proxy_seen_ip']}")
        except Exception as e:
            logger.error(f"Proxy test failed: {str(e)}")
            results["proxy_status"] = "failed"
            results["proxy_message"] = f"Proxy Error: {str(e)}"
            results["ssh_status"] = "not_attempted"
            results["ssh_message"] = "SSH test skipped due to proxy failure."
            return jsonify(results)

    logger.info(f"Attempting SSH test to {ssh_user}@{ssh_ip}:{ssh_port} {'via proxy' if use_proxy else ''}")

    ssh_client_test = paramiko.SSHClient()
    ssh_client_test.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    temp_sock_for_paramiko = None

    if use_proxy and results['proxy_status'] == 'success':
        try:
            temp_sock_for_paramiko = socks.socksocket()
            temp_sock_for_paramiko.set_proxy(proxy_type=socks.SOCKS5, addr=proxy_ip, port=proxy_port_int, username=proxy_user or None, password=proxy_pass or None)
            temp_sock_for_paramiko.settimeout(10)
            temp_sock_for_paramiko.connect((ssh_ip, ssh_port))
        except Exception as e:
            msg = f"Error connecting proxy socket to SSH host: {str(e)}"
            results["ssh_status"] = "failed_proxy_setup"
            results["ssh_message"] = msg
            logger.error(msg)
            if temp_sock_for_paramiko: temp_sock_for_paramiko.close()
            return jsonify(results)

    try:
        ssh_client_test.connect(
            hostname=ssh_ip, port=ssh_port, username=ssh_user, password=ssh_pass,
            sock=temp_sock_for_paramiko, timeout=10, banner_timeout=15, auth_timeout=15
        )
        results["ssh_status"] = "success"
        results["ssh_message"] = "SSH connection successful (authentication OK)."
        logger.info(f"SSH test to {ssh_ip}:{ssh_port} was successful.")
    except paramiko.AuthenticationException:
        results["ssh_status"] = "failed_auth"; results["ssh_message"] = "SSH Authentication failed."
        logger.warning(f"SSH authentication failed for {ssh_user}@{ssh_ip}:{ssh_port}")
    except paramiko.SSHException as e:
        results["ssh_status"] = "failed_other"; results["ssh_message"] = f"SSH Error: {str(e)}"
        logger.error(f"SSH protocol error for {ssh_ip}:{ssh_port}: {e}")
    except socket.timeout:
        results["ssh_status"] = "failed_timeout"; results["ssh_message"] = "SSH Connection timed out."
        logger.error(f"SSH connection to {ssh_ip}:{ssh_port} timed out.")
    except Exception as e:
        results["ssh_status"] = "failed_unexpected"; results["ssh_message"] = f"Unexpected SSH error: {str(e)}"
        logger.error(f"Unexpected SSH error for {ssh_ip}:{ssh_port}: {e}")
        sentry_sdk.capture_exception(e)
    finally:
        if ssh_client_test: ssh_client_test.close()
        # The socket is closed by paramiko if passed in `sock`, no need to close again.

    return jsonify(results)

###############################################################################
#                              ADD NODE VIA SSH                               #
###############################################################################
@nodes_bp.route("/add_node_ssh", methods=["POST"])
def add_node_ssh():
    """Handles the multi-step process of adding a node via SSH installation script."""
    logger.info("Request received to add a new node via SSH.")
    if "token" not in session:
        logger.warning("Unauthorized attempt to add node via SSH.")
        return jsonify({"success": False, "message": "Unauthorized access. Please login again."}), 401

    data = request.get_json()
    if not data:
        logger.error("Add node via SSH request received with no data.")
        return jsonify({"success": False, "message": "No data provided."}), 400

    node_name = data.get("nodeName")
    server_ip = data.get("serverIP")
    ssh_user = data.get("sshUser")
    ssh_password = data.get("sshPassword")
    ssh_port_str = data.get("sshPort")
    node_xray_port_str = data.get("nodeXrayPort")
    selected_xray_version = data.get("selectedXrayVersion")
    node_certificate_b64 = data.get("nodeCertificate")

    use_proxy = data.get("useProxy", False)
    proxy_ip = data.get("proxyIP")
    proxy_port_str = data.get("proxyPort")
    proxy_user = data.get("proxyUser")
    proxy_password = data.get("proxyPassword")
    
    required_fields = {
        "Node Name": node_name, "Server IP": server_ip,
        "SSH Username": ssh_user, "SSH Password": ssh_password, "SSH Port": ssh_port_str,
        "Node Certificate": node_certificate_b64, "Xray Version": selected_xray_version
    }

    missing_fields = [name for name, value in required_fields.items() if not value]
    if missing_fields:
        msg = f"Missing required fields: {', '.join(missing_fields)}."
        logger.error(f"Add node SSH failed. {msg}")
        return jsonify({"success": False, "message": msg}), 400

    try:
        ssh_port = int(ssh_port_str)
        if not (1 <= ssh_port <= 65535): raise ValueError("Invalid SSH port range")
    except (ValueError, TypeError):
        logger.error(f"Invalid SSH port provided: {ssh_port_str}")
        return jsonify({"success": False, "message": "Invalid SSH port. Must be 1-65535."}), 400

    logger.info(f"Starting setup for node '{node_name}' on {server_ip}:{ssh_port}")
    logger.info(f"  - SSH User: {ssh_user}, Xray Version: {selected_xray_version}, Use Proxy: {use_proxy}")

    local_script_path = "/opt/Xenon.xray/assets/setup_node.sh"
    remote_script_path = "/root/setup_node.sh"

    if not os.path.exists(local_script_path):
        error_msg = f"Source setup script file not found at {local_script_path}."
        logger.critical(error_msg)
        sentry_sdk.capture_message(error_msg, level='fatal')
        return jsonify({"success": False, "message": error_msg}), 500

    # This context is established before the stream starts.
    # The actual connection logic is now inside generate_output.
    def generate_output():
        ssh_client = None
        sftp_client = None
        proxy_sock_for_ssh = None
        try:
            logger.debug("Stream generator started. Establishing SSH connection...")
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            if use_proxy:
                if not proxy_ip or not proxy_port_str:
                    raise ValueError("Proxy IP and Port are required when 'Use Proxy' is enabled.")
                proxy_port_int = int(proxy_port_str)
                if not (1 <= proxy_port_int <= 65535): raise ValueError("Invalid proxy port range")

                logger.info(f"Setting up SOCKS proxy for SSH via {proxy_ip}:{proxy_port_int}")
                proxy_sock_for_ssh = socks.socksocket()
                proxy_sock_for_ssh.set_proxy(
                    socks.SOCKS5, proxy_ip, proxy_port_int,
                    username=proxy_user or None,
                    password=proxy_password or None
                )
                proxy_sock_for_ssh.settimeout(20)
                proxy_sock_for_ssh.connect((server_ip, ssh_port))

            ssh_client.connect(
                hostname=server_ip, port=ssh_port, username=ssh_user, password=ssh_password,
                sock=proxy_sock_for_ssh,
                timeout=20, banner_timeout=20, auth_timeout=20
            )
            logger.info(f"SSH connection established to {server_ip} {'via proxy' if use_proxy else ''}")
            yield f"data: {json.dumps({'line': 'SSH connection successful.'})}\n\n"
            
            # Upload and prepare script
            logger.info(f"Uploading script to '{remote_script_path}'")
            sftp_client = ssh_client.open_sftp()
            sftp_client.put(local_script_path, remote_script_path)
            sftp_client.close()
            logger.info("Script uploaded. Setting permissions...")
            ssh_client.exec_command(f"chmod +x {remote_script_path}")
            ssh_client.exec_command(f"sed -i 's/\\r$//' {remote_script_path}") # Ensure unix line endings
            yield f"data: {json.dumps({'line': 'Setup script uploaded and prepared.'})}\n\n"
            
            # Construct and execute command
            proxy_address_arg = ""
            if use_proxy:
                auth_part = f"{proxy_user}:{proxy_password}@" if proxy_user and proxy_password else ""
                proxy_address_arg = f"socks5://{auth_part}{proxy_ip}:{proxy_port_str}"

            command_args = [
                f"'{'true' if use_proxy else 'false'}'", f"'{proxy_address_arg}'",
                f"'{node_certificate_b64}'", f"'{selected_xray_version}'",
                f"'{node_xray_port_str or ''}'"
            ]
            command = f"sudo {remote_script_path} {' '.join(command_args)}"
            
            logger.info(f"Executing remote setup script on {server_ip}...")
            yield f"data: {json.dumps({'line': 'Executing setup script on the server... this may take a few minutes.'})}\n\n"
            
            stdin_chan, stdout_chan, stderr_chan = ssh_client.exec_command(command, get_pty=True)
            
            # Stream output and capture it for logging
            stdout_lines = []
            stderr_lines = []
            while not stdout_chan.channel.exit_status_ready():
                if stdout_chan.channel.recv_ready():
                    line = stdout_chan.channel.recv(1024).decode('utf-8', errors='ignore').strip()
                    if line:
                        logger.info(f"Script STDOUT: {line}") # Changed from debug to info
                        stdout_lines.append(line)
                        yield f"data: {json.dumps({'line': line})}\n\n"
                if stdout_chan.channel.recv_stderr_ready():
                    line = stderr_chan.channel.recv_stderr(1024).decode('utf-8', errors='ignore').strip()
                    if line:
                        logger.error(f"Script STDERR: {line}") # Changed from warning to error
                        stderr_lines.append(line)
                        yield f"data: {json.dumps({'error_line': line})}\n\n"
                time.sleep(0.1)

            exit_status = stdout_chan.channel.recv_exit_status()
            logger.info(f"Remote script completed with exit status: {exit_status}")

            if exit_status == 0:
                success_message = f"Node '{node_name}' setup script completed successfully."
                logger.info(success_message)
                
                try:
                    logger.info(f"Saving installed node '{node_name}' details to local database.")
                    database.add_installed_node(data)
                except Exception as db_error:
                    logger.error(f"Could not save node details to database for '{node_name}'. Error: {db_error}")
                    yield f"data: {json.dumps({'line': '[WARNING] Could not save node details to local database.'})}\n\n"
                
                node_details = {"name": node_name, "address": server_ip, "port": node_xray_port_str}
                yield f"data: {json.dumps({'status': 'completed', 'exit_code': 0, 'message': success_message, 'node_details': node_details})}\n\n"
            else:
                # Log the captured output for debugging
                full_stdout = "\\n".join(stdout_lines)
                full_stderr = "\\n".join(stderr_lines)
                logger.error(f"Node setup script for '{node_name}' failed. Full STDOUT: {full_stdout}")
                logger.error(f"Node setup script for '{node_name}' failed. Full STDERR: {full_stderr}")

                error_message = f"Node setup script failed for '{node_name}' with exit status: {exit_status}."
                logger.error(error_message)
                sentry_sdk.capture_message(error_message, level="error")
                yield f"data: {json.dumps({'status': 'failed', 'exit_code': exit_status, 'message': error_message})}\n\n"

        except (ValueError, TypeError) as e:
            err_msg = f"Invalid input error: {str(e)}"
            logger.error(err_msg)
            yield f"data: {json.dumps({'status': 'error', 'message': err_msg})}\n\n"
        except paramiko.AuthenticationException:
            err_msg = f"SSH Authentication failed for {ssh_user}@{server_ip}."
            logger.error(err_msg)
            yield f"data: {json.dumps({'status': 'error', 'message': err_msg})}\n\n"
        except (paramiko.SSHException, socket.timeout, socket.error, socks.ProxyConnectionError, socks.GeneralProxyError) as e:
            err_type = type(e).__name__
            user_message = f"Connection to {server_ip} failed. Error: {str(e)} ({err_type})"
            logger.error(user_message)
            yield f"data: {json.dumps({'status': 'error', 'message': user_message})}\n\n"
        except Exception as e:
            import traceback
            err_msg = f"An unexpected error occurred: {str(e)}"
            logger.error(f"Unexpected error during node setup stream for '{node_name}': {str(e)}\n{traceback.format_exc()}")
            sentry_sdk.capture_exception(e)
            yield f"data: {json.dumps({'status': 'error', 'message': err_msg})}\n\n"
        finally:
            if sftp_client: sftp_client.close()
            if ssh_client: ssh_client.close()
            if proxy_sock_for_ssh: proxy_sock_for_ssh.close()
            logger.debug("SSH resources cleaned up in stream generator.")
    
    return Response(stream_with_context(generate_output()), mimetype="text/event-stream", headers={"X-Accel-Buffering": "no"})
