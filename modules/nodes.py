# /opt/Xenon.xray/modules/nodes.py

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
    with open(CONFIG_FILE, "r") as f:
        data = json.load(f)
        return {
            "panel_port": data.get("panel_port", 8000),
            "panel_use_https": data.get("panel_use_https", False),
        }

config = get_config()
PANEL_PORT = config["panel_port"]
PANEL_USE_HTTPS = config["panel_use_https"]

###############################################################################
#                        GLOBAL REQUESTS SESSION                              #
###############################################################################
api_session = requests.Session()
API_BASE_URL = f"{'https' if PANEL_USE_HTTPS else 'http'}://127.0.0.1:{PANEL_PORT}/api"
api_session.verify = not PANEL_USE_HTTPS

###############################################################################
#                             API BRIDGE FUNCTIONS                            #
###############################################################################
def get_nodes(token):
    url = f"{API_BASE_URL}/nodes?page=1&size=100&descending=true&order_by=created_at"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        r = api_session.get(url, headers=headers)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        print(e)
    return None

def get_node(token, node_id):
    """
    Retrieve a single node's details from the API.
    Endpoint typically: /nodes/<node_id>
    """
    url = f"{API_BASE_URL}/nodes/{node_id}"
    headers = {"Authorization": f"Bearer {token}"}
    r = api_session.get(url, headers=headers)
    if r.status_code == 200:
        return r.json()
    return None

def create_node_api(token, node_payload):
    """
    Creates a new node in the Marzneshin panel via the API.
    Endpoint typically: POST /nodes
    """
    url = f"{API_BASE_URL}/nodes"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    try:
        r = api_session.post(url, headers=headers, json=node_payload)
        
        if r.status_code in [200, 201]: 
            logger.info(f"Successfully created node '{node_payload.get('name')}' via API. Status: {r.status_code}")
            return r.json()
        else:
            logger.error(f"Failed to create node via API. Status: {r.status_code}, Response: {r.text}")
            try:
                if r.status_code == 409:
                     error_detail = r.json().get('detail', 'Conflict: Resource already exists.')
                     return {"error": error_detail, "status_code": 409}
                
                error_detail = r.json().get('detail', r.text)
                return {"error": error_detail}
            except json.JSONDecodeError:
                return {"error": r.text}
    except Exception as e:
        logger.error(f"Exception while creating node via API: {str(e)}")
        sentry_sdk.capture_exception(e)
    return None

def update_node_api(token, node_id, node_payload):
    """
    Updates an existing node in the Marzneshin panel via the API.
    Endpoint typically: PUT /nodes/<node_id>
    """
    url = f"{API_BASE_URL}/nodes/{node_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    try:
        # The Marzban API expects the full node object for updates
        r = api_session.put(url, headers=headers, json=node_payload)
        
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
    except Exception as e:
        logger.error(f"Exception while updating node ID {node_id} via API: {str(e)}")
        sentry_sdk.capture_exception(e)
    return None

###############################################################################
#                           ROUTES & LOGIC                                    #
###############################################################################

@nodes_bp.route("/nodes")
def show_nodes():
    if "token" not in session:
        return redirect("/")
    nodes = get_nodes(session["token"])
    if not nodes:
        flash("Failed to fetch nodes.")
        return redirect("/")
    return render_template("nodes.html", nodes=nodes)

# ### START: MODIFIED add_node_to_panel ROUTE ###
@nodes_bp.route("/add_node_to_panel", methods=["POST"])
def add_node_to_panel():
    if "token" not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json()
    if not data or not all(k in data for k in ["name", "address", "port"]):
        return jsonify({"success": False, "message": "Missing node details"}), 400

    node_name = data.get("name")
    server_ip = data.get("address")
    node_xray_port_str = data.get("port")
    # New parameter to decide if we should check for duplicates or create a new unique name
    force_new = data.get("force_new", False) 
    
    if not node_xray_port_str:
        return jsonify({"success": False, "message": "Node Xray Port is required."}), 400

    try:
        node_api_port = int(node_xray_port_str)
    except (ValueError, TypeError):
        return jsonify({"success": False, "message": f"Invalid Node Xray Port: {node_xray_port_str}"}), 400

    try:
        all_nodes_data = get_nodes(session["token"])
        if not all_nodes_data:
            return jsonify({"success": False, "message": "Could not fetch existing nodes from the panel."}), 500
        
        existing_nodes = all_nodes_data.get('items', [])
        existing_node = next((node for node in existing_nodes if node['name'] == node_name), None)

        if existing_node and not force_new:
            # If node exists and we are not forcing a new one, return conflict
            conflict_message = f"A node named '{node_name}' already exists."
            logger.warning(conflict_message)
            return jsonify({
                "success": False, 
                "conflict": True, 
                "message": conflict_message,
                "existing_node": { "id": existing_node['id'], "name": existing_node['name'] }
            }), 409

        # If we are here, we either create a new node or force-create one with a unique name
        final_node_name = node_name
        if existing_node and force_new:
            # Find a unique name, e.g., "My Node 2"
            counter = 2
            existing_names = {node['name'] for node in existing_nodes}
            while True:
                new_name = f"{node_name} {counter}"
                if new_name not in existing_names:
                    final_node_name = new_name
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
            final_msg = f"Node '{final_node_name}' successfully added to the Marzneshin panel."
            logger.info(final_msg)
            return jsonify({"success": True, "message": final_msg})
        else:
            api_error_msg = api_response.get("error", "An unknown API error occurred.") if api_response else "API call failed."
            final_error_msg = f"Failed to add node to the panel. API Error: {api_error_msg}"
            logger.error(final_error_msg)
            return jsonify({"success": False, "message": final_error_msg}), 500

    except Exception as e:
        import traceback
        logger.error(f"Unexpected error while adding node to panel: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"success": False, "message": f"An unexpected server error occurred: {str(e)}"}), 500
# ### END: MODIFIED add_node_to_panel ROUTE ###


# ### START: NEW ROUTE FOR UPDATING ###
@nodes_bp.route("/update_existing_node", methods=["POST"])
def update_existing_node():
    if "token" not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json()
    if not data or not all(k in data for k in ["id", "address", "port"]):
        return jsonify({"success": False, "message": "Missing node update details"}), 400

    node_id = data.get("id")
    new_address = data.get("address")
    new_port_str = data.get("port")

    try:
        new_port = int(new_port_str)
    except (ValueError, TypeError):
        return jsonify({"success": False, "message": f"Invalid port format: {new_port_str}"}), 400

    try:
        # First, get the full current details of the node
        node_data = get_node(session["token"], node_id)
        if not node_data or "error" in node_data:
            return jsonify({"success": False, "message": f"Could not find existing node with ID {node_id}."}), 404

        # Update the necessary fields
        node_data['address'] = new_address
        node_data['port'] = new_port
        node_data['api_port'] = new_port
        
        # Now, send the full updated object back to the API
        api_response = update_node_api(session["token"], node_id, node_data)
        
        if api_response and "error" not in api_response:
            success_msg = f"Node '{node_data['name']}' has been updated successfully."
            logger.info(success_msg)
            return jsonify({"success": True, "message": success_msg})
        else:
            api_error_msg = api_response.get("error", "An unknown API error occurred.") if api_response else "API call failed."
            error_msg = f"Failed to update node. API Error: {api_error_msg}"
            logger.error(error_msg)
            return jsonify({"success": False, "message": error_msg}), 500

    except Exception as e:
        import traceback
        logger.error(f"Unexpected error while updating node {node_id}: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"success": False, "message": f"An unexpected server error occurred: {str(e)}"}), 500
# ### END: NEW ROUTE FOR UPDATING ###


#################### core v changer ####################
@nodes_bp.route("/get_xray_versions", methods=["GET"])
def get_xray_versions():
    """
    Fetch the latest 20 stable Xray versions using xrayc.sh -list 20
    Returns a JSON response with versions or an error message
    """
    if "token" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    script_path = "/opt/Xenon.xray/assets/xrayc.sh"
    if not os.path.isfile(script_path) or not os.access(script_path, os.X_OK):
        logger.error(f"Script {script_path} not found or not executable")
        return jsonify({"error": "Version fetch script not available"}), 500

    try:
        result = subprocess.run(
            ['sudo', script_path, '-list', '20'],
            capture_output=True,
            text=True,
            check=True
        )
        versions = result.stdout.strip().split('\n')
        if not versions or versions[0].startswith('{"status": "error"'):
            error_json = json.loads(versions[0])
            return jsonify({"error": error_json["message"]}), 500
        return jsonify({"versions": versions})
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to fetch versions: {e.stderr}")
        return jsonify({"error": f"Failed to fetch versions: {e.stderr}"}), 500
    except Exception as e:
        logger.error(f"Unexpected error fetching versions: {str(e)}")
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500

@nodes_bp.route("/change_core/<int:node_id>", methods=["POST"])
def change_core(node_id):
    logger.debug(f"Starting change_core for node_id: {node_id}")
    if "token" not in session:
        logger.warning("Unauthorized access attempt")
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    if not data or "version" not in data or not isinstance(data["version"], str):
        logger.error(f"Invalid or missing version in request data: {data}")
        return jsonify({"error": "Version must be a non-empty string"}), 400

    selected_version = data["version"]
    token = session["token"]
    logger.debug(f"Selected version: {selected_version}")

    node_data = get_node(token, node_id)
    if not node_data or node_data.get("name") != "local":
        logger.error(f"Invalid node or not local: {node_data}")
        return jsonify({"error": "This operation is only allowed on the local node"}), 403

    script_path = "/opt/Xenon.xray/assets/xrayc.sh"
    logger.debug(f"Script path: {script_path}")

    if not os.path.isfile(script_path) or not os.access(script_path, os.X_OK):
        logger.error(f"Script not found or not executable at {script_path}")
        return Response(
            f"data: {{\"progress\": 100, \"message\": \"Error: Script not found or not executable at {script_path}\", \"error\": true}}\n\n",
            mimetype="text/event-stream"
        )

    def generate():
        args = ['sudo', 'stdbuf', '-oL', script_path, selected_version]
        logger.debug(f"Subprocess args: {args}")
        process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True,
            env={"PYTHONUNBUFFERED": "1", "PATH": os.environ["PATH"]}
        )
        logger.debug(f"Subprocess started with PID: {process.pid}")

        yield "data: {\"progress\": 0, \"message\": \"Initializing...\"}\n\n"

        while True:
            streams = [process.stdout, process.stderr]
            ready, _, _ = select.select(streams, [], [], 0.1)
            for s in ready:
                line = s.readline().strip()
                if line:
                    if s == process.stdout:
                        logger.debug(f"Realtime STDOUT: {line}")
                        try:
                            data = json.loads(line)
                            yield f"data: {json.dumps(data)}\n\n"
                        except json.JSONDecodeError:
                            logger.debug(f"Ignoring non-JSON stdout: {line}")
                    else:
                        logger.error(f"Realtime STDERR: {line}")
                        yield f"data: {json.dumps({'progress': 100, 'message': f'Error: {line}', 'error': True})}\n\n"
            if process.poll() is not None:
                break

        for s in [process.stdout, process.stderr]:
            remaining = s.read()
            for line in remaining.splitlines():
                line = line.strip()
                if line:
                    if s == process.stdout:
                        logger.debug(f"Final STDOUT: {line}")
                        try:
                            data = json.loads(line)
                            yield f"data: {json.dumps(data)}\n\n"
                        except json.JSONDecodeError:
                            logger.debug(f"Ignoring final non-JSON stdout: {line}")
                    else:
                        logger.error(f"Final STDERR: {line}")
                        yield f"data: {json.dumps({'progress': 100, 'message': f'Error: {line}', 'error': True})}\n\n"
        process.stdout.close()
        process.stderr.close()

    return Response(stream_with_context(generate()), mimetype="text/event-stream", headers={"X-Accel-Buffering": "no"})

####################### Restart core section #######################
@nodes_bp.route("/node/<int:node_id>/restart_cores", methods=["POST"])
def restart_cores(node_id):
    if "token" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    if not data or "cores" not in data:
        return jsonify({"error": "No cores specified"}), 400

    cores = data["cores"]
    if not isinstance(cores, list) or 'xray' not in cores:
        return jsonify({"error": "Only 'xray' core restart is supported"}), 400

    token = session["token"]
    results = {}

    node_data = get_node(token, node_id)
    if not node_data or "backends" not in node_data:
        return jsonify({"error": "Failed to fetch node details"}), 500
    if not any(backend["name"] == "xray" for backend in node_data["backends"]):
        results["xray"] = {"status": "error", "message": "Xray core not found in node"}
        return jsonify(results)

    url = f"{API_BASE_URL}/nodes/{node_id}/xray/config"
    headers = {"Authorization": f"Bearer {token}"}

    try:
        response = api_session.get(url, headers=headers)
        if response.status_code != 200:
            results["xray"] = {"status": "error", "message": f"Failed to fetch config (status: {response.status_code})"}
            return jsonify(results)
    except requests.RequestException as e:
        results["xray"] = {"status": "error", "message": f"Fetch error: {str(e)}"}
        return jsonify(results)

    config_data = response.json()
    if "config" not in config_data:
        results["xray"] = {"status": "error", "message": "Config not found in response"}
        return jsonify(results)

    try:
        put_response = api_session.put(
            url,
            headers=headers,
            json={"config": config_data["config"], "format": 1}
        )
        if put_response.status_code == 200:
            results["xray"] = {"status": "success"}
        else:
            results["xray"] = {"status": "error", "message": f"Failed to update config (status: {put_response.status_code})"}
    except requests.RequestException as e:
        results["xray"] = {"status": "error", "message": f"Update error: {str(e)}"}

    return jsonify(results)

@nodes_bp.route("/restart_all_nodes_cores", methods=["POST"])
def restart_all_nodes_cores():
    if "token" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    token = session["token"]
    nodes_data = get_nodes(token)
    if not nodes_data or "items" not in nodes_data:
        return jsonify({"error": "Failed to fetch nodes"}), 500

    results = {}
    for node in nodes_data["items"]:
        node_id = node["id"]
        node_results = {}
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
                        else:
                            node_results["xray"] = {"status": "error", "message": f"Update failed (status: {put_response.status_code})"}
            except requests.RequestException as e:
                node_results["xray"] = {"status": "error", "message": f"Error: {str(e)}"}
        else:
            node_results["xray"] = {"status": "skipped", "message": "Xray not present"}
        results[node_id] = node_results

    return jsonify(results)

###############################################################################
#                       TEST PROXY & SSH CONNECTION                           #
###############################################################################
# /opt/Xenon.xray/modules/nodes.py

@nodes_bp.route("/test_full_connection", methods=["POST"])
def test_full_connection():
    if "token" not in session:
        logger.warning("Test full connection attempt without token.")
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "No data provided."}), 400

    results = {
        "proxy_status": "not_attempted", "proxy_message": "Proxy not used or not tested.", "proxy_seen_ip": None,
        "ssh_status": "not_attempted", "ssh_message": "SSH connection not attempted."
    }

    # --- START: NEW CREDENTIAL FETCHING LOGIC ---
    use_custom_ssh = data.get("use_custom_ssh", False)
    ssh_creds = {}

    if use_custom_ssh:
        # Get credentials from payload when custom toggle is ON
        ssh_creds['ip'] = data.get("ssh_ip")
        ssh_creds['port_str'] = data.get("ssh_port")
        ssh_creds['user'] = data.get("ssh_user")
        ssh_creds['pass'] = data.get("ssh_pass")
        if not all(ssh_creds.values()):
            results["ssh_message"] = "Custom SSH IP, Port, User, and Password are required."
            results["ssh_status"] = "failed_input"
            return jsonify(results), 400
    else:
        # Get credentials from Database using node_id when custom toggle is OFF
        node_id = data.get("node_id")
        if not node_id:
            results["ssh_message"] = "Node ID is required for testing with stored credentials."
            results["ssh_status"] = "failed_input"
            return jsonify(results), 400
        
        node_api_data = get_node(session["token"], node_id)
        if not node_api_data:
            results["ssh_message"] = f"Node with ID {node_id} not found."
            results["ssh_status"] = "failed_input"
            return jsonify(results), 404
            
        node_db_data = database.get_installed_node_by_name(node_api_data.get("name"))
        if not node_db_data:
            results["ssh_message"] = "SSH details not found in local DB for this node."
            results["ssh_status"] = "failed_input"
            return jsonify(results), 404
        
        ssh_creds['ip'] = node_db_data.get('server_ip')
        ssh_creds['port_str'] = str(node_db_data.get('ssh_port'))
        ssh_creds['user'] = node_db_data.get('ssh_user')
        ssh_creds['pass'] = node_db_data.get('ssh_password')
        if not all(ssh_creds.values()):
            results["ssh_message"] = "Incomplete SSH credentials found in local DB."
            results["ssh_status"] = "failed_input"
            return jsonify(results), 400
    
    # Unpack credentials for use in the rest of the function
    ssh_ip = ssh_creds['ip']
    ssh_port_str = ssh_creds['port_str']
    ssh_user = ssh_creds['user']
    ssh_pass = ssh_creds['pass']
    # --- END: NEW CREDENTIAL FETCHING LOGIC ---

    # --- The rest of the function remains the same ---
    use_proxy = data.get("use_proxy", False)
    proxy_ip = data.get("proxy_ip")
    proxy_port_str = data.get("proxy_port")
    proxy_user = data.get("proxy_user")
    proxy_pass = data.get("proxy_pass")

    try:
        ssh_port = int(ssh_port_str)
        if not (1 <= ssh_port <= 65535): raise ValueError("Invalid SSH port")
    except ValueError:
        results["ssh_message"] = "Invalid SSH Port."
        results["ssh_status"] = "failed_input"
        return jsonify(results), 400

    proxy_port_int = 0
    if use_proxy:
        if not proxy_ip or not proxy_port_str:
            results["proxy_status"] = "failed_input"
            results["proxy_message"] = "Proxy IP and Port are required when 'Use Proxy' is enabled."
            results["ssh_status"] = "not_attempted"
            results["ssh_message"] = "SSH test skipped due to proxy input error."
            return jsonify(results), 400
        try:
            proxy_port_int = int(proxy_port_str)
            if not (1 <= proxy_port_int <= 65535): raise ValueError("Invalid proxy port")
        except ValueError:
            results["proxy_status"] = "failed_input"
            results["proxy_message"] = "Invalid Proxy Port."
            results["ssh_status"] = "not_attempted"
            results["ssh_message"] = "SSH test skipped due to proxy input error."
            return jsonify(results), 400

        proxy_url_display = f"socks5://{proxy_ip}:{proxy_port_int}"
        proxies_for_requests = { "http": f"socks5h://{proxy_ip}:{proxy_port_int}", "https": f"socks5h://{proxy_ip}:{proxy_port_int}" }
        if proxy_user:
            auth_str = f"{requests.utils.quote(proxy_user)}"
            if proxy_pass:
                auth_str += f":{requests.utils.quote(proxy_pass)}"
            proxies_for_requests["http"] = f"socks5h://{auth_str}@{proxy_ip}:{proxy_port_int}"
            proxies_for_requests["https"] = f"socks5h://{auth_str}@{proxy_ip}:{proxy_port_int}"
            proxy_url_display = f"socks5://{proxy_user}:***@{proxy_ip}:{proxy_port_int}"

        logger.info(f"Testing proxy: {proxy_url_display} against http://httpbin.org/ip")
        try:
            response = requests.get("http://httpbin.org/ip", proxies=proxies_for_requests, timeout=10)
            response.raise_for_status()
            r_json = response.json()
            results["proxy_seen_ip"] = r_json.get("origin")
            results["proxy_status"] = "success"
            results["proxy_message"] = f"Proxy OK. IP via proxy: {results['proxy_seen_ip']}"
            logger.info(f"Proxy test successful. IP: {results['proxy_seen_ip']}")
        except Exception as e:
            logger.error(f"Proxy test failed: {str(e)}")
            results["proxy_status"] = "failed"
            results["proxy_message"] = f"Proxy Error: {str(e)}"
            results["ssh_status"] = "not_attempted"
            results["ssh_message"] = "SSH test skipped due to proxy failure."
            return jsonify(results)

    logger.info(f"Attempting SSH test to {ssh_ip}:{ssh_port} {'via proxy' if use_proxy and results['proxy_status'] == 'success' else ''}")

    ssh_client_test = paramiko.SSHClient()
    ssh_client_test.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    temp_sock_for_paramiko = None

    if use_proxy and results['proxy_status'] == 'success':
        temp_sock_for_paramiko = socks.socksocket()
        temp_sock_for_paramiko.set_proxy(proxy_type=socks.SOCKS5, addr=proxy_ip, port=proxy_port_int, username=proxy_user or None, password=proxy_pass or None)
        try:
            temp_sock_for_paramiko.connect((ssh_ip, ssh_port))
        except Exception as e:
            results["ssh_status"] = "failed_proxy_setup"
            results["ssh_message"] = f"Error connecting proxy socket to SSH host: {str(e)}"
            if temp_sock_for_paramiko: temp_sock_for_paramiko.close()
            return jsonify(results)

    try:
        ssh_client_test.connect(
            hostname=ssh_ip, port=ssh_port, username=ssh_user, password=ssh_pass,
            sock=temp_sock_for_paramiko, timeout=10, banner_timeout=15, auth_timeout=15
        )
        results["ssh_status"] = "success"
        results["ssh_message"] = "SSH connection successful (authentication OK)."
        logger.info(f"SSH test successful to {ssh_ip}:{ssh_port}")
    except paramiko.AuthenticationException:
        results["ssh_status"] = "failed_auth"; results["ssh_message"] = "SSH Authentication failed."
    except paramiko.SSHException as e:
        results["ssh_status"] = "failed_other"; results["ssh_message"] = f"SSH Error: {str(e)}"
    except socket.timeout:
        results["ssh_status"] = "failed_timeout"; results["ssh_message"] = "SSH Connection timed out."
    except Exception as e:
        results["ssh_status"] = "failed_unexpected"; results["ssh_message"] = f"Unexpected SSH error: {str(e)}"
    finally:
        if ssh_client_test: ssh_client_test.close()
        if temp_sock_for_paramiko: temp_sock_for_paramiko.close()

    return jsonify(results)

###############################################################################
#                            ADD NODE VIA SSH                                 #
###############################################################################
@nodes_bp.route("/add_node_ssh", methods=["POST"])
def add_node_ssh():
    if "token" not in session:
        logger.warning("Add node attempt without token.")
        return jsonify({"success": False, "message": "Unauthorized access. Please login again."}), 401

    data = request.get_json() # data contains all form fields
    if not data:
        logger.error("Add node attempt with no data.")
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
        logger.error(f"Add node attempt with missing fields: {', '.join(missing_fields)}")
        return jsonify({"success": False, "message": f"Missing required fields: {', '.join(missing_fields)}."}), 400

    try:
        ssh_port = int(ssh_port_str)
        if not (1 <= ssh_port <= 65535): raise ValueError("Invalid SSH port range")
    except ValueError:
        logger.error(f"Add node attempt with invalid SSH port: {ssh_port_str}")
        return jsonify({"success": False, "message": "Invalid SSH port. Must be 1-65535."}), 400

    logger.info(f"Received request to add new node '{node_name}' via setup script:")
    logger.info(f"  Server IP: {server_ip}, SSH User: {ssh_user}, SSH Port: {ssh_port}")
    logger.info(f"  Selected Xray Version: {selected_xray_version}")
    logger.info(f"  Using Proxy: {use_proxy}")

    local_script_path = "/opt/Xenon.xray/assets/setup_node.sh"
    remote_script_path = "/root/marznode/setup_node.sh"

    if not os.path.exists(local_script_path):
        error_msg = f"Source script file not found at {local_script_path}."
        logger.error(error_msg)
        try:
            raise FileNotFoundError(error_msg)
        except FileNotFoundError as e:
            sentry_sdk.capture_exception(e)
        return jsonify({"success": False, "message": error_msg}), 500

    ssh_client = None
    sftp_client = None
    proxy_sock_for_ssh = None

    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if use_proxy:
            if not proxy_ip or not proxy_port_str:
                logger.error("Proxy IP and Port are required when 'Use Proxy' is enabled for SSH.")
                return jsonify({"success": False, "message": "Proxy IP and Port are required."}), 400
            try:
                proxy_port_int = int(proxy_port_str)
                if not (1 <= proxy_port_int <= 65535): raise ValueError("Invalid proxy port range")
            except ValueError:
                logger.error(f"Invalid Proxy Port for SSH connection: {proxy_port_str}")
                return jsonify({"success": False, "message": "Invalid Proxy Port."}), 400

            logger.info(f"Setting up SOCKS proxy for SSH connection via {proxy_ip}:{proxy_port_int}")
            proxy_sock_for_ssh = socks.socksocket()
            proxy_sock_for_ssh.set_proxy(
                socks.SOCKS5, proxy_ip, proxy_port_int,
                username=proxy_user or None,
                password=proxy_password or None
            )
            proxy_sock_for_ssh.connect((server_ip, ssh_port))

        ssh_client.connect(
            hostname=server_ip, port=ssh_port, username=ssh_user, password=ssh_password,
            sock=proxy_sock_for_ssh,
            timeout=20, banner_timeout=20, auth_timeout=20
        )
        logger.info(f"SSH connection established to {server_ip} {'via proxy' if use_proxy else ''}")

        logger.info(f"Uploading script from '{local_script_path}' to '{remote_script_path}'")
        sftp_client = ssh_client.open_sftp()
        sftp_client.put(local_script_path, remote_script_path)
        sftp_client.close()
        logger.info("Script uploaded successfully.")

        logger.info(f"Making remote script '{remote_script_path}' executable.")
        stdin, stdout, stderr = ssh_client.exec_command(f"chmod +x {remote_script_path}")
        stdin, stdout, stderr = ssh_client.exec_command(f"sed -i 's/\\r$//' {remote_script_path}")
        exit_status_chmod = stdout.channel.recv_exit_status()
        if exit_status_chmod != 0:
            error_msg = f"Failed to make script executable on remote server. Error: {stderr.read().decode().strip()}"
            raise Exception(error_msg)

        use_proxy_arg = 'true' if use_proxy else 'false'
        proxy_address_arg = ""
        if use_proxy:
            auth_part = ""
            if proxy_user:
                auth_part = f"{proxy_user}"
                if proxy_password:
                    auth_part += f":{proxy_password}"
                auth_part += "@"
            proxy_address_arg = f"socks5://{auth_part}{proxy_ip}:{proxy_port_str}"

        command_args = [
            f"'{use_proxy_arg}'",
            f"'{proxy_address_arg}'",
            f"'{node_certificate_b64}'",
            f"'{selected_xray_version}'",
            f"'{node_xray_port_str or ''}'"
        ]
        
        command = f"sudo {remote_script_path} {' '.join(command_args)} > /dev/null"
        
        logger.info(f"Executing remote command on {server_ip}: '{remote_script_path} ...'")
        
        def generate_output():
            try:
                logger.info(f"Executing remote command on {server_ip}: '{remote_script_path} ...' (arguments hidden)")
                stdin_chan, stdout_chan, stderr_chan = ssh_client.exec_command(command, get_pty=True)
                
                stdout = stdout_chan.channel.makefile('rU', 1)
                stderr = stderr_chan.channel.makefile_stderr('rU', 1)

                while not stdout_chan.channel.exit_status_ready():
                    while stdout_chan.channel.recv_ready():
                        line = stdout.readline().strip()
                        if line:
                            logger.debug(f"Script STDOUT: {line}")
                            yield f"data: {json.dumps({'line': line})}\n\n"
                    while stdout_chan.channel.recv_stderr_ready():
                        line = stderr.readline().strip()
                        if line:
                            logger.warning(f"Script STDERR: {line}")
                            yield f"data: {json.dumps({'error_line': line})}\n\n"
                    time.sleep(0.1)

                for line in stdout.readlines():
                    line = line.strip()
                    if line:
                        logger.debug(f"Script STDOUT (final): {line}")
                        yield f"data: {json.dumps({'line': line})}\n\n"
                for line in stderr.readlines():
                    line = line.strip()
                    if line:
                        logger.warning(f"Script STDERR (final): {line}")
                        yield f"data: {json.dumps({'error_line': line})}\n\n"
                
                stdout.close()
                stderr.close()

                exit_status = stdout_chan.channel.recv_exit_status()
                logger.info(f"Remote script '{remote_script_path}' completed with exit_status: {exit_status}")

                if exit_status == 0:
                    success_message = f"Node '{node_name}' setup script completed successfully on {server_ip}."
                    logger.info(success_message)
                    
                    # ### START: SAVE TO DATABASE LOGIC ###
                    try:
                        logger.info("Attempting to save node details to local database.")
                        # The `data` dictionary from the start of the route has all we need.
                        database.add_installed_node(data)
                    except Exception as db_error:
                        # We log the error but don't fail the entire process,
                        # as the primary goal (node setup) was successful.
                        logger.error(f"Could not save node details to database. Error: {db_error}")
                        yield f"data: {json.dumps({'line': '[WARNING] Could not save node details to local database.'})}\n\n"
                    # ### END: SAVE TO DATABASE LOGIC ###

                    # Instead of adding to panel, send details back to the client.
                    node_details = {
                        "name": node_name,
                        "address": server_ip,
                        "port": node_xray_port_str,
                    }
                    yield f"data: {json.dumps({'status': 'completed', 'exit_code': 0, 'message': success_message, 'node_details': node_details})}\n\n"

                else:
                    error_detail = f"Script failed with exit code {exit_status}."
                    with sentry_sdk.push_scope() as scope:
                        scope.set_tag("node_setup_failed", "true")
                        scope.set_tag("exit_code", exit_status)
                        scope.set_context("node_details", {
                            "node_name": node_name,
                            "server_ip": server_ip,
                            "ssh_user": ssh_user,
                        })
                        sentry_sdk.capture_message(f"Node setup script failed for '{node_name}'", level="error")
                    ui_message = f"Node setup script failed for '{node_name}'. Exit status: {exit_status}."
                    logger.error(ui_message)
                    yield f"data: {json.dumps({'status': 'failed', 'exit_code': exit_status, 'message': ui_message})}\n\n"

            except paramiko.AuthenticationException:
                err_msg = f"SSH Authentication failed for {ssh_user}@{server_ip}."
                logger.error(err_msg)
                yield f"data: {json.dumps({'status': 'error', 'message': err_msg})}\n\n"
            except (paramiko.SSHException, socket.timeout, socket.error, socks.ProxyConnectionError, socks.GeneralProxyError) as e:
                err_type = type(e).__name__
                logger.error(f"SSH/Proxy connection error to {server_ip}: {err_type} - {str(e)}")
                if isinstance(e, socket.timeout):
                    user_message = f"Connection to {server_ip} timed out."
                elif isinstance(e, socks.ProxyConnectionError):
                    user_message = f"Failed to connect to proxy {proxy_ip}:{proxy_port_str if use_proxy else 'N/A'}. {str(e)}"
                else:
                    user_message = f"Could not connect to {server_ip}. Error: {str(e)}"
                yield f"data: {json.dumps({'status': 'error', 'message': user_message})}\n\n"
            except Exception as e:
                import traceback
                logger.error(f"Unexpected error during node setup stream for '{node_name}': {str(e)}\n{traceback.format_exc()}")
                yield f"data: {json.dumps({'status': 'error', 'message': f'An unexpected error occurred: {str(e)}'})}\n\n"
            finally:
                if ssh_client:
                    ssh_client.close()
                    logger.debug("SSH client closed in stream generator.")
                if proxy_sock_for_ssh:
                    proxy_sock_for_ssh.close()
                    logger.debug("Proxy socket for SSH closed in stream generator.")
        
        return Response(stream_with_context(generate_output()), mimetype="text/event-stream", headers={"X-Accel-Buffering": "no"})

    except paramiko.AuthenticationException:
        err_msg = f"SSH Authentication failed for {ssh_user}@{server_ip}. Please check username/password."
        logger.error(err_msg)
        return jsonify({"success": False, "message": err_msg, "stream_error": True }), 401 
    except (paramiko.SSHException, socket.timeout, socket.error, socks.ProxyConnectionError, socks.GeneralProxyError) as e:
        err_type = type(e).__name__
        logger.error(f"SSH/Proxy connection error to {server_ip}: {err_type} - {str(e)}")
        if isinstance(e, socket.timeout):
            user_message = f"Connection to {server_ip} timed out. Check IP, port, and firewall."
        elif isinstance(e, socks.ProxyConnectionError):
            user_message = f"Failed to connect to proxy {proxy_ip}:{proxy_port_str if use_proxy else 'N/A'}. {str(e)}"
        else:
            user_message = f"Could not connect to {server_ip}. Check server details and network. Error: {str(e)}"
        return jsonify({"success": False, "message": user_message, "stream_error": True}), 500
    except Exception as e:
        import traceback
        logger.error(f"Unexpected error during node setup (pre-stream) for '{node_name}': {str(e)}\n{traceback.format_exc()}")
        return jsonify({"success": False, "message": f"An unexpected error occurred: {str(e)}", "stream_error": True}), 500
    finally:
        if 'generate_output' not in locals() or not callable(locals()['generate_output']):
            if ssh_client:
                ssh_client.close()
                logger.debug("SSH client closed (pre-stream error).")
            if proxy_sock_for_ssh:
                proxy_sock_for_ssh.close()
                logger.debug("Proxy socket for SSH closed (pre-stream error).")
