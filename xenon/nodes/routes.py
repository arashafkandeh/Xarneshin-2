from flask import Blueprint, render_template, session, redirect, url_for, flash, request, jsonify
import logging
import paramiko
import socks
import socket
import requests
from requests.utils import quote as urlquote # For test_full_connection

# Use relative imports for modules within the same package or parent package
from .utils import get_nodes, get_node
from ..auth.decorators import login_required # Goes up to xenon, then into auth

logger = logging.getLogger(__name__)

nodes_bp = Blueprint('nodes', __name__, template_folder='../templates', url_prefix='/nodes')
# Note: Original nodes_bp had no url_prefix, routes were /nodes, /node/<id>/overview etc.
# If url_prefix='/nodes' is set here, then routes inside should be relative to this.
# e.g. @nodes_bp.route("/") for /nodes page, @nodes_bp.route("/<int:node_id>/overview") for /nodes/1/overview
# For now, I will adjust routes assuming this prefix.

@nodes_bp.route("/") # This will now be accessible at /nodes/
@login_required
def show_nodes():
    logger.debug("Attempting to show nodes page.")
    nodes_data = get_nodes(session["token"])
    if not nodes_data:
        flash("Failed to fetch nodes. The API might be down or your session expired.", "error")
    return render_template("nodes.html", nodes=nodes_data if nodes_data else {"items": []})

# The route /node/<id>/overview needs to be adjusted if nodes_bp has /nodes prefix.
# It would become /nodes/<id>/overview.
# Or, we remove url_prefix from nodes_bp and define full paths in routes.
# Let's assume full paths for now to match original structure more closely, so remove nodes_bp prefix.
# Re-defining blueprint without prefix:
# nodes_bp = Blueprint('nodes', __name__, template_folder='../templates')
# And routes would be:
# @nodes_bp.route("/nodes")
# @nodes_bp.route("/node/<int:node_id>/overview")

# Reverting to original structure (no prefix on nodes_bp itself for these specific routes)
# The Blueprint will be registered in app.py without a prefix, or with one that makes sense.
# Let's remove the prefix here and ensure app.py registers it appropriately.
# Blueprint definition without prefix: (This will be done in a separate step if I find it necessary,
# for now, I'll assume the prefix is /nodes and adjust routes accordingly)

# If nodes_bp is at /nodes:
# Path for overview: /nodes/<int:node_id>/overview
@nodes_bp.route("/<int:node_id>/overview")
@login_required
def overview(node_id):
    # This function was already in xenon_project/xenon/nodes/routes.py
    # Ensure imports are correct and url_for calls are updated if needed.
    logger.debug(f"Fetching overview for node_id: {node_id}")
    node_data = get_node(session["token"], node_id)
    if not node_data:
        flash(f"Failed to retrieve node details for node {node_id}.", "error")
        return redirect(url_for("nodes.show_nodes")) # Correct: blueprint_name.function_name

    node_status = node_data.get("status", "unknown")
    xray_version = "unknown"
    backends = node_data.get("backends", [])
    for backend in backends:
        if backend.get("name") == "xray":
            xray_version = backend.get("version", "unknown")
            break
    stats = {"status": node_status, "xray_version": xray_version}
    return render_template("overview.html", node_id=node_id, stats=stats, node_data=node_data)


# This route was /add_node_ssh at root in original.
# If nodes_bp is prefixed with /nodes, this would be /nodes/add_node_ssh
# Or it could be a top-level route in a different blueprint if not node-specific.
# For now, let's assume it's part of general node operations.
@nodes_bp.route("/add_node_via_ssh") # Changed route slightly for clarity if under /nodes prefix
@login_required
def add_node_ssh(): # Renamed function slightly if route changed
    data = request.get_json()
    if not data:
        logger.error("Add node SSH attempt with no data.")
        return jsonify({"success": False, "message": "No data provided."}), 400

    node_name = data.get("nodeName")
    server_ip = data.get("serverIP")
    ssh_user = data.get("sshUser")
    ssh_password = data.get("sshPassword")
    ssh_port_str = data.get("sshPort")
    node_certificate = data.get("nodeCertificate")

    use_proxy = data.get("useProxy", False)
    proxy_ip = data.get("proxyIP")
    proxy_port_str = data.get("proxyPort")
    proxy_user = data.get("proxyUser")
    proxy_password = data.get("proxyPassword")

    required_fields = {
        "Node Name": node_name, "Server IP": server_ip,
        "SSH Username": ssh_user, "SSH Password": ssh_password, "SSH Port": ssh_port_str,
        "Node Certificate": node_certificate
    }
    missing_fields = [name for name, value in required_fields.items() if not value]
    if missing_fields:
        logger.error(f"Add node SSH: Missing fields: {', '.join(missing_fields)}")
        return jsonify({"success": False, "message": f"Missing required fields: {', '.join(missing_fields)}."}), 400

    try:
        ssh_port = int(ssh_port_str)
        if not (1 <= ssh_port <= 65535): raise ValueError("Invalid SSH port range")
    except ValueError:
        logger.error(f"Add node SSH: Invalid SSH port: {ssh_port_str}")
        return jsonify({"success": False, "message": "Invalid SSH port. Must be 1-65535."}), 400

    logger.info(f"Attempting to add node '{node_name}' via SSH to {server_ip}:{ssh_port}")
    ssh_client = None
    proxy_sock_for_ssh = None

    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if use_proxy:
            if not proxy_ip or not proxy_port_str:
                return jsonify({"success": False, "message": "Proxy IP and Port are required."}), 400
            try:
                proxy_port_int = int(proxy_port_str)
                if not (1 <= proxy_port_int <= 65535): raise ValueError("Invalid proxy port range")
            except ValueError:
                return jsonify({"success": False, "message": "Invalid Proxy Port."}), 400
            logger.info(f"Setting up SOCKS proxy for SSH: {proxy_ip}:{proxy_port_int}")
            proxy_sock_for_ssh = socks.socksocket()
            proxy_sock_for_ssh.set_proxy(
                socks.SOCKS5, proxy_ip, proxy_port_int,
                username=proxy_user if proxy_user else None,
                password=proxy_password if proxy_password else None
            )
            proxy_sock_for_ssh.connect((server_ip, ssh_port))

        ssh_client.connect(
            hostname=server_ip, port=ssh_port, username=ssh_user, password=ssh_password,
            sock=proxy_sock_for_ssh, timeout=20, banner_timeout=20, auth_timeout=20
        )
        command = "hostname"
        stdin, stdout, stderr = ssh_client.exec_command(command, timeout=15)
        hostname_output = stdout.read().decode('utf-8', errors='ignore').strip()
        stderr_output = stderr.read().decode('utf-8', errors='ignore').strip()
        exit_status = stdout.channel.recv_exit_status()

        if exit_status == 0 and hostname_output:
            # Actual node addition to panel API is not in original snippet here
            return jsonify({"success": True, "message": f"Hostname for '{node_name}': {hostname_output}. (Node addition logic to panel not implemented in this snippet)", "hostname": hostname_output, "server_ip_used": server_ip})
        elif exit_status == 0 and not hostname_output:
            return jsonify({"success": False, "message": f"Hostname command on {server_ip} returned no output.", "hostname": ""})
        else:
            return jsonify({"success": False, "message": f"Failed to get hostname from {server_ip}. Exit: {exit_status}. Error: {stderr_output or 'No error output'}", "hostname": ""})
    except paramiko.AuthenticationException:
        return jsonify({"success": False, "message": f"SSH Auth failed for {ssh_user}@{server_ip}."}), 401
    except (paramiko.SSHException, socket.timeout, socket.error, socks.ProxyConnectionError, socks.GeneralProxyError) as e:
        user_message = f"Could not connect to {server_ip} for SSH. Error: {str(e)}"
        return jsonify({"success": False, "message": user_message}), 500
    except Exception as e:
        logger.error(f"Unexpected error during SSH for add_node for '{node_name}': {str(e)}", exc_info=True)
        return jsonify({"success": False, "message": f"Unexpected error: {str(e)}"}), 500
    finally:
        if ssh_client: ssh_client.close()
        if proxy_sock_for_ssh: proxy_sock_for_ssh.close()

# This was /test_full_connection at root. It's a tool, so should go to tools_bp.
# For now, I'll leave it commented here as a reminder if it was meant to be node-related.
# If it's a general tool, it's already in tools/network_tests.py and tools/routes.py
# @nodes_bp.route("/<int:node_id>/test_full_connection_on_node", methods=["POST"]) # Example if node-specific
# @login_required
# def test_full_connection_for_node(node_id):
    # ... logic for testing connection related to a specific node ...
    # This would likely use the node's stored details rather than getting all from request.
    # The current perform_full_connection_test is generic.
    # pass
```

**تصحیح در مورد `nodes_bp` و پیشوند URL:**

در `xenon_project/xenon/app.py`، من `nodes_bp` را بدون پیشوند URL ثبت کردم: `app.register_blueprint(nodes_bp)`.
این بدان معناست که مسیرهای داخل `nodes_bp` باید مسیر کامل خود را تعریف کنند.

بنابراین، در `xenon_project/xenon/nodes/routes.py`:
*   `@nodes_bp.route("/")` با پیشوند `/nodes` در `Blueprint` به `/nodes/` نگاشت می‌شود.
*   برای اینکه مسیرها مانند قبل عمل کنند (`/nodes` و `/node/<int:node_id>/overview`)، باید:
    1.  `url_prefix` از تعریف `nodes_bp` حذف شود: `nodes_bp = Blueprint('nodes', __name__, template_folder='../templates')`
    2.  مسیرها به صورت کامل تعریف شوند:
        *   `@nodes_bp.route("/nodes")`
        *   `@nodes_bp.route("/node/<int:node_id>/overview")`
        *   `@nodes_bp.route("/add_node_ssh")` (اگر این مسیر در اینجا باقی بماند)

من این اصلاح را در کد بالا اعمال می‌کنم.
