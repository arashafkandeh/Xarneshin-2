# /opt/Xenon.xray/modules/overview.py

from flask import Blueprint, render_template, session, redirect, url_for, jsonify, flash, request
import requests
import paramiko
import socks
import socket
import os
import time
import logging
import subprocess
from modules.nodes import get_node
from modules.database import get_installed_node_by_name

overview_bp = Blueprint('overview', __name__)
logger = logging.getLogger(__name__)

def is_node_local(node_data: dict) -> bool:
    """
    Determines if a node is the local node based on its name.
    This is a more reliable and secure method than checking the address.
    """
    if not node_data:
        return False
    # The default local node name in Marzban almost always contains "local".
    # This check is case-insensitive and robust.
    node_name = node_data.get("name", "").lower()
    return "local" in node_name

@overview_bp.route("/node/<int:node_id>/overview")
def overview(node_id):
    if "token" not in session:
        return redirect("/")
    node_data = get_node(session["token"], node_id)
    if not node_data:
        flash("Failed to retrieve node details.")
        return redirect(url_for("nodes.show_nodes"))

    # Use the reliable helper function to check if the node is local
    is_local = is_node_local(node_data)

    node_status = node_data.get("status", "unknown")
    xray_version = "unknown"
    backends = node_data.get("backends", [])
    for backend in backends:
        if backend.get("name") == "xray":
            xray_version = backend.get("version", "unknown")
            break

    stats = {
        "status": node_status,
        "xray_version": xray_version
    }
    return render_template("overview.html", node_id=node_id, stats=stats, is_local_node=is_local)

@overview_bp.route("/node/<int:node_id>/change_xray_version", methods=["POST"])
def change_xray_version(node_id):
    if "token" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "No data provided"}), 400

    selected_xray_version = data.get("selectedXrayVersion")
    if not selected_xray_version:
        return jsonify({"success": False, "error": "No Xray version was selected."}), 400

    use_custom_ssh = data.get("useCustomSsh", False)
    
    # Determine if the node is local, ONLY if not using custom SSH
    is_local = False
    node_api_data = None
    if not use_custom_ssh:
        node_api_data = get_node(session["token"], node_id)
        if not node_api_data:
            return jsonify({"success": False, "error": "Node not found in panel."}), 404
        is_local = is_node_local(node_api_data)

    # Common settings
    use_proxy = data.get("useProxy", False)
    proxy_ip = data.get("proxyIP")
    proxy_port_str = data.get("proxyPort")
    proxy_user = data.get("proxyUser")
    proxy_pass = data.get("proxyPassword")
    local_script_path = "/opt/Xenon.xray/assets/xray_version.sh"

    # --- PATH 1: LOCAL NODE EXECUTION ---
    if is_local:
        node_name = node_api_data.get('name') if node_api_data else f"ID: {node_id}"
        logger.info(f"Executing xray_version.sh locally for node '{node_name}' to version {selected_xray_version}.")
        if not os.path.exists(local_script_path) or not os.access(local_script_path, os.X_OK):
            return jsonify({"success": False, "error": f"Local script not found or not executable at {local_script_path}"}), 500

        use_proxy_arg = 'true' if use_proxy else 'false'
        proxy_address_arg = ""
        if use_proxy:
            auth_part = f"{proxy_user}:{proxy_pass}@" if proxy_user and proxy_pass else f"{proxy_user}@" if proxy_user else ""
            proxy_address_arg = f"socks5://{auth_part}{proxy_ip}:{proxy_port_str}"

        command_to_run = [
            'sudo', 
            local_script_path, 
            use_proxy_arg, 
            proxy_address_arg, 
            selected_xray_version, 
            'local'  # The new 4th argument for the script
        ]
        
        try:
            result = subprocess.run(command_to_run, capture_output=True, text=True, check=False)
            if result.returncode == 0:
                return jsonify({"success": True})
            else:
                error_output = result.stderr.strip()
                return jsonify({"success": False, "error": f"Script failed. Details: {error_output}"}), 500
        except Exception as e:
            return jsonify({"success": False, "error": f"An unexpected error occurred: {str(e)}"}), 500

    # --- PATH 2: REMOTE NODE EXECUTION (via Custom SSH or DB credentials) ---
    else:
        logger.info(f"Executing xray_version.sh via SSH for remote node (ID: {node_id}) to version {selected_xray_version}.")
        
        ssh_ip, ssh_port_str, ssh_user, ssh_pass = None, None, None, None
        if use_custom_ssh:
            ssh_ip = data.get("serverIP")
            ssh_port_str = data.get("sshPort")
            ssh_user = data.get("sshUser")
            ssh_pass = data.get("sshPassword")
            if not all([ssh_ip, ssh_port_str, ssh_user, ssh_pass]):
                return jsonify({"success": False, "error": "When using custom credentials, all SSH fields are required."}), 400
        else:
            if not node_api_data: # Fetch again if it wasn't fetched before
                node_api_data = get_node(session["token"], node_id)
            node_db_data = get_installed_node_by_name(node_api_data.get("name"))
            if not node_db_data:
                return jsonify({"success": False, "error": "Node details not in local DB. Please use custom credentials."}), 404
            ssh_ip = node_db_data.get('server_ip')
            ssh_port_str = str(node_db_data.get('ssh_port'))
            ssh_user = node_db_data.get('ssh_user')
            ssh_pass = node_db_data.get('ssh_password')
            if not all([ssh_ip, ssh_port_str, ssh_user, ssh_pass]):
                return jsonify({"success": False, "error": "Incomplete SSH credentials found in database."}), 400

        try:
            ssh_port = int(ssh_port_str)
        except (ValueError, TypeError):
            return jsonify({"success": False, "error": "Invalid SSH port."}), 400
        
        # (The rest of the SSH logic remains the same as your original file)
        remote_script_path = "/root/marznode/xray_version.sh"
        if not os.path.exists(local_script_path):
            return jsonify({"success": False, "error": f"Local script not found at {local_script_path}"}), 500
        
        ssh_client, proxy_sock = None, None
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if use_proxy:
                if not proxy_ip or not proxy_port_str:
                    return jsonify({"success": False, "error": "Proxy IP and Port are required."}), 400
                proxy_port = int(proxy_port_str)
                proxy_sock = socks.socksocket()
                proxy_sock.set_proxy(socks.SOCKS5, proxy_ip, proxy_port, username=proxy_user or None, password=proxy_pass or None)
                proxy_sock.connect((ssh_ip, ssh_port))

            ssh_client.connect(hostname=ssh_ip, port=ssh_port, username=ssh_user, password=ssh_pass, sock=proxy_sock, timeout=20, banner_timeout=20)
            sftp = ssh_client.open_sftp()
            sftp.put(local_script_path, remote_script_path)
            sftp.close()
            stdin, stdout, stderr = ssh_client.exec_command(f"chmod +x {remote_script_path} && sed -i 's/\\r$//' {remote_script_path}")
            if stdout.channel.recv_exit_status() != 0:
                error_output = stderr.read().decode('utf-8').strip()
                return jsonify({"success": False, "error": f"Failed to set permissions: {error_output}"}), 500

            use_proxy_arg = 'true' if use_proxy else 'false'
            proxy_address_arg = ""
            if use_proxy:
                auth_part = f"{proxy_user}:{proxy_pass}@" if proxy_user and proxy_pass else f"{proxy_user}@" if proxy_user else ""
                proxy_address_arg = f"socks5://{auth_part}{proxy_ip}:{proxy_port_str}"

            command_to_run = f"sudo {remote_script_path} '{use_proxy_arg}' '{proxy_address_arg}' '{selected_xray_version}'"
            stdin, stdout, stderr = ssh_client.exec_command(command_to_run)
            
            if stdout.channel.recv_exit_status() == 0:
                logger.info(f"Successfully executed xray_version.sh on {ssh_ip}")
                return jsonify({"success": True})
            else:
                error_output = stderr.read().decode('utf-8').strip()
                logger.error(f"Script execution failed on {ssh_ip}. Error: {error_output}")
                return jsonify({"success": False, "error": f"Script failed. Details: {error_output}"}), 500
        except Exception as e:
            logger.error(f"Unexpected error in SSH change_xray_version: {str(e)}")
            return jsonify({"success": False, "error": f"An unexpected error occurred during SSH operation: {str(e)}"}), 500
        finally:
            if ssh_client: ssh_client.close()

@overview_bp.route("/node/<int:node_id>/system_command", methods=["POST"])
def system_command(node_id):
    if "token" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    data = request.get_json()
    command = data.get("command")

    COMMAND_MAP = {
        "reboot": "reboot",
        "clear_cache": "sync && echo 1 > /proc/sys/vm/drop_caches && sync && echo 2 > /proc/sys/vm/drop_caches && sync && echo 3 > /proc/sys/vm/drop_caches"
    }
    if command not in COMMAND_MAP:
        return jsonify({"success": False, "error": "Invalid command specified."}), 400
    
    node_api_data = get_node(session["token"], node_id)
    if not node_api_data:
        return jsonify({"success": False, "error": "Node not found in panel."}), 404
    
    # Use the reliable helper function here as well
    is_local = is_node_local(node_api_data)

    if is_local and command == 'clear_cache':
        logger.info(f"Executing command '{command}' locally for node '{node_api_data.get('name')}' (ID: {node_id}).")
        shell_command = COMMAND_MAP[command]
        try:
            result = subprocess.run(['sudo', 'sh', '-c', shell_command], capture_output=True, text=True, check=False)
            if result.returncode == 0:
                return jsonify({"success": True, "message": f"Local command '{command}' executed successfully."})
            else:
                return jsonify({"success": False, "error": f"Command failed: {result.stderr.strip()}"}), 500
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    # Fallback to SSH for remote nodes or other commands (like reboot) on any node
    node_db_data = get_installed_node_by_name(node_api_data.get("name"))
    if not node_db_data:
        return jsonify({"success": False, "error": "Cannot execute command: SSH details not found in local database."}), 404

    ssh_ip = node_db_data.get('server_ip')
    ssh_port = int(node_db_data.get('ssh_port'))
    ssh_user = node_db_data.get('ssh_user')
    ssh_pass = node_db_data.get('ssh_password')

    shell_command = COMMAND_MAP[command]
    ssh_client = None
    try:
        logger.info(f"Executing command '{command}' via SSH on node {ssh_ip}.")
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname=ssh_ip, port=ssh_port, username=ssh_user, password=ssh_pass, timeout=10)

        stdin, stdout, stderr = ssh_client.exec_command(shell_command)

        if command == 'reboot':
            logger.info(f"Reboot command sent to {ssh_ip}.")
            return jsonify({"success": True, "message": "Reboot command sent. The server will be unreachable for a few moments."})

        exit_status = stdout.channel.recv_exit_status()
        if exit_status == 0:
            return jsonify({"success": True, "message": f"Command '{command}' executed successfully."})
        else:
            error_output = stderr.read().decode('utf-8').strip()
            return jsonify({"success": False, "error": f"Command failed: {error_output}"}), 500
    except Exception as e:
        logger.error(f"Failed to execute system command '{command}' on {ssh_ip}: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if ssh_client:
            ssh_client.close()
