from flask import Blueprint, jsonify, request, session # Added session for token access
import subprocess
import re
import datetime
import json
import asyncio
import websockets # For Xray logs
import time
import psutil # For system stats
import logging

from xenon.auth.decorators import login_required
from xenon.config import API_BASE_URL # For Xray log WebSocket URL construction (panel_port needed)

logger = logging.getLogger(__name__)

# Note: url_prefix can be added here if all system_info routes should be under a common path e.g., /system
# Original getinfo.py registered blueprint with url_prefix='/getinfo'
# For consistency, let's keep it if the main app expects it.
system_info_bp = Blueprint('system_info', __name__, url_prefix='/getinfo')


# --- Helper Functions (from original getinfo.py) ---
def _run_command(command_str): # Renamed from run_command to avoid potential clashes
    """Executes a shell command and returns its output or error."""
    try:
        # Using shell=True can be a security risk if command_str is from user input.
        # Here, commands are hardcoded, so it's less of a risk.
        # Consider splitting command_str into a list if shell=False is preferred.
        output = subprocess.check_output(command_str, shell=True, stderr=subprocess.STDOUT, timeout=15)
        return output.decode('utf-8').strip(), None
    except subprocess.CalledProcessError as e:
        logger.warning(f"Command '{command_str}' failed with error: {e.output.decode('utf-8').strip()}")
        return None, e.output.decode('utf-8').strip()
    except subprocess.TimeoutExpired:
        logger.warning(f"Command '{command_str}' timed out.")
        return None, "Command timed out"
    except Exception as e:
        logger.error(f"Unexpected error running command '{command_str}': {e}", exc_info=True)
        return None, str(e)

def _format_timedelta(td_object): # Renamed from format_timedelta
    """Formats a timedelta object into a human-readable string."""
    total_seconds = int(td_object.total_seconds())
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)

    parts = []
    if days > 0: parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours > 0: parts.append(f"{hours} hr{'s' if hours != 1 else ''}")
    if minutes > 0: parts.append(f"{minutes} min{'s' if minutes != 1 else ''}")
    # Always show seconds, even if 0 and other parts are present, or if it's the only unit.
    if seconds >= 0 or not parts : parts.append(f"{seconds} s")
    return " ".join(parts) if parts else "0 s"


async def _get_latest_xray_started_log(websocket_uri, timeout_seconds=5): # Renamed
    """Connects to Xray logs WebSocket and extracts the latest startup timestamp."""
    latest_startup_message = None
    try:
        logger.debug(f"Connecting to Xray log WebSocket: {websocket_uri}")
        async with websockets.connect(websocket_uri, open_timeout=timeout_seconds) as websocket:
            # Try to receive a few messages to find a startup message.
            # This might need adjustment based on how verbose the logs are.
            # Original code had a while True loop with a timeout on recv.
            # This version tries for a limited time or number of messages.
            for _ in range(20): # Try to get up to 20 messages or until timeout
                try:
                    message_str = await asyncio.wait_for(websocket.recv(), timeout=1) # Short timeout per message
                    if "Xray" in message_str and "started" in message_str:
                        latest_startup_message = message_str
                        # Don't break, continue to see if a more recent "started" message appears quickly
                except asyncio.TimeoutError: # Timeout waiting for a single message
                    break # Stop if no message received for a bit
                except websockets.exceptions.ConnectionClosed:
                    logger.warning("WebSocket connection closed while receiving Xray logs.")
                    break
            if latest_startup_message:
                 logger.info(f"Found Xray startup message: {latest_startup_message[:100]}...")
            else:
                 logger.warning("No Xray startup message found in received logs.")
    except asyncio.TimeoutError: # Timeout for the initial connection
        logger.error(f"Timeout connecting to Xray log WebSocket: {websocket_uri}")
    except websockets.exceptions.InvalidURI:
        logger.error(f"Invalid URI for Xray log WebSocket: {websocket_uri}")
    except Exception as e:
        logger.error(f"Error with Xray log WebSocket {websocket_uri}: {e}", exc_info=True)
    return latest_startup_message

# --- Routes ---

@system_info_bp.route('/container/<container_name>/uptime', methods=['GET'])
@login_required # Assuming these info endpoints also require login
def get_container_uptime(container_name): # Renamed
    # Basic security check for container_name to prevent command injection if it were dynamic
    # For now, assuming container_name is from a controlled list.
    if not re.match(r'^[\w-]+$', container_name): # Allow word chars and hyphens
        return jsonify({"error": "Invalid container name format."}), 400

    logger.debug(f"Request for uptime of container: {container_name}")
    command = f"docker inspect --format='{{{{.State.StartedAt}}}}' {container_name}"
    output, error = _run_command(command)

    if error:
        return jsonify({"error": f"Error getting uptime for container '{container_name}': {error}"}), 500
    if not output:
        return jsonify({"error": f"No start time found for container '{container_name}'."}), 404

    try:
        # Docker's StartedAt format: "YYYY-MM-DDTHH:MM:SS.sssssssssZ"
        started_at_str = output.strip("'\"") # Remove potential quotes
        # Handle nanoseconds and 'Z' (UTC)
        if '.' in started_at_str:
            timestamp_part, subsecond_part = started_at_str.split('.', 1)
            subsecond_part = subsecond_part.rstrip('Z')
            # Truncate or round nanoseconds to microseconds for datetime compatibility
            subsecond_part = subsecond_part[:6]
            started_at_str_formatted = f"{timestamp_part}.{subsecond_part}"
        else:
            started_at_str_formatted = started_at_str.rstrip('Z')

        started_at_dt = datetime.datetime.fromisoformat(started_at_str_formatted)
        # If StartedAt does not include timezone info (no Z and no offset), assume UTC as Docker typically uses.
        # If fromisoformat doesn't yield a timezone-aware object, make it UTC.
        if started_at_dt.tzinfo is None:
            started_at_dt = started_at_dt.replace(tzinfo=datetime.timezone.utc)

        now_utc = datetime.datetime.now(datetime.timezone.utc)
        uptime_delta = now_utc - started_at_dt

        return jsonify({
            "container": container_name,
            "started_at_raw": output, # Original raw output
            "started_at_iso": started_at_dt.isoformat(),
            "uptime_seconds": int(uptime_delta.total_seconds()),
            "uptime_formatted": _format_timedelta(uptime_delta)
        })
    except Exception as e:
        logger.error(f"Error parsing start time for container {container_name}: {e}. Raw: '{output}'", exc_info=True)
        return jsonify({"error": f"Could not parse container start time: {str(e)}"}), 500


@system_info_bp.route('/full-uptime', methods=['GET'])
@login_required
def get_full_marzneshin_uptime(): # Renamed
    logger.debug("Request for full Marzneshin stack uptime.")
    # Standard Marzneshin container names
    container_names = ["marzneshin-marznode-1", "marzneshin-marzneshin-1", "marzneshin-db-1"] # As per original
    earliest_start_time = None

    for name in container_names:
        command = f"docker inspect --format='{{{{.State.StartedAt}}}}' {name}"
        output, error = _run_command(command)
        if error or not output:
            logger.warning(f"Could not get start time for container {name} for full uptime calc.")
            continue
        try:
            started_at_str = output.strip("'\"")
            if '.' in started_at_str:
                timestamp_part, subsecond_part = started_at_str.split('.', 1)
                subsecond_part = subsecond_part.rstrip('Z')[:6]
                started_at_str_formatted = f"{timestamp_part}.{subsecond_part}"
            else:
                started_at_str_formatted = started_at_str.rstrip('Z')

            current_container_start_dt = datetime.datetime.fromisoformat(started_at_str_formatted)
            if current_container_start_dt.tzinfo is None:
                 current_container_start_dt = current_container_start_dt.replace(tzinfo=datetime.timezone.utc)

            if earliest_start_time is None or current_container_start_dt < earliest_start_time:
                earliest_start_time = current_container_start_dt
        except Exception as e:
            logger.error(f"Error parsing start time for {name} during full uptime calc: {e}", exc_info=True)
            continue # Skip this container if its time can't be parsed

    if not earliest_start_time:
        return jsonify({
            "error": "Could not determine earliest start time for Marzneshin stack.",
            "earliest_start_iso": None,
            "full_uptime_seconds": 0,
            "full_uptime_formatted": "0 s"
        }), 404

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    full_uptime_delta = now_utc - earliest_start_time

    return jsonify({
        "earliest_start_iso": earliest_start_time.isoformat(),
        "full_uptime_seconds": int(full_uptime_delta.total_seconds()),
        "full_uptime_formatted": _format_timedelta(full_uptime_delta)
    })


@system_info_bp.route('/xray-uptime', methods=['GET'])
@login_required
def get_xray_core_uptime(): # Renamed
    logger.debug("Request for Xray core uptime.")
    node_id = request.args.get("node_id", "1") # Default to node 1 if not specified
    user_token = session.get("token")
    if not user_token: # Should be caught by @login_required, but good practice
        return jsonify({"error": "Authentication token not found."}), 401

    # Construct WebSocket URL for Xray logs based on panel's port (from config)
    # Assuming panel runs on 127.0.0.1 relative to this app.
    # The API_BASE_URL uses http(s)://127.0.0.1:PANEL_PORT/api
    # So, the WebSocket URL should be ws(s)://127.0.0.1:PANEL_PORT/api/...
    # Original xenon.py: ws_uri = f"ws://127.0.0.1:8000/api/nodes/{node_id}/xray/logs?interval=1&token={token}"
    # This needs the actual panel_port, not FLASK_PORT.
    # And needs to respect PANEL_USE_HTTPS for ws vs wss.

    # We need panel_port and panel_use_https from config
    from xenon.config import PANEL_PORT, PANEL_USE_HTTPS
    ws_protocol = "wss" if PANEL_USE_HTTPS else "ws"
    ws_uri = f"{ws_protocol}://127.0.0.1:{PANEL_PORT}/api/nodes/{node_id}/xray/logs?interval=1&token={user_token}"

    try:
        latest_message = asyncio.run(_get_latest_xray_started_log(ws_uri))
        if not latest_message:
            return jsonify({"error": "No Xray startup message found via WebSocket or WebSocket failed."}), 500

        # Regex from original: r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+).*Xray.*started'
        # This regex assumes a specific log format.
        match = re.search(r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+).*Xray.*started', latest_message, re.IGNORECASE)
        if not match:
            logger.warning(f"Could not parse timestamp from Xray startup message: {latest_message[:100]}...")
            return jsonify({"error": "Could not parse timestamp from Xray startup message."}), 500

        timestamp_str = match.group(1)
        # Original format: "%Y/%m/%d %H:%M:%S.%f"
        # Ensure the parsed datetime is timezone-aware (assume UTC if not specified by log)
        core_start_dt = datetime.datetime.strptime(timestamp_str, "%Y/%m/%d %H:%M:%S.%f")
        core_start_dt_utc = core_start_dt.replace(tzinfo=datetime.timezone.utc) # Assume logs are in UTC

        now_utc = datetime.datetime.now(datetime.timezone.utc)
        uptime_delta = now_utc - core_start_dt_utc

        return jsonify({
            "xray_start_log_timestamp": timestamp_str,
            "xray_start_iso": core_start_dt_utc.isoformat(),
            "xray_uptime_seconds": int(uptime_delta.total_seconds()),
            "xray_uptime_formatted": _format_timedelta(uptime_delta)
        })
    except Exception as e:
        logger.error(f"Error getting Xray uptime via WebSocket: {e}", exc_info=True)
        return jsonify({"error": f"Could not determine Xray uptime: {str(e)}"}), 500


@system_info_bp.route('/system-usage', methods=['GET'])
@login_required
def get_system_usage(): # Renamed
    logger.debug("Request for system resource usage.")
    try:
        cpu_percent = psutil.cpu_percent(interval=0.5) # Non-blocking, short interval
        memory_info = psutil.virtual_memory()
        swap_info = psutil.swap_memory()
        disk_info = psutil.disk_usage('/')

        return jsonify({
            "cpu_percent": cpu_percent,
            "memory_percent": memory_info.percent,
            "memory_total_gb": round(memory_info.total / (1024**3), 2),
            "memory_used_gb": round(memory_info.used / (1024**3), 2),
            "swap_percent": swap_info.percent,
            "swap_total_gb": round(swap_info.total / (1024**3), 2),
            "swap_used_gb": round(swap_info.used / (1024**3), 2),
            "disk_percent": disk_info.percent,
            "disk_total_gb": round(disk_info.total / (1024**3), 2),
            "disk_used_gb": round(disk_info.used / (1024**3), 2),
        })
    except Exception as e:
        logger.error(f"Error getting system usage: {e}", exc_info=True)
        return jsonify({"error": f"Could not retrieve system usage: {str(e)}"}), 500


@system_info_bp.route('/os-uptime', methods=['GET'])
@login_required
def get_os_uptime(): # Renamed
    logger.debug("Request for OS uptime.")
    try:
        boot_timestamp = psutil.boot_time()
        boot_dt = datetime.datetime.fromtimestamp(boot_timestamp, tz=datetime.timezone.utc)
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        uptime_delta = now_utc - boot_dt

        return jsonify({
            "os_boot_time_iso": boot_dt.isoformat(),
            "os_uptime_seconds": int(uptime_delta.total_seconds()),
            "os_uptime_formatted": _format_timedelta(uptime_delta)
        })
    except Exception as e:
        logger.error(f"Error getting OS uptime: {e}", exc_info=True)
        return jsonify({"error": f"Could not retrieve OS uptime: {str(e)}"}), 500


@system_info_bp.route('/network-stats', methods=['GET'])
@login_required
def get_network_stats(): # Renamed
    logger.debug("Request for network statistics.")
    try:
        # Get initial IO counters
        # net_io_initial = psutil.net_io_counters()
        # time.sleep(1) # Wait for 1 second to calculate speed (original logic)
        # net_io_final = psutil.net_io_counters()

        # upload_speed_bps = (net_io_final.bytes_sent - net_io_initial.bytes_sent) * 8 # bits per second
        # download_speed_bps = (net_io_final.bytes_recv - net_io_initial.bytes_recv) * 8 # bits per second

        # Simpler approach: get current totals, speed calculation is tricky without persistent state or longer sampling.
        # The original 1-second sample might be too short / bursty.
        # For now, returning totals and connection counts. Speed can be a TODO if precise measurement is needed.

        current_net_io = psutil.net_io_counters()
        tcp_connections = len(psutil.net_connections(kind='tcp'))
        udp_connections = len(psutil.net_connections(kind='udp'))

        # Get primary global IPs (best effort, might fail in some environments)
        ipv4, ipv4_error = _run_command("curl -4 -s --max-time 5 ifconfig.me || ip -4 addr show scope global | grep inet | awk '{print $2}' | cut -d/ -f1 | head -n1")
        ipv6, ipv6_error = _run_command("curl -6 -s --max-time 5 ifconfig.me || ip -6 addr show scope global | grep inet6 | awk '{print $2}' | cut -d/ -f1 | head -n1")

        if ipv4_error and not ipv4 : ipv4 = "N/A" # If command fails and output is empty
        if ipv6_error and not ipv6 : ipv6 = "N/A"

        return jsonify({
            # "upload_speed_bps": upload_speed_bps, # Removed for now, needs better sampling
            # "download_speed_bps": download_speed_bps, # Removed for now
            "total_bytes_sent": current_net_io.bytes_sent,
            "total_bytes_recv": current_net_io.bytes_recv,
            "total_packets_sent": current_net_io.packets_sent,
            "total_packets_recv": current_net_io.packets_recv,
            "tcp_connections": tcp_connections,
            "udp_connections": udp_connections,
            "primary_ipv4": ipv4.split('\n')[0] if ipv4 else "N/A", # Take first line if multiple
            "primary_ipv6": ipv6.split('\n')[0] if ipv6 else "N/A"  # Take first line
        })
    except Exception as e:
        logger.error(f"Error getting network stats: {e}", exc_info=True)
        return jsonify({"error": f"Could not retrieve network stats: {str(e)}"}), 500


@system_info_bp.route('/container/<container_name>/restart', methods=['POST'])
@login_required
def restart_docker_container(container_name): # Renamed
    if not re.match(r'^[\w-]+$', container_name):
        return jsonify({"error": "Invalid container name format."}), 400

    logger.info(f"Request to restart container: {container_name}")
    command = f"docker restart {container_name}"
    output, error = _run_command(command)

    if error:
        # Docker restart usually outputs container name on success, or error message on failure.
        # If 'error' has content, it's likely the error message from docker.
        return jsonify({"error": f"Error restarting container '{container_name}': {error}", "details": output or error}), 500

    return jsonify({
        "message": f"Container '{container_name}' restart command issued.",
        "output": output # Usually the container name or ID
    })


@system_info_bp.route('/full-restart', methods=['POST'])
@login_required
def full_marzneshin_restart(): # Renamed
    logger.info("Request for full Marzneshin stack restart.")
    # Command from original getinfo.py
    # This assumes 'marzneshin' command is available and in PATH.
    command = "marzneshin restart"
    output, error = _run_command(command) # This will block until 'marzneshin restart' completes.

    if error:
        # 'marzneshin restart' might output to stderr even on success for some phases.
        # Check output for confirmation if error is ambiguous.
        # For now, if 'error' (which is stderr from _run_command) exists, report it.
        logger.error(f"Error during 'marzneshin restart': {error}. Output: {output}")
        return jsonify({"error": f"Error during full Marzneshin restart: {error}", "details": output}), 500

    # Original getinfo.py had a check for Uvicorn running log.
    # This is good for ensuring the panel is back up.
    # This check might take time.
    uvicorn_check_container = "marzneshin-marzneshin-1" # Standard name
    uvicorn_log_pattern = r"Uvicorn running on http[s]?://0\.0\.0\.0:\d+" # More generic
    timeout_seconds = 90 # Increased timeout for full stack restart + log check
    check_interval_seconds = 3
    start_time = time.time()
    uvicorn_ready = False

    logger.info("Marzneshin restart command issued. Waiting for Uvicorn confirmation...")
    while time.time() - start_time < timeout_seconds:
        logs_cmd = f"docker logs {uvicorn_check_container} --tail 50" # Check recent logs
        container_logs, logs_err = _run_command(logs_cmd)
        if logs_err and "No such container" in logs_err: # Container might not be up yet
             logger.debug(f"Container {uvicorn_check_container} not found yet, retrying...")
        elif container_logs and re.search(uvicorn_log_pattern, container_logs, re.IGNORECASE):
            uvicorn_ready = True
            logger.info("Uvicorn startup confirmed in Marzneshin container logs.")
            break
        time.sleep(check_interval_seconds)

    if not uvicorn_ready:
        logger.warning(f"Full Marzneshin restart: Uvicorn startup not confirmed in logs after {timeout_seconds}s.")
        # Return success for the restart command itself, but with a warning.
        return jsonify({
            "message": "Full Marzneshin stack restart command issued, but Uvicorn startup could not be confirmed within timeout.",
            "output_from_restart_command": output,
            "warning": "Panel readiness check timed out."
        }), 202 # Accepted, but outcome of panel readiness unknown

    return jsonify({
        "message": "Full Marzneshin stack restarted successfully and panel is responsive.",
        "output_from_restart_command": output
    })

```

**توضیحات و تغییرات کلیدی:**

*   **نام طرح اولیه و پیشوند URL**: طرح اولیه `system_info_bp` با پیشوند URL `/getinfo` ایجاد شده است تا با `assets/getinfo.py` اصلی سازگار باشد.
*   **توابع کمکی**: توابع کمکی `_run_command` و `_format_timedelta` از `assets/getinfo.py` اصلی منتقل و برای جلوگیری از تداخل احتمالی، تغییر نام داده شده‌اند. تابع `_get_latest_xray_started_log` برای واکشی گزارش‌های Xray از طریق WebSocket نیز منتقل شده است.
*   **مسیرها**: تمام مسیرهای موجود در `assets/getinfo.py` به این طرح اولیه منتقل شده‌اند و نام توابع آنها برای وضوح بیشتر تغییر یافته است (مثلاً `container_uptime` به `get_container_uptime`).
*   **`@login_required`**: این دکوراتور به مسیرها اضافه شده است، با فرض اینکه این نقاط پایانی اطلاعاتی نیاز به احراز هویت دارند.
*   **مدیریت خطا و ثبت وقایع**: مدیریت خطای بهتری برای اجرای دستورات، تجزیه خروجی‌ها و عملیات شبکه اضافه شده است. همچنین از ماژول `logging` برای ثبت اطلاعات و خطاها استفاده می‌شود.
*   **زمان‌های UTC**: در محاسبات مربوط به زمان آپتایم، از شیءهای `datetime` آگاه از منطقه زمانی (UTC) استفاده شده است تا از بروز خطا در اثر تفاوت‌های منطقه زمانی جلوگیری شود.
*   **واکشی IP**: دستورات واکشی IP در `get_network_stats` کمی بهبود یافته‌اند تا در صورت عدم موفقیت `curl ifconfig.me`، از دستورات `ip addr` به عنوان جایگزین استفاده کنند.
*   **بررسی Uvicorn**: در مسیر `full_marzneshin_restart`، پس از اجرای دستور `marzneshin restart`، یک حلقه برای بررسی گزارش‌های کانتینر `marzneshin-marzneshin-1` و اطمینان از اجرای موفقیت‌آمیز Uvicorn (نشان‌دهنده آمادگی پنل) اضافه شده است. این با مهلت زمانی مشخصی انجام می‌شود.
*   **وابستگی به `xenon.config`**: مسیر `get_xray_core_uptime` برای ساخت URL وب‌سوکت گزارش‌های Xray، به `PANEL_PORT` و `PANEL_USE_HTTPS` از `xenon.config` نیاز دارد.

این ماژول اکنون عملکرد `assets/getinfo.py` را به طور کامل پوشش می‌دهد. در مرحله بعد، فایل اصلی برنامه `xenon/app.py` ایجاد و طرح‌های اولیه ثبت خواهند شد. همچنین، دکوراتور `@login_required` ایجاد خواهد شد.
