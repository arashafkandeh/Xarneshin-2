import logging
import paramiko
import socks # For SOCKS proxy with Paramiko
import socket # For socket errors
import requests # For testing proxy connection to httpbin (or other reliable service)
from requests.utils import quote as urlquote # For quoting proxy username/password

logger = logging.getLogger(__name__)

def perform_full_connection_test(ssh_ip, ssh_port_str, ssh_user, ssh_pass,
                                 use_proxy=False, proxy_ip=None, proxy_port_str=None,
                                 proxy_user=None, proxy_pass=None):
    """
    Performs a two-part test:
    1. (Optional) Test SOCKS5 proxy connection by trying to fetch an external IP.
    2. Test SSH connection to the specified server, potentially through the proxy.

    Returns a dictionary with test results.
    """
    results = {
        "proxy_status": "not_attempted",
        "proxy_message": "Proxy not configured or not used for this test.",
        "proxy_seen_ip": None,
        "ssh_status": "not_attempted",
        "ssh_message": "SSH connection test not initiated."
    }

    # --- Validate Inputs ---
    if not all([ssh_ip, ssh_port_str, ssh_user, ssh_pass]): # ssh_pass can be empty if using key auth (not supported here yet)
        results["ssh_status"] = "failed_input"
        results["ssh_message"] = "Missing required SSH connection details (IP, Port, User, or Password)."
        logger.warning("Full connection test: Missing SSH input.")
        return results

    try:
        ssh_port = int(ssh_port_str)
        if not (1 <= ssh_port <= 65535):
            raise ValueError("SSH port out of range.")
    except ValueError:
        results["ssh_status"] = "failed_input"
        results["ssh_message"] = "Invalid SSH Port number."
        logger.warning(f"Full connection test: Invalid SSH port '{ssh_port_str}'.")
        return results

    proxy_port_int = None
    if use_proxy:
        if not proxy_ip or not proxy_port_str:
            results["proxy_status"] = "failed_input"
            results["proxy_message"] = "Proxy IP and Port are required when 'Use Proxy' is enabled."
            results["ssh_status"] = "skipped" # Skip SSH test if proxy input is bad
            results["ssh_message"] = "SSH test skipped due to proxy input error."
            logger.warning("Full connection test: Proxy enabled but IP/Port missing.")
            return results
        try:
            proxy_port_int = int(proxy_port_str)
            if not (1 <= proxy_port_int <= 65535):
                raise ValueError("Proxy port out of range.")
        except ValueError:
            results["proxy_status"] = "failed_input"
            results["proxy_message"] = "Invalid Proxy Port number."
            results["ssh_status"] = "skipped"
            results["ssh_message"] = "SSH test skipped due to proxy input error."
            logger.warning(f"Full connection test: Invalid Proxy port '{proxy_port_str}'.")
            return results

    # --- 1. Test Proxy Connection (if use_proxy is true) ---
    if use_proxy and proxy_ip and proxy_port_int: # Ensure proxy_port_int is set
        proxy_url_display = f"socks5://{proxy_ip}:{proxy_port_int}"
        proxies_for_requests = {
            "http": f"socks5h://{proxy_ip}:{proxy_port_int}", # socks5h for DNS resolution through proxy
            "https": f"socks5h://{proxy_ip}:{proxy_port_int}"
        }
        if proxy_user:
            auth_str = f"{urlquote(proxy_user)}"
            if proxy_pass: # Password can be empty
                auth_str += f":{urlquote(proxy_pass)}"
            proxies_for_requests["http"] = f"socks5h://{auth_str}@{proxy_ip}:{proxy_port_int}"
            proxies_for_requests["https"] = f"socks5h://{auth_str}@{proxy_ip}:{proxy_port_int}"
            proxy_url_display = f"socks5://{proxy_user}:***@{proxy_ip}:{proxy_port_int}"

        logger.info(f"Testing proxy connection via {proxy_url_display} to https://api.ipify.org?format=json")
        try:
            # Using a simple IP echo service. httpbin.org/ip is also good.
            # Ensure the service is reachable from the environment where this code runs.
            response = requests.get("https://api.ipify.org?format=json", proxies=proxies_for_requests, timeout=15)
            response.raise_for_status() # Check for HTTP errors
            r_json = response.json()
            seen_ip = r_json.get("ip")
            if not seen_ip: # api.ipify.org should always return an IP
                 raise ValueError("IP not found in proxy test response.")

            results["proxy_seen_ip"] = seen_ip
            results["proxy_status"] = "success"
            results["proxy_message"] = f"Proxy connection successful. IP seen by external service: {seen_ip}"
            logger.info(f"Proxy test successful for {proxy_url_display}. Seen IP: {seen_ip}")
        except Exception as e:
            logger.error(f"Proxy connection test failed for {proxy_url_display}: {str(e)}", exc_info=True)
            results["proxy_status"] = "failed"
            results["proxy_message"] = f"Proxy connection error: {str(e)}"
            results["ssh_status"] = "skipped" # Skip SSH if proxy fails
            results["ssh_message"] = "SSH test skipped due to proxy connection failure."
            return results # Return early if proxy test fails

    # --- 2. Test SSH Connection ---
    logger.info(f"Attempting SSH connection to {ssh_user}@{ssh_ip}:{ssh_port}"
                f"{(' via proxy ' + proxy_ip + ':' + str(proxy_port_int)) if use_proxy and results['proxy_status'] == 'success' else ''}")

    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    paramiko_proxy_socket = None
    if use_proxy and results['proxy_status'] == 'success' and proxy_ip and proxy_port_int:
        paramiko_proxy_socket = socks.socksocket()
        paramiko_proxy_socket.set_proxy(
            proxy_type=socks.SOCKS5,
            addr=proxy_ip,
            port=proxy_port_int,
            username=proxy_user if proxy_user else None, # PySocks expects None for no auth
            password=proxy_pass if proxy_pass else None
        )
        try:
            logger.debug(f"Connecting SOCKS proxy socket to SSH target {ssh_ip}:{ssh_port} for Paramiko.")
            paramiko_proxy_socket.connect((ssh_ip, ssh_port))
        except socks.ProxyConnectionError as e:
            logger.error(f"SOCKS proxy connection to SSH host {ssh_ip}:{ssh_port} failed: {e}", exc_info=True)
            results["ssh_status"] = "failed_proxy_connect_to_ssh_host"
            results["ssh_message"] = f"Error connecting SOCKS proxy to SSH host: {str(e)}"
            if paramiko_proxy_socket: paramiko_proxy_socket.close()
            return results
        except Exception as e: # Catch other potential socket errors
            logger.error(f"Unexpected error setting up SOCKS proxy socket for SSH to {ssh_ip}:{ssh_port}: {e}", exc_info=True)
            results["ssh_status"] = "failed_proxy_socket_setup"
            results["ssh_message"] = f"Unexpected SOCKS proxy socket error: {str(e)}"
            if paramiko_proxy_socket: paramiko_proxy_socket.close()
            return results


    try:
        ssh_client.connect(
            hostname=ssh_ip,
            port=ssh_port,
            username=ssh_user,
            password=ssh_pass, # Consider adding key-based auth support later
            sock=paramiko_proxy_socket, # Pass the SOCKS socket here if using proxy
            timeout=20,          # Overall connection timeout
            banner_timeout=20,   # Timeout for SSH banner
            auth_timeout=20      # Timeout for authentication phase
        )
        results["ssh_status"] = "success"
        results["ssh_message"] = "SSH connection and authentication successful."
        logger.info(f"SSH test successful to {ssh_ip}:{ssh_port}.")

        # Optional: execute a simple command to further verify connection
        # stdin, stdout, stderr = ssh_client.exec_command("echo SSH_OK", timeout=5)
        # if "SSH_OK" in stdout.read().decode():
        #     logger.info("SSH command execution verified.")
        # else:
        #     logger.warning("SSH command execution check failed or returned unexpected output.")
        #     results["ssh_message"] += " (Command exec check failed or no output)"


    except paramiko.AuthenticationException:
        results["ssh_status"] = "failed_auth"
        results["ssh_message"] = "SSH Authentication failed. Please check username/password."
        logger.warning(f"SSH test: Authentication failed for {ssh_user}@{ssh_ip}.")
    except paramiko.SSHException as e: # Catches a wide range of Paramiko SSH errors
        results["ssh_status"] = "failed_ssh_protocol"
        results["ssh_message"] = f"SSH protocol error: {str(e)}"
        logger.error(f"SSH test: SSH protocol error for {ssh_ip}: {str(e)}", exc_info=True)
    except socket.timeout: # This can be from the Paramiko connect timeout
        results["ssh_status"] = "failed_timeout"
        results["ssh_message"] = "SSH Connection timed out."
        logger.error(f"SSH test: Connection timed out for {ssh_ip}.")
    except socket.error as e: # Other socket errors (e.g., connection refused)
        results["ssh_status"] = "failed_socket_error"
        results["ssh_message"] = f"Socket error during SSH connection: {str(e)}"
        logger.error(f"SSH test: Socket error for {ssh_ip}: {str(e)}", exc_info=True)
    except Exception as e: # Catch-all for any other unexpected errors during SSH phase
        results["ssh_status"] = "failed_unexpected"
        results["ssh_message"] = f"An unexpected error occurred during SSH connection: {str(e)}"
        logger.error(f"SSH test: Unexpected error for {ssh_ip}: {str(e)}", exc_info=True)
    finally:
        if ssh_client:
            ssh_client.close()
        # paramiko_proxy_socket is closed by Paramiko if passed to connect()
        # but if connect() fails before that, or if it wasn't passed, ensure it's closed.
        if paramiko_proxy_socket and not (ssh_client and ssh_client.get_transport() and ssh_client.get_transport().is_active()):
             paramiko_proxy_socket.close()


    return results
```

**توضیحات:**

*   تابع `perform_full_connection_test` منطق اصلی تست اتصال از `xenon.py` را در بر می‌گیرد.
*   **اعتبارسنجی ورودی**: بررسی‌های اولیه برای پارامترهای ضروری و معتبر بودن پورت‌ها اضافه شده است.
*   **تست پراکسی**:
    *   از `https://api.ipify.org?format=json` برای تست پراکسی استفاده می‌کند که یک سرویس ساده و قابل اعتماد برای دریافت آدرس IP عمومی است. این جایگزین `http://httpbin.org/ip` شده است که گاهی اوقات می‌تواند حساسیت بیشتری نسبت به درخواست‌های خودکار نشان دهد.
    *   از `requests.utils.quote` برای رمزگذاری صحیح نام کاربری و رمز عبور پراکسی در URL استفاده می‌کند.
    *   `socks5h://` برای اطمینان از اینکه DNS از طریق پراکسی انجام می‌شود، استفاده می‌شود.
*   **تست SSH**:
    *   از کتابخانه `paramiko` برای اتصال SSH استفاده می‌کند.
    *   در صورت استفاده از پراکسی، یک سوکت SOCKS با استفاده از کتابخانه `socks` (PySocks) ایجاد کرده و آن را به `paramiko_proxy_socket` ارسال می‌کند.
    *   مدیریت خطاهای دقیق‌تری برای مراحل مختلف اتصال SSH (احراز هویت، خطاهای پروتکل، اتمام زمان، خطاهای سوکت) اضافه شده است.
*   **ثبت وقایع**: ثبت وقایع (Logging) برای اشکال‌زدایی و پیگیری روند تست‌ها و خطاهای احتمالی استفاده می‌شود.
*   **مقادیر بازگشتی**: یک دیکشنری با وضعیت و پیام‌های مربوط به هر دو بخش تست (پراکسی و SSH) برمی‌گرداند.

این ماژول اکنون منطق تست اتصال را به طور مستقل ارائه می‌دهد. در مرحله بعد، `xenon/tools/routes.py` برای ایجاد مسیرهای HTTP برای این ابزارها و ابزارهای `cert_utils` ایجاد خواهد شد.
