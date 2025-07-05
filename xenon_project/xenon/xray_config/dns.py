from flask import Blueprint, request, render_template, session, redirect, url_for, jsonify, flash
import logging
import json

from xenon.auth.decorators import login_required
from xenon.xray_config.utils import get_xray_config, update_xray_dns, filter_empty_dns_fields

logger = logging.getLogger(__name__)

dns_bp = Blueprint(
    'dns',
    __name__,
    template_folder='../../templates',
    url_prefix='/node/<int:node_id>' # All routes will be under /node/<id>/...
)

# --- Helper function from original xenon.py (now in xray_config.utils) ---
# filter_empty_dns_fields is used to clean up the DNS config before saving.

# --- Routes ---
@dns_bp.route("/dns") # Endpoint: /node/<node_id>/dns
@login_required
def dns_settings_page(node_id):
    logger.debug(f"Displaying DNS settings page for node_id: {node_id}")
    config_data_resp = get_xray_config(session["token"], node_id)

    dns_config_to_render = {} # Default empty config for template
    if config_data_resp and "config" in config_data_resp:
        try:
            decoded_config = json.loads(config_data_resp["config"])
            # Extract current DNS config, provide defaults if parts are missing for the template
            current_dns_config = decoded_config.get("dns", {})
            dns_config_to_render = {
                "hosts": current_dns_config.get("hosts", {}),
                "servers": current_dns_config.get("servers", []),
                "clientIp": current_dns_config.get("clientIp", ""),
                "queryStrategy": current_dns_config.get("queryStrategy", "UseIP"),
                "disableCache": current_dns_config.get("disableCache", False),
                "disableFallback": current_dns_config.get("disableFallback", False),
                "disableFallbackIfMatch": current_dns_config.get("disableFallbackIfMatch", False),
                "tag": current_dns_config.get("tag", "")
            }
        except (json.JSONDecodeError, TypeError):
            flash("Error parsing current Xray config to display DNS settings.", "error")
            logger.error(f"Failed to parse Xray config for DNS page, node {node_id}", exc_info=True)
            # Fallback to empty config for rendering, or redirect
    else:
        flash("Failed to retrieve Xray config to display DNS settings.", "warning")

    return render_template("dns.html", node_id=node_id, dns_config=dns_config_to_render)


@dns_bp.route("/api/dns", methods=["GET"]) # Endpoint: /node/<node_id>/api/dns
@login_required
def api_get_dns_config(node_id): # Renamed from api_get_dns for clarity
    logger.debug(f"API GET request for DNS config, node_id: {node_id}")
    config_data_resp = get_xray_config(session["token"], node_id)

    dns_section = {}
    if config_data_resp and "config" in config_data_resp:
        try:
            decoded_config = json.loads(config_data_resp["config"])
            dns_section = decoded_config.get("dns", {})
        except (json.JSONDecodeError, TypeError):
            logger.error(f"API GET DNS: Error parsing Xray config for node {node_id}", exc_info=True)
            return jsonify({"error": "Could not parse current DNS configuration."}), 500
    else:
        logger.warning(f"API GET DNS: Xray config not found or incomplete for node {node_id}.")
        # Return default structure as per original xenon.py if no config or no DNS section

    # Ensure default structure for client-side consistency (from original xenon.py)
    dns_section.setdefault("hosts", {})
    dns_section.setdefault("servers", [])
    dns_section.setdefault("clientIp", "")
    dns_section.setdefault("queryStrategy", "UseIP")
    dns_section.setdefault("disableCache", False)
    dns_section.setdefault("disableFallback", False)
    dns_section.setdefault("disableFallbackIfMatch", False)
    dns_section.setdefault("tag", "")

    return jsonify(dns_section)


@dns_bp.route("/api/dns", methods=["POST"]) # Endpoint: /node/<node_id>/api/dns
@login_required
def api_save_dns_config(node_id): # Renamed from api_save_dns
    logger.info(f"API POST request to save DNS config for node_id: {node_id}")
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided for DNS update."}), 400

    # Construct the new DNS object based on original xenon.py logic
    # This logic takes flat form fields and structures them into the Xray DNS object
    new_dns_object = {}

    # Global DNS settings from form (keys like 'globalClientIp' were from frontend JS)
    if client_ip := data.get("globalClientIp", "").strip(): new_dns_object["clientIp"] = client_ip
    if qs := data.get("globalQueryStrategy", "UseIP").strip(): new_dns_object["queryStrategy"] = qs

    new_dns_object["disableCache"] = bool(data.get("globalDisableCache", False))
    new_dns_object["disableFallback"] = bool(data.get("globalDisableFallback", False))
    new_dns_object["disableFallbackIfMatch"] = bool(data.get("globalDisableFallbackIfMatch", False))

    if dns_tag := data.get("globalDnsTag", "").strip(): new_dns_object["tag"] = dns_tag

    # Hosts block (static hosts)
    # The form was expected to send this as a pre-formatted object if using `dns_config.hosts`
    new_dns_object["hosts"] = data.get("hosts", {})

    # DNS servers array
    # The form was expected to send this as a pre-formatted list of server objects
    servers_list = data.get("servers", [])
    new_dns_object["servers"] = servers_list # Already filtered by filter_empty_dns_fields later

    # Clean the constructed DNS object using the helper
    # The original xenon.py called filter_empty on the final new_dns object.
    # It's better to call it on the parts before assignment or on the final object.
    # For now, replicating original: filter after construction.
    cleaned_new_dns_object = filter_empty_dns_fields(new_dns_object)

    if update_xray_dns(session["token"], node_id, cleaned_new_dns_object):
        # The dns.html page might not show flash messages if it uses JS for save.
        # JSON response is primary for API routes.
        flash("DNS configuration updated successfully.", "success") # For non-JS fallback if any
        return jsonify({"success": True, "message": "DNS configuration updated successfully."})
    else:
        return jsonify({"error": "Failed to update DNS configuration on server."}), 500

```

**توضیحات و تغییرات کلیدی:**

*   **URL Prefix**: تمام مسیرها در این طرح اولیه تحت پیشوند `/node/<int:node_id>/` قرار دارند.
*   **`filter_empty_dns_fields`**: این تابع کمکی که در `xenon.py` اصلی وجود داشت، اکنون از `xenon.xray_config.utils` وارد شده و برای پاکسازی شیء DNS قبل از ذخیره استفاده می‌شود.
*   **مسیرهای API و صفحه HTML**:
    *   `/dns`: صفحه HTML را برای ویرایش تنظیمات DNS ارائه می‌دهد.
    *   `/api/dns` (GET): پیکربندی DNS فعلی را به صورت JSON برمی‌گرداند (احتمالاً توسط جاوا اسکریپت در صفحه HTML استفاده می‌شود).
    *   `/api/dns` (POST): پیکربندی DNS جدید را از یک بار JSON ذخیره می‌کند.
*   **ساختار داده DNS**: منطق ساخت شیء `new_dns_object` از داده‌های JSON ورودی (که احتمالاً توسط جاوا اسکریپت سمت سرویس گیرنده بر اساس یک فرم ساخته شده است) با کد `xenon.py` اصلی مطابقت دارد.
*   **مقادیر پیش‌فرض**: مسیر GET برای `/api/dns` و مسیر نمایش صفحه `/dns` اطمینان حاصل می‌کنند که یک ساختار پیش‌فرض برای DNS به سرویس گیرنده/قالب برگردانده می‌شود، حتی اگر بخش DNS در پیکربندی Xray وجود نداشته باشد. این با رفتار `xenon.py` اصلی سازگار است.

این ماژول اکنون مدیریت تنظیمات DNS را پوشش می‌دهد. در مرحله بعد، ماژول `routing.py` برای قوانین مسیریابی ایجاد خواهد شد.
