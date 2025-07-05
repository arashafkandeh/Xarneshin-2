from flask import Blueprint, request, render_template, session, redirect, url_for, jsonify, flash
import logging
import json

from xenon.auth.decorators import login_required
from xenon.xray_config.utils import get_xray_config, update_full_xray_config
# update_full_xray_config takes the complete JSON string for the config.

logger = logging.getLogger(__name__)

# This blueprint is for general Xray config operations like the advanced editor.
# Specific sections (inbounds, outbounds, etc.) have their own blueprint files.
xray_general_bp = Blueprint(
    'xray_general', # Renamed from xray_config_bp to avoid clash with package name
    __name__,
    template_folder='../../templates', # Relative to this file's location
    url_prefix='/node/<int:node_id>'
)

# --- Advanced Editor Routes ---

@xray_general_bp.route("/advance", methods=["GET"]) # Original: /node/<id>/advance
@login_required
def advanced_editor_page(node_id): # Renamed from advanced_editor
    logger.debug(f"Displaying advanced Xray config editor page for node_id: {node_id}")
    config_data_resp = get_xray_config(session["token"], node_id)

    if not config_data_resp or "config" not in config_data_resp:
        flash("Xray config not found or could not be retrieved.", "error")
        # Redirect to a safe page, e.g., node overview or nodes list
        return redirect(url_for("nodes.overview", node_id=node_id, _external=True))

    # The 'config' key in config_data_resp contains the raw Xray config as a JSON string.
    raw_config_json_string = config_data_resp["config"]

    # The template 'advance.html' likely expects this raw string to be embedded
    # in a way that JavaScript can pick it up, possibly already escaped if necessary.
    # Original xenon.py: escaped_config = json.dumps(raw_config)
    # This double-escapes it if raw_config is already a valid JSON string.
    # If raw_config_json_string is indeed the JSON string of the config,
    # it can be passed directly or after validation.
    # For safety, let's ensure it's valid JSON then pass it.
    try:
        json.loads(raw_config_json_string) # Validate it's JSON
    except json.JSONDecodeError:
        flash("The retrieved Xray config is not valid JSON. Cannot display advanced editor.", "error")
        logger.error(f"Advanced editor: Retrieved config for node {node_id} is not valid JSON.")
        return redirect(url_for("nodes.overview", node_id=node_id, _external=True))

    # The template advance.html will receive the raw_config_json_string.
    # It might load this into a textarea or a JS editor.
    # The original code passed `escaped_config = json.dumps(raw_config)`
    # If raw_config (which is raw_config_json_string here) is ALREADY a JSON string,
    # then json.dumps(raw_config_json_string) will make it a JSON string *literal*
    # e.g. "\"{\\\"foo\\\": \\\"bar\\\"}\"" which is what a JS variable would need if assigned like:
    # var configStr = "< અહીં escaped_config قرار می‌گیرد >";
    # So, the original double escaping was likely correct for direct embedding in JS.

    # Pass the already JSON string config_data_resp["config"] to the template.
    # The template's JS will handle parsing this if it's for an editor like Monaco/ACE.
    # If template expects a string literal for JS, then json.dumps(raw_config_json_string) is needed.
    # Assuming template's JS can handle a JSON string directly:
    template_config_str = raw_config_json_string

    # If template's JS expects a string literal (e.g. var x = "...json string...")
    # template_config_str_for_js_literal = json.dumps(raw_config_json_string)

    return render_template("advance.html", node_id=node_id, config_str=template_config_str)


@xray_general_bp.route("/advance_save", methods=["POST"]) # Original: /node/<id>/advance_save
@login_required
def advanced_editor_save_api(node_id): # Renamed from advanced_editor_save
    logger.info(f"API POST request to save full Xray config (advanced editor) for node_id: {node_id}")

    data = request.get_json()
    if data is None or "config" not in data:
        return jsonify({"error": "No 'config' data provided in JSON payload."}), 400

    new_config_json_string = data.get("config")
    if not isinstance(new_config_json_string, str):
        return jsonify({"error": "'config' must be a string containing valid JSON."}), 400

    # Validate if the string is actually JSON before sending to backend util
    try:
        json.loads(new_config_json_string) # This validates the JSON structure
    except json.JSONDecodeError as e:
        logger.error(f"Advanced save: Invalid JSON submitted for node {node_id}. Error: {e}")
        return jsonify({"error": "Invalid JSON format in the 'config' string.", "details": str(e)}), 400

    # update_full_xray_config expects the complete Xray config as a JSON string.
    # It will then wrap it in the {"config": "...", "format": 1} payload for the API.
    if update_full_xray_config(session["token"], node_id, new_config_json_string):
        flash("Full Xray configuration updated successfully via advanced editor.", "success")
        return jsonify({"success": True, "message": "Xray configuration updated successfully."})
    else:
        # update_full_xray_config logs errors internally
        return jsonify({"error": "Failed to update full Xray configuration on server."}), 500

```

**توضیحات و تغییرات کلیدی:**

*   **نام طرح اولیه**: نام طرح اولیه به `xray_general_bp` تغییر یافته است تا از تداخل با نام بسته `xenon.xray_config` جلوگیری شود.
*   **URL Prefix**: تمام مسیرها در این طرح اولیه تحت پیشوند `/node/<int:node_id>/` قرار دارند.
*   **`update_full_xray_config`**: این تابع کمکی از `xenon.xray_config.utils` مسئول دریافت رشته JSON کامل پیکربندی، اعتبارسنجی آن (اختیاری، اما `utils` این کار را انجام می‌دهد) و ارسال آن به API پنل است.
*   **مسیرها**:
    *   `/advance` (GET): صفحه ویرایشگر پیشرفته (`advance.html`) را ارائه می‌دهد. این مسیر پیکربندی فعلی Xray را به عنوان یک رشته JSON واکشی کرده و به قالب ارسال می‌کند.
    *   `/advance_save` (POST): رشته JSON کامل و جدید پیکربندی Xray را از یک بار JSON دریافت کرده و ذخیره می‌کند.
*   **ارسال پیکربندی به قالب**:
    *   کد اصلی (`xenon.py`) از `json.dumps(raw_config)` استفاده می‌کرد که اگر `raw_config` خود یک رشته JSON باشد، آن را به یک رشته JSON تحت اللفظی (double-escaped) تبدیل می‌کند. این برای جاسازی مستقیم در یک متغیر جاوا اسکریپت در قالب HTML صحیح است.
    *   در کد فعلی، `raw_config_json_string` (که همان `config_data_resp["config"]` است) مستقیماً به قالب ارسال می‌شود. اگر قالب `advance.html` از یک ویرایشگر جاوا اسکریپت استفاده می‌کند که می‌تواند یک رشته JSON استاندارد را بارگیری کند، این روش صحیح است. اگر قالب نیاز به یک رشته تحت اللفظی برای جاوا اسکریپت دارد، باید از `json.dumps(raw_config_json_string)` استفاده شود. فرض فعلی این است که قالب می‌تواند رشته JSON استاندارد را مدیریت کند.
*   **اعتبارسنجی JSON**: قبل از ارسال پیکربندی جدید به `update_full_xray_config`، یک اعتبارسنجی اولیه (`json.loads`) روی رشته JSON ورودی انجام می‌شود تا از ارسال داده‌های نامعتبر جلوگیری شود.

این ماژول عملکرد ویرایشگر پیشرفته را پوشش می‌دهد. در ادامه، به سراغ ماژول ابزارها (`tools`) خواهیم رفت.
