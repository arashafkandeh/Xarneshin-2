from flask import Blueprint, request, render_template, session, redirect, url_for, jsonify, flash
import logging
import json

from xenon.auth.decorators import login_required
from xenon.xray_config.utils import get_xray_config, update_xray_routing_rules
# update_xray_routing_rules will handle placing the rules array into config.routing.rules

logger = logging.getLogger(__name__)

routing_bp = Blueprint(
    'routing',
    __name__,
    template_folder='../../templates',
    url_prefix='/node/<int:node_id>'
)

# --- Routes ---

@routing_bp.route("/rules") # Original was /node/<id>/rules, matches prefix
@login_required
def rules_view_page(node_id): # Renamed from rules_view to avoid conflict if rules becomes a var
    logger.debug(f"Displaying rules page for node_id: {node_id}")
    config_data_resp = get_xray_config(session["token"], node_id)

    existing_rules_list = []
    # Tags for dropdowns in the template (from original xenon.py)
    # These should ideally be fetched dynamically.
    # For now, keeping the mock structure if dynamic fetching is complex.
    # In a real app, these would come from parsing the current config's inbounds, outbounds, balancers.

    # Placeholder for dynamic tag fetching logic
    inbound_tags_list = []
    outbound_tags_list = []
    balancer_tags_list = []

    if config_data_resp and "config" in config_data_resp:
        try:
            decoded_config = json.loads(config_data_resp["config"])
            if "routing" in decoded_config and "rules" in decoded_config["routing"]:
                existing_rules_list = decoded_config["routing"]["rules"]

            # Dynamically populate tags
            inbound_tags_list = [ib.get("tag") for ib in decoded_config.get("inbounds", []) if ib.get("tag")]
            outbound_tags_list = [ob.get("tag") for ob in decoded_config.get("outbounds", []) if ob.get("tag")]
            if "routing" in decoded_config and "balancers" in decoded_config["routing"]:
                 balancer_tags_list = [b.get("tag") for b in decoded_config["routing"].get("balancers", []) if b.get("tag")]

        except (json.JSONDecodeError, TypeError):
            flash("Error parsing Xray config to display routing rules.", "error")
            logger.error(f"Failed to parse Xray config for rules page, node {node_id}", exc_info=True)
    else:
        flash("Failed to retrieve Xray config to display routing rules.", "warning")

    return render_template(
        "rules.html",
        node_id=node_id,
        rules=existing_rules_list, # Pass the actual rules
        # Passing tags for the UI to build rules
        inbound_tags=inbound_tags_list,
        outbound_tags=outbound_tags_list,
        balancer_tags=balancer_tags_list
    )

@routing_bp.route("/rules_data") # Original: /node/<id>/rules_data
@login_required
def get_rules_data_api(node_id): # Renamed from rules_data
    logger.debug(f"API GET request for rules data, node_id: {node_id}")
    config_data_resp = get_xray_config(session["token"], node_id)

    rules_list_for_api = []
    if config_data_resp and "config" in config_data_resp:
        try:
            decoded_config = json.loads(config_data_resp["config"])
            if "routing" in decoded_config and "rules" in decoded_config["routing"]:
                rules_list_for_api = decoded_config["routing"]["rules"]
        except (json.JSONDecodeError, TypeError):
            logger.error(f"API GET rules: Error parsing Xray config for node {node_id}", exc_info=True)
            return jsonify({"error": "Could not parse current routing rules."}), 500
    else:
        logger.warning(f"API GET rules: Xray config not found or incomplete for node {node_id}.")
        # Return empty list if no config or no rules section

    return jsonify({"rules": rules_list_for_api})


@routing_bp.route("/save_rules", methods=["POST"]) # Original: /node/<id>/save_rules
@login_required
def save_rules_api(node_id): # Renamed from save_rules
    logger.info(f"API POST request to save routing rules for node_id: {node_id}")

    # The frontend (rules.html) is expected to send the entire new rules array.
    # Original xenon.py: new_rules = request.get_json().get("rules")
    data = request.get_json()
    if data is None or "rules" not in data: # Check if data itself is None
        return jsonify({"error": "No rules data provided or invalid JSON payload."}), 400

    new_rules_list = data.get("rules")
    if not isinstance(new_rules_list, list):
        return jsonify({"error": "'rules' must be a list."}), 400

    # The update_xray_routing_rules utility function handles fetching the current config,
    # placing the new_rules_list into the correct place (config.routing.rules),
    # and PUTting the entire modified config back.
    if update_xray_routing_rules(session["token"], node_id, new_rules_list):
        # Flash message might not be visible if page uses JS for saving.
        flash("Routing rules updated successfully.", "success")
        return jsonify({"success": True, "message": "Routing rules updated successfully."})
    else:
        return jsonify({"error": "Failed to update routing rules on server."}), 500


@routing_bp.route("/tags") # Original: /node/<id>/tags
@login_required
def get_all_tags_api(node_id): # Renamed from get_tags
    """
    Provides a list of available inbound, outbound, and balancer tags.
    Useful for populating dropdowns in the UI when creating/editing rules.
    """
    logger.debug(f"API GET request for all tags, node_id: {node_id}")
    config_data_resp = get_xray_config(session["token"], node_id)

    inbound_tags_list = []
    outbound_tags_list = []
    balancer_tags_list = []

    if config_data_resp and "config" in config_data_resp:
        try:
            decoded_config = json.loads(config_data_resp["config"])

            # Extract inbound tags
            if "inbounds" in decoded_config:
                inbound_tags_list = [ib.get("tag") for ib in decoded_config["inbounds"] if ib.get("tag")]

            # Extract outbound tags
            if "outbounds" in decoded_config:
                outbound_tags_list = [ob.get("tag") for ob in decoded_config["outbounds"] if ob.get("tag")]

            # Extract balancer tags
            if "routing" in decoded_config and "balancers" in decoded_config["routing"]:
                balancer_tags_list = [b.get("tag") for b in decoded_config["routing"].get("balancers", []) if b.get("tag")]

        except (json.JSONDecodeError, TypeError):
            logger.error(f"API GET tags: Error parsing Xray config for node {node_id}", exc_info=True)
            return jsonify({"error": "Could not parse config to retrieve tags."}), 500
    else:
        logger.warning(f"API GET tags: Xray config not found or incomplete for node {node_id}.")
        # Return empty lists if no config

    return jsonify({
        "inbound_tags": sorted(list(set(inbound_tags_list))), # Ensure unique and sorted
        "outbound_tags": sorted(list(set(outbound_tags_list))),
        "balancer_tags": sorted(list(set(balancer_tags_list)))
    })

```

**توضیحات و تغییرات کلیدی:**

*   **URL Prefix**: تمام مسیرها در این طرح اولیه تحت پیشوند `/node/<int:node_id>/` قرار دارند.
*   **`update_xray_routing_rules`**: این تابع کمکی از `xenon.xray_config.utils` مسئول دریافت پیکربندی فعلی، قرار دادن آرایه قوانین جدید در مکان صحیح (`config.routing.rules`) و ارسال کل پیکربندی اصلاح شده به سرور است.
*   **مسیرها**:
    *   `/rules`: صفحه HTML را برای مشاهده و ویرایش قوانین مسیریابی ارائه می‌دهد. این صفحه همچنین لیست تگ‌های ورودی، خروجی و متعادل‌کننده را برای استفاده در UI دریافت می‌کند.
    *   `/rules_data` (GET): آرایه قوانین مسیریابی فعلی را به صورت JSON برمی‌گرداند (احتمالاً برای بارگیری اولیه توسط جاوا اسکریپت در صفحه rules.html).
    *   `/save_rules` (POST): آرایه جدید قوانین مسیریابی را از یک بار JSON دریافت کرده و ذخیره می‌کند.
    *   `/tags` (GET): لیستی از تمام تگ‌های ورودی، خروجی و متعادل‌کننده موجود را به صورت JSON برمی‌گرداند. این برای پر کردن لیست‌های کشویی در UI هنگام ایجاد/ویرایش قوانین مفید است.
*   **واکشی تگ‌ها**: مسیر `/rules` (صفحه HTML) و مسیر `/tags` (API) اکنون به صورت پویا تگ‌ها را از پیکربندی فعلی Xray واکشی می‌کنند به جای استفاده از داده‌های ساختگی.
*   **نامگذاری توابع**: برخی از نام‌های توابع برای جلوگیری از تداخل احتمالی با متغیرها یا کلمات کلیدی تغییر یافته‌اند (مثلاً `rules_view_page` به جای `rules_view`).

این ماژول اکنون مسئولیت مدیریت قوانین مسیریابی را بر عهده دارد. در ادامه، ماژول `balancers.py` ایجاد خواهد شد.
