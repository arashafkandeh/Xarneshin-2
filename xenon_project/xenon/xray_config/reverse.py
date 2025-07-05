from flask import Blueprint, request, render_template, session, redirect, url_for, jsonify, flash
import logging
import json

from xenon.auth.decorators import login_required
from xenon.xray_config.utils import get_xray_config, update_xray_reverse_config
# update_xray_reverse_config handles the 'reverse' section and related 'routing.rules'

logger = logging.getLogger(__name__)

reverse_bp = Blueprint(
    'reverse',
    __name__,
    template_folder='../../templates',
    url_prefix='/node/<int:node_id>' # All routes under /node/<id>/...
)

# --- Routes ---

@reverse_bp.route("/reverse") # Original: /node/<id>/reverse
@login_required
def reverse_settings_page(node_id): # Renamed from reverse_settings
    logger.debug(f"Displaying reverse proxy settings page for node_id: {node_id}")
    config_data_resp = get_xray_config(session["token"], node_id)

    reverse_config_data = {"bridges": [], "portals": []} # Default empty structure
    inbound_tags_list = []
    outbound_tags_list = []
    # Routing rules are also relevant as reverse often adds specific rules
    routing_rules_list = []

    if config_data_resp and "config" in config_data_resp:
        try:
            decoded_config = json.loads(config_data_resp["config"])

            reverse_config_data = decoded_config.get("reverse", {"bridges": [], "portals": []})

            # Get tags for UI selection (as per original xenon.py)
            inbound_tags_list = [ib.get("tag") for ib in decoded_config.get("inbounds", []) if ib.get("tag")]
            outbound_tags_list = [ob.get("tag") for ob in decoded_config.get("outbounds", []) if ob.get("tag")]

            # Get current routing rules
            routing_rules_list = decoded_config.get("routing", {}).get("rules", [])

        except (json.JSONDecodeError, TypeError):
            flash("Error parsing Xray config to display reverse settings.", "error")
            logger.error(f"Failed to parse Xray config for reverse page, node {node_id}", exc_info=True)
    else:
        flash("Failed to retrieve Xray config to display reverse settings.", "warning")

    return render_template(
        "reverse.html",
        node_id=node_id,
        reverse_config=json.dumps(reverse_config_data), # Pass as JSON string for JS frontend
        inbound_tags=inbound_tags_list, # Pass lists directly
        outbound_tags=outbound_tags_list,
        routing_rules=routing_rules_list # Pass current rules for context if needed by template
    )

@reverse_bp.route("/save_reverse", methods=["POST"]) # Original: /node/<id>/save_reverse
@login_required
def save_reverse_api(node_id): # Renamed from save_reverse
    logger.info(f"API POST request to save reverse proxy settings for node_id: {node_id}")

    data = request.get_json()
    if data is None:
        return jsonify({"error": "No JSON data provided."}), 400

    # Expected payload structure from original xenon.py:
    # {
    #   "reverse": {"bridges": [...], "portals": [...]}, (can be null or empty to remove section)
    #   "newRules": [...], (optional, rules to add for this reverse setup)
    #   "rulesToRemove": [...] (optional, tags of rules to remove that were related to old reverse setup)
    # }
    new_reverse_object = data.get("reverse", {"bridges": [], "portals": []}) # Default to empty if not provided
    new_routing_rules_to_add = data.get("newRules", [])
    tags_of_rules_to_remove = data.get("rulesToRemove", [])

    # The utility function update_xray_reverse_config will:
    # 1. Fetch current config.
    # 2. Update or remove the 'reverse' section based on new_reverse_object.
    # 3. Modify 'routing.rules':
    #    - Remove rules containing any tag from 'tags_of_rules_to_remove'.
    #    - Append rules from 'new_routing_rules_to_add'.
    # 4. PUT the modified config.

    if update_xray_reverse_config(
        session["token"],
        node_id,
        new_reverse_object, # The new reverse object (or None to delete the section)
        new_rules=new_routing_rules_to_add,
        rules_tags_to_remove=tags_of_rules_to_remove
    ):
        flash("Reverse proxy settings updated successfully.", "success") # For non-JS fallback
        return jsonify({"success": True, "message": "Reverse settings updated successfully."})
    else:
        return jsonify({"error": "Failed to update reverse settings on server."}), 500

```

**توضیحات و تغییرات کلیدی:**

*   **URL Prefix**: تمام مسیرها در این طرح اولیه تحت پیشوند `/node/<int:node_id>/` قرار دارند.
*   **`update_xray_reverse_config`**: این تابع کمکی از `xenon.xray_config.utils` مسئولیت اصلی به‌روزرسانی پیکربندی را بر عهده دارد. این تابع نه تنها بخش `reverse` را مدیریت می‌کند، بلکه قوانین مسیریابی مرتبط را نیز بر اساس `newRules` (قوانین جدید برای افزودن) و `rulesToRemove` (تگ‌های قوانینی که باید حذف شوند) اصلاح می‌کند.
*   **مسیرها**:
    *   `/reverse`: صفحه HTML را برای مشاهده و ویرایش تنظیمات پراکسی معکوس ارائه می‌دهد. این صفحه همچنین لیست تگ‌های ورودی و خروجی موجود و قوانین مسیریابی فعلی را برای استفاده در UI دریافت می‌کند.
    *   `/save_reverse` (POST): شیء پیکربندی معکوس جدید، به همراه هرگونه قانون مسیریابی جدید برای افزودن و لیستی از تگ‌های قوانین مسیریابی برای حذف را از یک بار JSON دریافت کرده و ذخیره می‌کند.
*   **ساختار بار JSON**: مسیر `/save_reverse` انتظار دارد که بار JSON ورودی ساختاری مشابه آنچه در `xenon.py` اصلی استفاده می‌شد، داشته باشد (یعنی شامل کلیدهای `reverse`، `newRules` و `rulesToRemove`).

این ماژول اکنون مدیریت پیکربندی پراکسی معکوس را پوشش می‌دهد. در ادامه، ماژول `routes.py` در `xenon/xray_config/` برای مسیر ویرایشگر پیشرفته و سایر مسیرهای عمومی پیکربندی Xray ایجاد خواهد شد.
