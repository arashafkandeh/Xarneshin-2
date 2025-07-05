from flask import Blueprint, request, render_template, session, redirect, url_for, jsonify, flash
import logging
import json

from xenon.auth.decorators import login_required
from xenon.xray_config.utils import get_xray_config, update_xray_balancers
# update_xray_balancers handles placing balancers array into config.routing.balancers
# and also handles observatory & burstObservatory settings.

logger = logging.getLogger(__name__)

balancers_bp = Blueprint(
    'balancers',
    __name__,
    template_folder='../../templates',
    url_prefix='/node/<int:node_id>' # All routes under /node/<id>/...
)

# --- Routes ---

@balancers_bp.route("/balancers") # Original: /node/<id>/balancers
@login_required
def balancers_view_page(node_id): # Renamed from view_balancers
    logger.debug(f"Displaying balancers page for node_id: {node_id}")
    config_data_resp = get_xray_config(session["token"], node_id)

    balancers_list = []
    outbound_tags_list = []
    # Observatory settings are at the root of the config, not inside routing.
    # They are related to balancers, so they are often managed together.
    observatory_settings = {
        "observatory": None, # Store the actual observatory object if present
        "burstObservatory": None # Store the actual burstObservatory object if present
    }


    if config_data_resp and "config" in config_data_resp:
        try:
            decoded_config = json.loads(config_data_resp["config"])

            if "routing" in decoded_config and "balancers" in decoded_config["routing"]:
                balancers_list = decoded_config["routing"].get("balancers", [])

            # Get outbound tags for selection in the UI (as per original xenon.py)
            if "outbounds" in decoded_config:
                outbound_tags_list = [ob.get("tag") for ob in decoded_config.get("outbounds", []) if ob.get("tag")]

            # Get observatory settings if they exist
            if "observatory" in decoded_config:
                observatory_settings["observatory"] = decoded_config["observatory"]
            if "burstObservatory" in decoded_config:
                observatory_settings["burstObservatory"] = decoded_config["burstObservatory"]

        except (json.JSONDecodeError, TypeError):
            flash("Error parsing Xray config to display balancers.", "error")
            logger.error(f"Failed to parse Xray config for balancers page, node {node_id}", exc_info=True)
            # Fallback to empty lists/defaults or redirect
    else:
        flash("Failed to retrieve Xray config to display balancers.", "warning")

    return render_template(
        "balancers.html",
        node_id=node_id,
        balancers=json.dumps(balancers_list), # Pass as JSON string for JS frontend
        outbound_tags=json.dumps(outbound_tags_list), # Pass as JSON string
        # Pass observatory settings to the template if it needs to display/edit them
        observatory_config=json.dumps(observatory_settings.get("observatory")),
        burst_observatory_config=json.dumps(observatory_settings.get("burstObservatory"))
    )

@balancers_bp.route("/save_balancers", methods=["POST"]) # Original: /node/<id>/save_balancers
@login_required
def save_balancers_api(node_id): # Renamed from save_balancers
    logger.info(f"API POST request to save balancers for node_id: {node_id}")

    data = request.get_json()
    if data is None: # Check if data itself is None (e.g. empty non-JSON request)
        return jsonify({"error": "No JSON data provided."}), 400

    new_balancers_list = data.get("balancers") # Expects a list of balancer objects
    if new_balancers_list is None: # Check if "balancers" key exists and is not None
        return jsonify({"error": "No 'balancers' array provided in JSON payload."}), 400
    if not isinstance(new_balancers_list, list):
        return jsonify({"error": "'balancers' must be a list."}), 400

    # Observatory settings might also be part of the payload, at the same level as "balancers"
    # The update_xray_balancers utility function will handle placing these at the root of the config.
    observatory_payload = {}
    if "observatory" in data: # If client sends null, it means delete. If key not present, no change.
        observatory_payload["observatory"] = data.get("observatory")
    if "burstObservatory" in data:
        observatory_payload["burstObservatory"] = data.get("burstObservatory")

    # The utility function update_xray_balancers will:
    # 1. Fetch current config.
    # 2. Update config.routing.balancers with new_balancers_list.
    # 3. Update config.observatory and config.burstObservatory based on observatory_payload.
    #    If a key is in observatory_payload and its value is null, the key will be removed from config.
    #    If a key is not in observatory_payload, it's left unchanged in config.
    # 4. PUT the modified config.

    if update_xray_balancers(session["token"], node_id, new_balancers_list, observatory_settings=observatory_payload):
        flash("Balancers and observatory settings updated successfully.", "success") # For non-JS fallback
        return jsonify({"success": True, "message": "Balancers updated successfully."})
    else:
        return jsonify({"error": "Failed to update balancers on server."}), 500

```

**توضیحات و تغییرات کلیدی:**

*   **URL Prefix**: تمام مسیرها در این طرح اولیه تحت پیشوند `/node/<int:node_id>/` قرار دارند.
*   **`update_xray_balancers`**: این تابع کمکی از `xenon.xray_config.utils` مسئولیت اصلی به‌روزرسانی پیکربندی را بر عهده دارد. این تابع نه تنها لیست متعادل‌کننده‌ها را در `config.routing.balancers` قرار می‌دهد، بلکه تنظیمات `observatory` و `burstObservatory` را نیز در ریشه پیکربرحله مدیریت می‌کند.
*   **مسیرها**:
    *   `/balancers`: صفحه HTML را برای مشاهده و ویرایش متعادل‌کننده‌ها و تنظیمات مرتبط با observatory ارائه می‌دهد. این صفحه لیست تگ‌های خروجی موجود را نیز برای استفاده در UI دریافت می‌کند. داده‌های متعادل‌کننده‌ها و تگ‌ها به صورت رشته JSON به قالب ارسال می‌شوند تا توسط جاوا اسکریپت پردازش شوند.
    *   `/save_balancers` (POST): لیست جدید متعادل‌کننده‌ها و همچنین تنظیمات `observatory` و `burstObservatory` (در صورت وجود) را از یک بار JSON دریافت کرده و ذخیره می‌کند.
*   **مدیریت `observatory`**:
    *   صفحه نمایش (`balancers_view_page`) تنظیمات `observatory` و `burstObservatory` فعلی را از پیکربندی واکشی کرده و به قالب ارسال می‌کند.
    *   مسیر ذخیره (`save_balancers_api`) انتظار دارد که این تنظیمات (در صورت تمایل به تغییر) در همان سطح کلید `balancers` در بار JSON ورودی قرار داشته باشند. تابع `update_xray_balancers` در `utils` به درستی آنها را در ریشه پیکربندی قرار می‌دهد یا در صورت ارسال `null` توسط سرویس گیرنده، آنها را حذف می‌کند.

این ماژول اکنون مدیریت متعادل‌کننده‌ها و تنظیمات مرتبط با observatory را پوشش می‌دهد. در ادامه، ماژول `reverse.py` برای مدیریت پیکربندی معکوس ایجاد خواهد شد.
