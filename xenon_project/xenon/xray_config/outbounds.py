from flask import Blueprint, request, render_template, session, redirect, url_for, jsonify, flash
import logging
import json
import random

from xenon.auth.decorators import login_required
from xenon.xray_config.utils import get_xray_config, update_xray_outbounds

logger = logging.getLogger(__name__)

outbounds_bp = Blueprint(
    'outbounds',
    __name__,
    template_folder='../../templates',
    url_prefix='/node/<int:node_id>'
)

# --- Routes ---
@outbounds_bp.route("/outbounds")
@login_required
def view_outbounds(node_id): # Renamed from outbounds to view_outbounds for clarity
    logger.debug(f"Viewing outbounds for node_id: {node_id}")
    config_data_resp = get_xray_config(session["token"], node_id)
    if not config_data_resp or "config" not in config_data_resp:
        flash("Failed to retrieve Xray config for outbounds.", "error")
        return redirect(url_for("nodes.show_nodes", _external=True))

    try:
        decoded_config = json.loads(config_data_resp["config"])
    except (json.JSONDecodeError, TypeError):
        flash("Invalid Xray config JSON.", "error")
        logger.error(f"Failed to parse Xray config for outbounds, node {node_id}", exc_info=True)
        return redirect(url_for("nodes.show_nodes", _external=True))

    outbounds_list = decoded_config.get("outbounds", [])
    return render_template("outbounds.html", node_id=node_id, outbounds=outbounds_list)

@outbounds_bp.route("/add_outbound")
@login_required
def add_outbound_form(node_id):
    logger.debug(f"Displaying add outbound form for node_id: {node_id}")
    # Default data for the form, similar to original xenon.py
    # These names must match those expected by outbound_form.html
    form_data_defaults = {
        "protocols": [ # Common outbound protocols
            "freedom", "blackhole", "dns", "vmess", "vless", "trojan",
            "shadowsocks", "socks", "http", "wireguard"
        ],
        "freedomDomainStrategies": ["AsIs", "UseIP", "UseIPv4", "UseIPv6", "ForceIP"], # For freedom protocol
        "stream_transmissions": ["tcp", "ws", "grpc", "httpupgrade", "quic", "mkcp"], # Common stream networks for proxy outbounds
        "default_tag": f"outbound-{random.randint(1000, 9999)}"
    }
    # Original outbound_form.html used 'outbound_data_json' for initial data (empty for add)
    # and 'form_action_url'.
    return render_template(
        "outbound_form.html",
        page_title="Add Outbound",
        form_action_url=url_for(".save_outbound_new", node_id=node_id), # Save new outbound
        outbound_data_json=json.dumps({}), # Empty for new
        node_id=node_id,
        edit_mode=False,
        **form_data_defaults
    )

@outbounds_bp.route("/edit_outbound/<path:outbound_tag>")
@login_required
def edit_outbound_form(node_id, outbound_tag):
    logger.debug(f"Displaying edit outbound form for tag '{outbound_tag}' on node_id: {node_id}")
    config_data_resp = get_xray_config(session["token"], node_id)
    if not config_data_resp or "config" not in config_data_resp:
        flash("Failed to retrieve config to edit outbound.", "error")
        return redirect(url_for(".view_outbounds", node_id=node_id))

    try:
        decoded_config = json.loads(config_data_resp["config"])
    except (json.JSONDecodeError, TypeError):
        flash("Invalid config JSON for editing outbound.", "error")
        return redirect(url_for(".view_outbounds", node_id=node_id))

    outbounds_list = decoded_config.get("outbounds", [])
    outbound_to_edit = next((ob for ob in outbounds_list if ob.get("tag") == outbound_tag), None)

    if not outbound_to_edit:
        flash(f"No outbound found with tag: {outbound_tag}", "error")
        return redirect(url_for(".view_outbounds", node_id=node_id))

    form_data_defaults = { # Same options as add form
        "protocols": ["freedom", "blackhole", "dns", "vmess", "vless", "trojan", "shadowsocks", "socks", "http", "wireguard"],
        "freedomDomainStrategies": ["AsIs", "UseIP", "UseIPv4", "UseIPv6", "ForceIP"],
        "stream_transmissions": ["tcp", "ws", "grpc", "httpupgrade", "quic", "mkcp"],
        "default_tag": outbound_tag # Current tag for editing
    }

    return render_template(
        "outbound_form.html",
        page_title=f"Edit Outbound (tag: {outbound_tag})",
        form_action_url=url_for(".save_outbound_edit", node_id=node_id, outbound_tag=outbound_tag), # Save edited
        outbound_data_json=json.dumps(outbound_to_edit, indent=2), # Current data
        node_id=node_id,
        edit_mode=True,
        **form_data_defaults
    )

@outbounds_bp.route("/save_outbound", methods=["POST"]) # For new outbounds
@login_required
def save_outbound_new(node_id):
    logger.info(f"Attempting to save new outbound for node_id: {node_id}")
    # Original xenon.py relied on a "jsonEditor" form field containing the full JSON.
    outbound_json_str = request.form.get("jsonEditor")
    if not outbound_json_str:
        flash("No outbound JSON data provided.", "error")
        return redirect(url_for(".add_outbound_form", node_id=node_id))

    try:
        new_outbound_obj = json.loads(outbound_json_str)
    except json.JSONDecodeError:
        flash("Invalid JSON format for the outbound configuration.", "error")
        # Consider re-rendering form with the invalid JSON to allow user to fix
        return redirect(url_for(".add_outbound_form", node_id=node_id))

    if not new_outbound_obj.get("tag"):
        flash("Outbound configuration must include a 'tag'.", "error")
        return redirect(url_for(".add_outbound_form", node_id=node_id))
    # TODO: Add more validation for the outbound object structure if needed.

    config_data_resp = get_xray_config(session["token"], node_id)
    if not config_data_resp or "config" not in config_data_resp:
        flash("Cannot retrieve current config to add outbound.", "error")
        return redirect(url_for(".view_outbounds", node_id=node_id))
    try:
        decoded_config = json.loads(config_data_resp["config"])
    except (json.JSONDecodeError, TypeError):
        flash("Cannot parse current Xray config.", "error")
        return redirect(url_for(".view_outbounds", node_id=node_id))

    outbounds_list = decoded_config.get("outbounds", [])
    existing_tags = {ob.get("tag") for ob in outbounds_list}
    if new_outbound_obj.get("tag") in existing_tags:
        flash(f"Outbound tag '{new_outbound_obj.get('tag')}' already exists.", "error")
        return redirect(url_for(".add_outbound_form", node_id=node_id)) # Re-render with data

    outbounds_list.append(new_outbound_obj)

    if update_xray_outbounds(session["token"], node_id, outbounds_list):
        flash(f"Outbound '{new_outbound_obj.get('tag')}' added successfully.", "success")
    else:
        flash("Failed to update outbounds on server.", "error")
    return redirect(url_for(".view_outbounds", node_id=node_id))


@outbounds_bp.route("/save_outbound/<path:outbound_tag>", methods=["POST"]) # For editing
@login_required
def save_outbound_edit(node_id, outbound_tag):
    logger.info(f"Attempting to save edited outbound '{outbound_tag}' for node_id: {node_id}")
    outbound_json_str = request.form.get("jsonEditor")
    if not outbound_json_str:
        flash("No outbound JSON data provided for edit.", "error")
        return redirect(url_for(".edit_outbound_form", node_id=node_id, outbound_tag=outbound_tag))

    try:
        edited_outbound_obj = json.loads(outbound_json_str)
    except json.JSONDecodeError:
        flash("Invalid JSON format for the edited outbound configuration.", "error")
        return redirect(url_for(".edit_outbound_form", node_id=node_id, outbound_tag=outbound_tag))

    new_tag_from_form = edited_outbound_obj.get("tag")
    if not new_tag_from_form:
        flash("Edited outbound configuration must include a 'tag'.", "error")
        return redirect(url_for(".edit_outbound_form", node_id=node_id, outbound_tag=outbound_tag))

    config_data_resp = get_xray_config(session["token"], node_id)
    if not config_data_resp or "config" not in config_data_resp:
        flash("Cannot retrieve current config to edit outbound.", "error")
        return redirect(url_for(".view_outbounds", node_id=node_id))
    try:
        decoded_config = json.loads(config_data_resp["config"])
    except (json.JSONDecodeError, TypeError):
        flash("Cannot parse current Xray config for editing outbound.", "error")
        return redirect(url_for(".view_outbounds", node_id=node_id))

    outbounds_list = decoded_config.get("outbounds", [])
    updated_outbounds_list = []
    found_original_tag = False

    for ob in outbounds_list:
        current_tag = ob.get("tag")
        if current_tag == outbound_tag: # Found the one to replace
            updated_outbounds_list.append(edited_outbound_obj)
            found_original_tag = True
            if new_tag_from_form != outbound_tag: # Tag was changed
                if new_tag_from_form in (x.get("tag") for x in outbounds_list if x.get("tag") != outbound_tag):
                    flash(f"The new tag '{new_tag_from_form}' (changed from '{outbound_tag}') conflicts with another existing outbound. Edit failed.", "error")
                    return redirect(url_for(".edit_outbound_form", node_id=node_id, outbound_tag=outbound_tag))
        # If the current outbound (not the one being edited) has the same tag as the new_tag_from_form
        elif current_tag == new_tag_from_form and new_tag_from_form != outbound_tag :
             flash(f"The new tag '{new_tag_from_form}' conflicts with another existing outbound. Edit failed.", "error")
             return redirect(url_for(".edit_outbound_form", node_id=node_id, outbound_tag=outbound_tag))
        else:
            updated_outbounds_list.append(ob)

    if not found_original_tag:
        # This could happen if the tag was changed by another process or deleted.
        # Decide whether to add as new if tag is unique, or just error out.
        # For now, error out if original tag to edit is not found.
        flash(f"Original outbound tag '{outbound_tag}' not found. It might have been modified or deleted.", "warning")
        return redirect(url_for(".view_outbounds", node_id=node_id))

    if update_xray_outbounds(session["token"], node_id, updated_outbounds_list):
        flash(f"Outbound '{new_tag_from_form}' updated successfully.", "success")
    else:
        flash("Failed to update outbound on server.", "error")

    return redirect(url_for(".view_outbounds", node_id=node_id))


@outbounds_bp.route("/delete_outbound/<path:outbound_tag>")
@login_required
def delete_outbound(node_id, outbound_tag):
    logger.info(f"Attempting to delete outbound '{outbound_tag}' for node_id: {node_id}")
    config_data_resp = get_xray_config(session["token"], node_id)
    if not config_data_resp or "config" not in config_data_resp:
        flash("Failed to retrieve config for outbound deletion.", "error")
        return redirect(url_for(".view_outbounds", node_id=node_id))

    try:
        decoded_config = json.loads(config_data_resp["config"])
    except (json.JSONDecodeError, TypeError):
        flash("Invalid config JSON, cannot delete outbound.", "error")
        return redirect(url_for(".view_outbounds", node_id=node_id))

    outbounds_list = decoded_config.get("outbounds", [])
    original_len = len(outbounds_list)
    new_outbounds_list = [ob for ob in outbounds_list if ob.get("tag") != outbound_tag]

    if len(new_outbounds_list) == original_len:
        flash(f"No outbound found with tag '{outbound_tag}'. No changes made.", "warning")
    else:
        if update_xray_outbounds(session["token"], node_id, new_outbounds_list):
            flash(f"Outbound '{outbound_tag}' deleted successfully.", "success")
        else:
            flash("Failed to update config after deleting outbound.", "error")

    return redirect(url_for(".view_outbounds", node_id=node_id))

```

**توضیحات و تغییرات کلیدی:**

*   **وابستگی به `jsonEditor`**: منطق ذخیره سازی (`save_outbound_new` و `save_outbound_edit`) همچنان بر اساس این است که فرم (`outbound_form.html`) یک فیلد به نام `jsonEditor` ارائه می دهد که حاوی کل پیکربندی JSON خروجی است. این با رفتار `xenon.py` اصلی مطابقت دارد.
*   **ارائه گزینه‌ها به فرم**: مسیرهای `add_outbound_form` و `edit_outbound_form` داده‌های پیش‌فرض (مانند لیست پروتکل‌ها، استراتژی‌های freedom، و غیره) را به قالب ارسال می‌کنند، همانطور که در `xenon.py` اصلی انجام می‌شد. نام این متغیرها باید با آنچه در `outbound_form.html` انتظار می‌رود مطابقت داشته باشد.
*   **مسیرهای جداگانه برای ذخیره**: مشابه `inbounds.py`، مسیرهای جداگانه‌ای برای ذخیره خروجی جدید (`save_outbound_new`) و ویرایش خروجی موجود (`save_outbound_edit`) استفاده می‌شود.
*   **مدیریت تگ**: منطق مشابهی برای مدیریت تغییرات تگ و جلوگیری از تداخل در هنگام ویرایش اعمال شده است.
*   **ساده‌سازی**: بر خلاف `inbounds.py`، هیچ تابع کمکی `_parse_outbound_form` وجود ندارد زیرا فرم اصلی برای خروجی‌ها به کاربر اجازه می‌داد تا مستقیماً JSON را ویرایش کند. اگر یک فرم ساختاریافته‌تر برای خروجی‌ها مورد نظر باشد، چنین تابعی مورد نیاز خواهد بود.

این ماژول اکنون عملکردهای اساسی CRUD (ایجاد، خواندن، به‌روزرسانی، حذف) را برای خروجی‌ها پوشش می‌دهد، با حفظ رویکرد ویرایش JSON از `xenon.py` اصلی.

ادامه با ماژول `dns.py`.
