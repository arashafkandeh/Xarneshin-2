import requests
import json
import logging

# Relative imports for modules within xenon package
from ..config import API_BASE_URL
from ..auth.utils import api_session

logger = logging.getLogger(__name__)

def get_xray_config(token, node_id):
    url = f"{API_BASE_URL}/nodes/{node_id}/xray/config"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        logger.debug(f"Fetching Xray config for node_id: {node_id} from {url}")
        r = api_session.get(url, headers=headers, timeout=10)
        r.raise_for_status()
        config_data = r.json()
        logger.info(f"Successfully fetched Xray config for node_id: {node_id}")
        return config_data
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error fetching Xray config for node {node_id}: {http_err} - Response: {r.text if 'r' in locals() and hasattr(r, 'text') else 'N/A'}")
    except requests.exceptions.ConnectionError as conn_err:
        logger.error(f"Connection error fetching Xray config for node {node_id}: {conn_err}")
    except requests.exceptions.Timeout as timeout_err:
        logger.error(f"Timeout fetching Xray config for node {node_id}: {timeout_err}")
    except json.JSONDecodeError as json_err: # Specific error for JSON parsing
        logger.error(f"Failed to decode JSON response for Xray config node {node_id}: {json_err}. Response text: {r.text if 'r' in locals() and hasattr(r, 'text') else 'N/A'}")
    except requests.exceptions.RequestException as req_err: # General requests error
        logger.error(f"Unexpected requests error fetching Xray config for node {node_id}: {req_err}")
    return None

def _put_xray_config(token, node_id, config_object_or_string, is_json_string=True):
    url = f"{API_BASE_URL}/nodes/{node_id}/xray/config"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    final_config_str = ""
    if is_json_string:
        try:
            # Validate and re-format for consistency
            loaded_obj = json.loads(config_object_or_string)
            final_config_str = json.dumps(loaded_obj, indent=2)
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON string provided for Xray config update on node {node_id}.")
            return False
    else:
        final_config_str = json.dumps(config_object_or_string, indent=2)

    body = {"config": final_config_str, "format": 1}
    try:
        logger.debug(f"Updating Xray config for node_id: {node_id} at {url}")
        put_resp = api_session.put(url, headers=headers, data=json.dumps(body), timeout=15)
        put_resp.raise_for_status()
        logger.info(f"Successfully updated Xray config for node_id: {node_id}. Status: {put_resp.status_code}")
        return True
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error updating Xray config for node {node_id}: {http_err} - Response: {put_resp.text if 'put_resp' in locals() and hasattr(put_resp, 'text') else 'N/A'}")
    except requests.exceptions.ConnectionError as conn_err:
        logger.error(f"Connection error updating Xray config for node {node_id}: {conn_err}")
    except requests.exceptions.Timeout as timeout_err:
        logger.error(f"Timeout updating Xray config for node {node_id}: {timeout_err}")
    except requests.exceptions.RequestException as req_err: # General requests error
        logger.error(f"Unexpected requests error updating Xray config for node {node_id}: {req_err}")
    return False

def update_xray_section(token, node_id, section_name, new_data):
    current_config_response = get_xray_config(token, node_id)
    if not current_config_response or "config" not in current_config_response:
        logger.error(f"Cannot retrieve current config for node {node_id} to update section '{section_name}'.")
        return False
    try:
        decoded_config = json.loads(current_config_response["config"])
    except json.JSONDecodeError:
        logger.error(f"Error parsing current Xray config string for node {node_id} to update section '{section_name}'.")
        return False
    decoded_config[section_name] = new_data
    return _put_xray_config(token, node_id, decoded_config, is_json_string=False)

def update_xray_inbounds(token, node_id, new_inbounds):
    return update_xray_section(token, node_id, "inbounds", new_inbounds)

def update_xray_outbounds(token, node_id, new_outbounds):
    return update_xray_section(token, node_id, "outbounds", new_outbounds)

def update_xray_dns(token, node_id, new_dns_config):
    return update_xray_section(token, node_id, "dns", new_dns_config)

def update_xray_routing_rules(token, node_id, new_rules):
    current_config_response = get_xray_config(token, node_id)
    if not current_config_response or "config" not in current_config_response:
        logger.error(f"Cannot retrieve current config for node {node_id} to update routing rules.")
        return False
    try:
        decoded_config = json.loads(current_config_response["config"])
    except json.JSONDecodeError:
        logger.error(f"Error parsing current Xray config string for node {node_id} to update routing rules.")
        return False
    if "routing" not in decoded_config: decoded_config["routing"] = {}
    decoded_config["routing"]["rules"] = new_rules
    return _put_xray_config(token, node_id, decoded_config, is_json_string=False)

def update_xray_balancers(token, node_id, new_balancers, observatory_settings=None):
    current_config_response = get_xray_config(token, node_id)
    if not current_config_response or "config" not in current_config_response:
        logger.error(f"Cannot retrieve current config for node {node_id} to update balancers.")
        return False
    try:
        decoded_config = json.loads(current_config_response["config"])
    except json.JSONDecodeError:
        logger.error(f"Error parsing current Xray config string for node {node_id} to update balancers.")
        return False

    if "routing" not in decoded_config: decoded_config["routing"] = {}
    decoded_config["routing"]["balancers"] = new_balancers

    if observatory_settings:
        if "observatory" in observatory_settings:
            decoded_config["observatory"] = observatory_settings["observatory"]
        else: # If key exists in payload with null, it means delete from config
            if observatory_settings.get("observatory") is None and "observatory" in observatory_settings:
                 decoded_config.pop("observatory", None)

        if "burstObservatory" in observatory_settings:
            decoded_config["burstObservatory"] = observatory_settings["burstObservatory"]
        else:
            if observatory_settings.get("burstObservatory") is None and "burstObservatory" in observatory_settings:
                decoded_config.pop("burstObservatory", None)

    return _put_xray_config(token, node_id, decoded_config, is_json_string=False)

def update_xray_reverse_config(token, node_id, new_reverse_obj, new_rules=None, rules_tags_to_remove=None):
    current_config_response = get_xray_config(token, node_id)
    if not current_config_response or "config" not in current_config_response:
        logger.error(f"Cannot retrieve current config for node {node_id} to update reverse config.")
        return False
    try:
        decoded_config = json.loads(current_config_response["config"])
    except json.JSONDecodeError:
        logger.error(f"Error parsing current Xray config string for node {node_id} for reverse update.")
        return False

    if new_reverse_obj is None or (not new_reverse_obj.get("bridges") and not new_reverse_obj.get("portals")):
        decoded_config.pop("reverse", None)
        logger.debug(f"Node {node_id}: Removed reverse section.")
    else:
        decoded_config["reverse"] = new_reverse_obj
        logger.debug(f"Node {node_id}: Updated reverse section.")

    if rules_tags_to_remove or new_rules: # Check if new_rules is not None and not empty
        routing = decoded_config.get("routing", {"rules": []}) # Ensure routing and rules list exist
        current_rules = routing.get("rules", [])

        if rules_tags_to_remove:
            logger.debug(f"Node {node_id}: Tags for rules to remove: {rules_tags_to_remove}")
            def search_tag_in_value(value, tags_to_remove):
                if isinstance(value, str): return value in tags_to_remove
                if isinstance(value, list): return any(search_tag_in_value(item, tags_to_remove) for item in value)
                if isinstance(value, dict): return any(search_tag_in_value(val, tags_to_remove) for val in value.values())
                return False
            current_rules = [rule for rule in current_rules if not search_tag_in_value(rule, rules_tags_to_remove)]

        if new_rules: # Append new rules if provided
            logger.debug(f"Node {node_id}: Appending new rules for reverse: {json.dumps(new_rules)}")
            current_rules.extend(new_rules)

        decoded_config["routing"] = decoded_config.get("routing", {})
        decoded_config["routing"]["rules"] = current_rules
        logger.debug(f"Node {node_id}: Routing rules updated for reverse logic.")

    return _put_xray_config(token, node_id, decoded_config, is_json_string=False)

def update_full_xray_config(token, node_id, config_json_string):
    return _put_xray_config(token, node_id, config_json_string, is_json_string=True)

def filter_empty_dns_fields(obj):
    if isinstance(obj, dict):
        return {k: filter_empty_dns_fields(v) for k, v in obj.items() if v not in ["", None, []] or k == "hosts"}
    elif isinstance(obj, list):
        filtered_list = [filter_empty_dns_fields(item) for item in obj]
        # Keep item if it's not None, not an empty dict, or if it's a non-empty list itself
        return [item for item in filtered_list if item is not None and item != {} or (isinstance(item, list) and item)]
    return obj

```

**`xenon_project/xenon/xray_config/inbounds.py`** (و سایر فایل‌های طرح اولیه در `xray_config`)
وارد کردن‌ها در این فایل‌ها (`inbounds.py`, `outbounds.py`, `dns.py`, `routing.py`, `balancers.py`, `reverse.py`, `routes.py`) باید به صورت زیر باشند:
*   `from ..auth.decorators import login_required` (دو نقطه برای رفتن به `xenon`، سپس به `auth`)
*   `from .utils import ...` (یک نقطه برای وارد کردن از `utils.py` در همان بسته `xray_config`)
*   `from ..config import ...` (دو نقطه برای رفتن به `xenon`، سپس به `config`)

این الگو برای تمام فایل‌های طرح اولیه در `xenon/xray_config/` اعمال خواهد شد. من با `inbounds.py` شروع می‌کنم و سپس بقیه را انجام می‌دهم.
