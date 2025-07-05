import requests
import logging
import json # Added for JSONDecodeError handling
# Use relative import to go up one level to xenon package, then into config module
from ..config import API_BASE_URL, PANEL_USE_HTTPS

logger = logging.getLogger(__name__)

api_session = requests.Session()
# Original logic: api_session.verify = not PANEL_USE_HTTPS
# This means if PANEL_USE_HTTPS is True, verify becomes False (allowing self-signed certs).
# If PANEL_USE_HTTPS is False, verify becomes True (requests default, will verify if URL is HTTPS).
# This seems counter-intuitive. Typically, you set verify=False to *disable* verification for HTTPS.
# If panel is HTTP, verify has no effect. If panel is HTTPS, this disables verification.
# Let's assume the intention was: if panel is HTTPS, then `verify` should control verification.
# For now, keeping original logic:
api_session.verify = not PANEL_USE_HTTPS
if PANEL_USE_HTTPS and api_session.verify is False:
    logger.warning("API session SSL verification is DISABLED for PANEL_USE_HTTPS=True. This is insecure for production unless using a known self-signed cert.")


def get_token(username, password):
    url = f"{API_BASE_URL}/admins/token"
    data = {
        "username": username,
        "password": password,
        "grant_type": "password"
    }
    try:
        logger.debug(f"Requesting token from {url} for user {username}")
        response = api_session.post(url, data=data, timeout=10)
        response.raise_for_status()
        access_token = response.json().get("access_token")
        if access_token:
            logger.info(f"Token obtained successfully for user {username}")
            return access_token
        else:
            logger.warning(f"Token request successful but no access_token in response for user {username}")
            return None
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error occurred while getting token for {username}: {http_err} - Response: {response.text if 'response' in locals() and hasattr(response, 'text') else 'N/A'}")
    except requests.exceptions.ConnectionError as conn_err:
        logger.error(f"Connection error occurred while getting token for {username}: {conn_err}")
    except requests.exceptions.Timeout as timeout_err:
        logger.error(f"Timeout occurred while getting token for {username}: {timeout_err}")
    except json.JSONDecodeError as json_err: # More specific error for JSON parsing
        logger.error(f"Failed to decode JSON response while getting token for {username}: {json_err}. Response text: {response.text if 'response' in locals() and hasattr(response, 'text') else 'N/A'}")
    except requests.exceptions.RequestException as req_err: # Catch-all for other requests errors
        logger.error(f"An unexpected requests error occurred while getting token for {username}: {req_err}")
    return None
