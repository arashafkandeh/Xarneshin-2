import requests
import logging
from xenon.config import API_BASE_URL
from xenon.auth.utils import api_session # Using shared session from auth.utils

logger = logging.getLogger(__name__)

def get_nodes(token):
    url = f"{API_BASE_URL}/nodes?page=1&size=100&descending=true&order_by=created_at"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        logger.debug(f"Fetching nodes from {url}")
        r = api_session.get(url, headers=headers, timeout=15)
        r.raise_for_status()
        nodes_data = r.json()
        logger.info(f"Successfully fetched {len(nodes_data.get('items', []))} nodes.")
        return nodes_data
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error occurred while fetching nodes: {http_err} - Response: {r.text if 'r' in locals() else 'N/A'}")
    except requests.exceptions.ConnectionError as conn_err:
        logger.error(f"Connection error occurred while fetching nodes: {conn_err}")
    except requests.exceptions.Timeout as timeout_err:
        logger.error(f"Timeout occurred while fetching nodes: {timeout_err}")
    except requests.exceptions.RequestException as req_err:
        logger.error(f"An unexpected error occurred while fetching nodes: {req_err}")
    except json.JSONDecodeError as json_err:
        logger.error(f"Failed to decode JSON response while fetching nodes: {json_err}")
    return None

def get_node(token, node_id):
    url = f"{API_BASE_URL}/nodes/{node_id}"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        logger.debug(f"Fetching node details for node_id: {node_id} from {url}")
        r = api_session.get(url, headers=headers, timeout=10)
        r.raise_for_status()
        node_data = r.json()
        logger.info(f"Successfully fetched details for node_id: {node_id}")
        return node_data
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error occurred while fetching node {node_id}: {http_err} - Response: {r.text if 'r' in locals() else 'N/A'}")
    except requests.exceptions.ConnectionError as conn_err:
        logger.error(f"Connection error occurred while fetching node {node_id}: {conn_err}")
    except requests.exceptions.Timeout as timeout_err:
        logger.error(f"Timeout occurred while fetching node {node_id}: {timeout_err}")
    except requests.exceptions.RequestException as req_err:
        logger.error(f"An unexpected error occurred while fetching node {node_id}: {req_err}")
    except json.JSONDecodeError as json_err:
        logger.error(f"Failed to decode JSON response while fetching node {node_id}: {json_err}")
    return None
