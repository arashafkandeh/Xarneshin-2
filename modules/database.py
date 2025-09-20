# /opt/Xenon.xray/modules/database.py

import sqlite3
import logging
import os
import base64
from datetime import datetime

# Setup logging
logger = logging.getLogger(__name__)

# Define the path for the database file
DB_FILE = "/opt/Xenon.xray/data/installed_nodes.db"

def init_db():
    """
    Initializes the database and creates the 'installed_nodes' table if it doesn't exist.
    """
    # Ensure the data directory exists
    try:
        os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
    except OSError as e:
        logger.error(f"Error creating directory for database: {e}")
        return

    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # SQL statement to create the table
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS installed_nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_name TEXT NOT NULL,
            server_ip TEXT NOT NULL,
            ssh_user TEXT NOT NULL,
            ssh_password TEXT NOT NULL,
            ssh_port INTEGER NOT NULL,
            node_certificate TEXT,
            node_xray_port INTEGER,
            xray_version TEXT,
            use_proxy BOOLEAN,
            proxy_ip TEXT,
            proxy_port INTEGER,
            proxy_user TEXT,
            proxy_password TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        """
        cursor.execute(create_table_sql)
        conn.commit()
        logger.info(f"Database initialized successfully at {DB_FILE}")

    except sqlite3.Error as e:
        logger.error(f"Database error during initialization: {e}")
    finally:
        if conn:
            conn.close()

def get_installed_node_by_name(node_name: str):
    """
    Retrieves the details of an installed node by its name.

    Args:
        node_name (str): The name of the node.

    Returns:
        dict: A dictionary containing the node's details, or None if not found.
    """
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        sql = "SELECT * FROM installed_nodes WHERE node_name = ? ORDER BY timestamp DESC LIMIT 1;"
        cursor.execute(sql, (node_name,))
        row = cursor.fetchone()

        if row:
            return dict(row)
        return None

    except sqlite3.Error as e:
        logger.error(f"Database error while fetching node by name '{node_name}': {e}")
        return None
    finally:
        if conn:
            conn.close()

def add_installed_node(node_data: dict):
    """
    Adds the details of a successfully installed node to the database.

    Args:
        node_data (dict): A dictionary containing all the node's configuration details.
    """
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        # IMPORTANT SECURITY WARNING: Storing passwords in plaintext is not recommended for
        # production environments. Consider using encryption or a dedicated secrets manager.
        
        # Decode the certificate from Base64 before storing
        try:
            certificate_text = base64.b64decode(node_data.get('nodeCertificate', '')).decode('utf-8')
        except (TypeError, ValueError):
            certificate_text = "" # Handle cases where certificate is empty or invalid

        sql = """
        INSERT INTO installed_nodes (
            node_name, server_ip, ssh_user, ssh_password, ssh_port,
            node_certificate, node_xray_port, xray_version, use_proxy,
            proxy_ip, proxy_port, proxy_user, proxy_password, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        
        params = (
            node_data.get('nodeName'),
            node_data.get('serverIP'),
            node_data.get('sshUser'),
            node_data.get('sshPassword'),
            int(node_data.get('sshPort', 22)),
            certificate_text,
            int(node_data['nodeXrayPort']) if node_data.get('nodeXrayPort') else None,
            node_data.get('selectedXrayVersion'),
            node_data.get('useProxy', False),
            node_data.get('proxyIP'),
            int(node_data['proxyPort']) if node_data.get('proxyPort') else None,
            node_data.get('proxyUser'),
            node_data.get('proxyPassword'),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

        cursor.execute(sql, params)
        conn.commit()
        logger.info(f"Successfully saved node '{node_data.get('nodeName')}' details to the database.")
        return cursor.lastrowid

    except sqlite3.Error as e:
        logger.error(f"Failed to save node details to database: {e}")
        return None
    finally:
        if conn:
            conn.close()
