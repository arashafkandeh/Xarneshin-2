# This file makes the 'xray_config' directory a Python package.

# Expose blueprints from this package for easier registration in app.py
from .routes import xray_general_bp # For advanced editor etc.
from .inbounds import inbounds_bp
from .outbounds import outbounds_bp
from .dns import dns_bp
from .routing import routing_bp
from .balancers import balancers_bp
from .reverse import reverse_bp

# Expose common utility functions if needed externally
from .utils import (
    get_xray_config,
    update_xray_inbounds,
    update_xray_outbounds,
    update_xray_dns,
    update_xray_routing_rules,
    update_xray_balancers,
    update_xray_reverse_config,
    update_full_xray_config,
    filter_empty_dns_fields
)

__all__ = [
    'xray_general_bp',
    'inbounds_bp',
    'outbounds_bp',
    'dns_bp',
    'routing_bp',
    'balancers_bp',
    'reverse_bp',
    'get_xray_config',
    'update_xray_inbounds',
    'update_xray_outbounds',
    'update_xray_dns',
    'update_xray_routing_rules',
    'update_xray_balancers',
    'update_xray_reverse_config',
    'update_full_xray_config',
    'filter_empty_dns_fields'
]

import logging
logger = logging.getLogger(__name__)
logger.debug("xenon.xray_config package initialized.")
