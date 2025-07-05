# This file makes the 'tools' directory a Python package.

from .routes import tools_bp

# Expose utility functions if they are intended for direct use by other packages
# For example:
from .cert_utils import generate_self_signed_cert, generate_reality_keypair, generate_hex_short_ids
from .warp import generate_warp_config_external
from .network_tests import perform_full_connection_test

__all__ = [
    'tools_bp',
    'generate_self_signed_cert',
    'generate_reality_keypair',
    'generate_hex_short_ids',
    'generate_warp_config_external',
    'perform_full_connection_test'
]

import logging
logger = logging.getLogger(__name__)
logger.debug("xenon.tools package initialized.")
