# This file makes the 'core' directory a Python package.

from .routes import core_bp
# Expose utility functions if they are meant to be used by other packages directly
# from .utils import get_available_xray_versions, change_xray_core_version_streamed, etc.

__all__ = ['core_bp']

import logging
logger = logging.getLogger(__name__)
logger.debug("xenon.core package initialized.")
