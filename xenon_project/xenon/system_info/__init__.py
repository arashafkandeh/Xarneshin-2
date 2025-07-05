# This file makes the 'system_info' directory a Python package.

from .routes import system_info_bp

# Expose utility functions if they are meant to be used by other packages directly
# For example, if _run_command or _format_timedelta were general utilities:
# from .routes import _run_command, _format_timedelta
# However, they are kept as private helpers within routes.py for now.

__all__ = ['system_info_bp']

import logging
logger = logging.getLogger(__name__)
logger.debug("xenon.system_info package initialized.")
