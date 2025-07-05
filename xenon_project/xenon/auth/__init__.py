# This file makes the 'auth' directory a Python package.

# Optionally, expose key components like the blueprint for easier importing.
# This allows `from xenon.auth import auth_bp` instead of `from xenon.auth.routes import auth_bp`.
from .routes import auth_bp
from .utils import get_token
from .decorators import login_required

# You can define __all__ to specify what `from xenon.auth import *` imports.
__all__ = ['auth_bp', 'get_token', 'login_required']

import logging
logger = logging.getLogger(__name__)
logger.debug("xenon.auth package initialized.")
