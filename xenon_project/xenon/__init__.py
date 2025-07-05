import logging

# Configure basic logging for the xenon package
# This will apply to all modules within xenon unless they override it.
# More sophisticated logging can be configured in app.py or a dedicated logging config file.
logging.basicConfig(
    level=logging.DEBUG, # Set to INFO or WARNING for production
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)
logger.info("Xenon package initialized.")

# Optionally, you can import the app instance here to make it accessible as xenon.app
# from .app import app
# However, this can lead to circular imports if app.py imports from other modules in xenon
# that might try to import 'app' from 'xenon'.
# It's often safer to manage app instance creation and blueprint registration solely within app.py.

# You could also expose specific components from submodules here if desired, for example:
# from .auth.routes import auth_bp
# This would allow `from xenon import auth_bp`
# But for now, keeping it simple. Blueprints will be imported directly by app.py.

# Define __all__ if you want to control what `from xenon import *` imports
# __all__ = ['app', 'some_other_component']
