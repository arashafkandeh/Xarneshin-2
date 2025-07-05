from functools import wraps
from flask import session, redirect, url_for, flash, request
import logging

logger = logging.getLogger(__name__)

def login_required(f):
    """
    Decorator to ensure a user is logged in before accessing a route.
    Redirects to the login page if the user is not authenticated.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'token' not in session or not session['token']: # Check if token exists and is not empty
            logger.warning(f"Access denied for unauthenticated user to {request.path}")
            flash("You need to be logged in to access this page.", "warning")
            # Store the attempted URL in session to redirect after login
            # session['next_url'] = request.url # Optional: for redirecting back after login
            return redirect(url_for('auth.root_index', _external=True)) # 'auth.root_index' is login page
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f): # Example for a future admin-specific decorator
    """
    Decorator to ensure a user has admin privileges (placeholder).
    This would require more sophisticated role management.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'): # This session variable would need to be set at login
            logger.warning(f"Admin access denied for user {session.get('username')} to {request.path}")
            flash("You do not have administrator privileges for this action.", "danger")
            return redirect(request.referrer or url_for('nodes.show_nodes')) # Redirect to previous or nodes
        return f(*args, **kwargs)
    return decorated_function
