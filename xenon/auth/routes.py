from flask import Blueprint, request, render_template, session, redirect, url_for, flash
import logging
# Use relative import for utils within the same package
from .utils import get_token
# Use relative import for decorators if it's now part of auth package directly
# If decorators.py is in xenon/auth/decorators.py:
from .decorators import login_required


logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__, template_folder='../templates') # templates at xenon/templates

@auth_bp.route("/", methods=["GET"])
def root_index():
    if "token" in session:
        logger.debug("User already logged in, redirecting to nodes page.")
        # nodes.show_nodes is the endpoint function name in nodes_bp
        return redirect(url_for("nodes.show_nodes", _external=True))
    logger.debug("Serving login page.")
    return render_template("login.html")

@auth_bp.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        flash("Username and password are required.", "warning")
        return render_template("login.html"), 400

    logger.info(f"Login attempt for user: {username}")
    token = get_token(username, password)

    if token:
        session["token"] = token
        session["username"] = username
        logger.info(f"User {username} logged in successfully.")
        flash("Login successful!", "success")
        # After login, redirect to the 'next_url' if it exists, otherwise to nodes page
        next_url = session.pop('next_url', None)
        return redirect(next_url or url_for("nodes.show_nodes", _external=True))
    else:
        logger.warning(f"Login failed for user: {username}. Invalid credentials or API error.")
        flash("Invalid credentials or cannot connect to API.", "error")
        return render_template("login.html"), 401

@auth_bp.route("/logout")
def logout():
    username = session.get("username", "Unknown user")
    session.clear()
    logger.info(f"User {username} logged out.")
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.root_index", _external=True))


# login_required decorator was moved to xenon/auth/decorators.py
# Example of how it might be used in other blueprints:
# from xenon.auth.decorators import login_required
# @some_other_bp.route('/protected')
# @login_required
# def protected_route():
# pass
