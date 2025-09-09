from flask import Flask, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os

load_dotenv()

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()

# Limiter: tracks per IP by default, sets default request limits
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

from .models import User

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Unauthorized handler for AJAX vs normal requests
@login_manager.unauthorized_handler
def unauthorized():
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify(success=False, error="Unauthorized"), 401
    return redirect(url_for("main.login"))

def create_app():
    app = Flask(__name__, template_folder='templates')

    # Config
    app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    # Ensure uploads are stored in a non-executable directory outside static/
    app.config['UPLOAD_FOLDER'] = "uploads"
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB

    # Secure cookie flags
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf = CSRFProtect(app)
    limiter.init_app(app)

    # Import and register blueprints/routes
    from .routes import main
    app.register_blueprint(main)

    return app
