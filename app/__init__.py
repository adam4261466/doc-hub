from flask import Flask, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_wtf import CSRFProtect
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
from flask_mail import Mail


load_dotenv()

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
mail = Mail()

# Limiter: tracks per IP by default, sets default request limits
limiter = Limiter(key_func=get_remote_address, default_limits=["60 per minute"])

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

csrf = CSRFProtect()

def create_app():
    app = Flask(__name__, template_folder='templates')

    # Config
    app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    # Ensure uploads are stored in a non-executable directory outside static/
    app.config['UPLOAD_FOLDER'] = "data/uploads"
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB

    # Secure cookie flags
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

    # Mail config
    app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER")
    app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT", 587))
    app.config["MAIL_USE_TLS"] = os.getenv("MAIL_USE_TLS", "True") == "True"
    app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
    app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
    app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_DEFAULT_SENDER")

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    mail.init_app(app)

    # Context processor to make session available in templates
    @app.context_processor
    def inject_session():
        from flask import session
        return dict(session=session)

    # Import and register blueprints/routes
    from .routes import main
    app.register_blueprint(main)

    return app
