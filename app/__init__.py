from flask import Flask
from app.config import Config
from app.extensions import db, migrate

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)

    # Import models so they register with SQLAlchemy
    from app.models import user  

    # Register blueprints
    from app.routes.auth import auth_bp
    from app.routes.admin import admin_bp

    app.register_blueprint(auth_bp, url_prefix="/api")
    app.register_blueprint(admin_bp)

    return app