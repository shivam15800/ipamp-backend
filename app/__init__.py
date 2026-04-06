from flask import Flask, request, g
from app.config import Config
from app.extensions import db, migrate
from flask_jwt_extended import JWTManager
from .utils.jwt import decode_token

jwt = JWTManager()

def create_app(Config):
    app = Flask(__name__)
    app.config.from_object(Config)
    # app.config.from_object(Config)

    @app.before_request
    def attach_user():
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            g.user = None
            return
        token = auth_header.split(" ")[1]
        try:
            g.user = decode_token(token)
        except Exception:
            g.user = None

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)

    # Import models so they register with SQLAlchemy
    from app.models import user  
    

    # Register blueprints
    from app.routes.auth import auth_bp
    from app.routes.admin import admin_bp
    from app.routes.project import projects_bp
    from app.routes.task import tasks_bp
    from app.routes.upload import upload_bp

    app.register_blueprint(auth_bp, url_prefix="/api")
    app.register_blueprint(admin_bp, url_prefix="/api/admin")
    app.register_blueprint(projects_bp, url_prefix="/api")
    app.register_blueprint(tasks_bp, url_prefix="/api")
    app.register_blueprint(upload_bp, url_prefix="/api")

    @app.errorhandler(Exception)
    def handle_exception(e):
        from flask import jsonify, current_app
        import traceback
        if current_app.config.get("ENABLE_VULNS", False):
            return jsonify({"error": str(e), "traceback": traceback.format_exc()}), 500
        else:
            return jsonify({"error": "An internal server error occurred"}), 500

    return app