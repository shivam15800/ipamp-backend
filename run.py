from flask import Flask
from app.utils.config import Config
from app.utils.extensions import db, migrate
from sqlalchemy import text

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)

    @app.route("/")
    def index():
        return "API is running", 200

    return app

app = create_app()

if __name__ == "__main__":
    app.run()  

with app.app_context():
    try:
        # Run a simple query to check connection
        db.session.execute(text("SELECT 1"))
        print("✅ Connected to MySQL successfully")
    except Exception as e:
        print("❌ Connection failed:", e)
        