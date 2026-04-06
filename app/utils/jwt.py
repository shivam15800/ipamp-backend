import jwt
from datetime import datetime, timedelta
from app.config import Config
from flask import current_app 

def generate_token(user):
    payload = {
        "sub": f"{user.id}",
        "user_id": user.id,
        "username": user.username,
        # Embed all roles
        "roles": [role.name for role in user.roles],
        "exp": datetime.utcnow() + timedelta(hours=1)
    }

    token = jwt.encode(
        payload,
        Config.JWT_SECRET_KEY,
        algorithm="HS256"
    )

    return token

def decode_token(token):
    if current_app.config["ENABLE_VULNS"]:
        return jwt.decode(token, Config.JWT_SECRET_KEY, options={"verify_signature": False})
    else:
        return jwt.decode(token, Config.JWT_SECRET_KEY, algorithms=["HS256"])
