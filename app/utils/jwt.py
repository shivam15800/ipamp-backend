import jwt
from datetime import datetime, timedelta
from app.config import Config

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