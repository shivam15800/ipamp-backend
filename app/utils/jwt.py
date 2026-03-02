import jwt
from datetime import datetime, timedelta
from app.config import Config


def generate_token(user):
    payload = {
        "user_id": user.id,
        "username": user.username,
        "role": user.role,
        "exp": datetime.utcnow() + timedelta(hours=1)
    }

    token = jwt.encode(
        payload,
        Config.JWT_SECRET,
        algorithm="HS256"
    )

    return token