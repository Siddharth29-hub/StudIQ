import jwt
from django.conf import settings
from datetime import datetime ,timedelta

def create_jwt_token(user):

    payload = {
        "user_id" : user.id,
        "username" : user.username,
        "role" : user.role,
        "exp" : datetime.utcnow() + timedelta(hours = 1),
        "iat" : datetime.utcnow(),

    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm = "HS256")
    return token

def decode_jwt_token(token):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms= ["HS256"])
        return payload
    
    except jwt.ExpiredSignatureError:
        return {"error" : "token expired"}
    except jwt.InvalidTokenError:
        return {"error" : "invalid token"}
    