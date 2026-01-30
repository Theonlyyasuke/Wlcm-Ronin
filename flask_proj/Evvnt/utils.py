from functools import wraps
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from models import User

def role_required(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            user = User.query.get(get_jwt_identity())

            if not user or not user.is_active:
                return {"msg": "Unauthorized"}, 403

            if user.role not in roles:
                return {"msg": "Forbidden"}, 403

            return fn(*args, **kwargs)
        return wrapper
    return decorator
