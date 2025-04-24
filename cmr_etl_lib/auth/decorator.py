from functools import wraps
from flask import request
from auth_helper import get_logged_in_user

ROUTES_TO_SKIP = [
    "/auth/login",
    "/auth/register",
    "/auth/logout",
    "/auth/refresh",
    "/auth/forgot_password",
    "/auth/reset-password",
]


def token_required(roles=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            
            if request.path in ROUTES_TO_SKIP or "swagger" in request.path:
                return f(*args, **kwargs)

            if 'Authorization' not in request.headers:
                    return {"message": "Token is missing"}, 401
            # Fetch logged-in user data
            data, status = get_logged_in_user(request)
            # Log the URL and token
            if status != 200:
                return {"message": "Invalid token"}, 401

            token = data.get('data')
            if token is None:
                return {"message": "Token is missing"}, 401

            # Check if the token has the required role
            if roles is None:
                return f(*args, **kwargs)

            user_role = token.get('role')
            if user_role not in roles:
                    return {"message": "Permission denied"}, 403
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator