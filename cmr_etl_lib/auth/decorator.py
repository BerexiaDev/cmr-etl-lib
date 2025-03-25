from functools import wraps
from flask import request
from cmr_etl_lib.auth.auth_helper import AuthHelper
from loguru import logger
ROUTES_TO_SKIP = [
    "/auth/login",
    "/auth/register",
    "/auth/logout",
    "/auth/refresh",
    "/auth/forgot_password",
]

def token_required(roles=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            logger.info(f"Request path: {request.path}")
            if request.path in ROUTES_TO_SKIP:
                return f(*args, **kwargs)
            
            
            # Ensure Authorization within the request headers
            if 'Authorization' not in request.headers:
                return {"message": "Token is missing"}, 401

            # Fetch logged-in user data
            data, status = AuthHelper.get_logged_in_user(request)

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