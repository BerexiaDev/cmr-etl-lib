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
    "/auth/reset-password",
    
    # health check
    "/auth/halth",
    "/api/health",
]


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        roles = None
        
        # Skip authentication for specified routes, swagger, and OPTIONS requests
        if request.path in ROUTES_TO_SKIP or "swagger" in request.path or request.method == "OPTIONS":
            return f(*args, **kwargs)

        try:
            if 'Authorization' not in request.headers:
                return {"message": "Token is missing"}, 401
            
            logger.info(f"Request path: {request.path}")
            
            # Fetch logged-in user data
            data, status = AuthHelper.get_logged_in_user(request)
            
            logger.info(f"Data: {data}")
            
            # Log the URL and token
            if status != 200:
                return {"message": "Invalid token"}, 401

            token = data.get('data')
            
            logger.info(f"Token: {token}")
            if token is None:
                return {"message": "Token is missing"}, 401

            # Check if the token has the required role
            if roles is None:
                return f(*args, **kwargs)

            user_role = token.get('role')
            if user_role not in roles:
                return {"message": "Permission denied"}, 403
                
            return f(*args, **kwargs)
        
        except Exception as e:
            return {"message": f"Authentication error: {str(e)}"}, 401
            
    return decorator