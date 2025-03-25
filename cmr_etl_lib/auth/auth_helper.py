from cmr_etl_lib.auth.user import User
from loguru import logger
import os
import jwt

class AuthHelper:
    def get_logged_in_user(authorization):
        # get the auth token
        auth_token = authorization.split(" ")[1]
        if auth_token:
            resp = decode_auth_token(auth_token)
            if not isinstance(resp, str):
                user = User().load(query={"_id": resp['token']})
                resp = {
                        'id': str(user._id),
                        'references': user.references if user.references else [],
                        'process': user.process if user.process else [],
                        'role': user.role,
                        'created_on': str(user.created_on),
                        'email': user.email,
                        'full_name': user.full_name,
                }
                return resp
  
        else:
            print("Provide a valid auth token.")
            return None
        
        
def decode_auth_token(auth_token):
    """
    Decodes the auth token
    :param auth_token:
    :return: integer|string
    """
    try:
        key = os.getenv("SECRET_KEY")
        payload = jwt.decode(auth_token, key, algorithms=['HS256'])
        return {"status": "success", "token": payload["sub"]}
    except jwt.ExpiredSignatureError:
        logger.error("Signature expired. Please log in again.")
        return {
            "status": "fail", 
            "message": "Signature expired. Please log in again.",
        }
    except jwt.InvalidTokenError:
        logger.error("Invalid token. Please log in again.")
        return {"status": "fail", "message": "Invalid token. Please log in again."}