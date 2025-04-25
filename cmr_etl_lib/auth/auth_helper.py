from cmr_etl_lib.auth.user import User
from loguru import logger
import jwt
import os
class AuthHelper:
    def get_logged_in_user(new_request):
        # get the auth token
        authorization = new_request.headers.get('Authorization')
        auth_token = authorization.split(" ")[1]
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                user = User().load({'_id':resp['token']})
                # TODO CHANGE THIS
                response_object = {
                    'status': 'success',
                    'data': {
                        'id': user.id,
                        'email': user.email,
                        'full_name': user.full_name,
                        'is_active': user.is_active,
                        'references': user.references,
                        'process': user.process,
                        'created_on': str(user.created_on),
                        'role': user.role
                    }
                }
                return response_object, 200
            response_object = {
                'status': 'fail',
                'message': resp
            }
            return response_object, 401
        else:
            response_object = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return response_object, 401
        
        
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