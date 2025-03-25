from flask import request
from typing import Tuple, Dict
from cmr_etl_lib.auth.user import User
from loguru import logger


class AuthHelper:
    @staticmethod
    def get_logged_in_user() -> Tuple[Dict, int]:
        # Get the auth token
        authorization = request.headers.get('Authorization')
        if not authorization:
            logger.warning("Authorization header missing in request")
            return {
                'status': 'fail',
                'message': 'Authorization header is missing.'
            }, 401
            
        try:
            auth_token = authorization.split(" ")[1]
        except IndexError:
            logger.warning("Invalid authorization format provided")
            return {
                'status': 'fail',
                'message': 'Invalid authorization format. Use "Bearer <token>"'
            }, 401

        if not auth_token:
            logger.warning("Empty auth token provided")
            return {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }, 401

        resp = User.decode_auth_token(auth_token)
        if isinstance(resp, str):
            logger.warning(f"Token validation failed: {resp}")
            return {
                'status': 'fail',
                'message': resp
            }, 401

        try:
            user = User().load({'_id': resp['token']})
            logger.info(f"User successfully authenticated: {user.email}")
            return {
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
            }, 200
        except Exception as e:
            logger.error(f"Error loading user: {str(e)}")
            return {
                'status': 'fail',
                'message': f'Error loading user: {str(e)}'
            }, 401