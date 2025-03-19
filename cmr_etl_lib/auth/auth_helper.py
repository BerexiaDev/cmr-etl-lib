from flask import g
from cmr_etl_lib.auth.user import User


class AuthHelper:
    @staticmethod
    def get_logged_in_user():
        pass
    ## TODO: Implement get logged in user, Get user from global context
