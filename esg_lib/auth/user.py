from esg_lib.document import Document


class User(Document):
    __TABLE__ = "users"

    email = None
    password_hash = None
    full_name = None
    created_on = None
    modified_on = None
    admin = None
    role = None
    references = None
    is_active= None
    is_new_user = None
    references = None
    process = None
