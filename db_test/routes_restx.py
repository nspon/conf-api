from flask_restx import Model, ValidationError

from db_test import (wraps, generate_password_hash, check_password_hash, Resource,
    jwtm, jwt_required, get_jwt, get_jwt_identity, create_access_token, 
    NoAuthorizationError, InvalidSignatureError, RevokedTokenError, DecodeError, InvalidHeaderError,
    JWTDecodeError,
    app, db, ns_auth, ns_suppl, ns_roles, ns_users, ns_rooms, ns_presentations, ns_schedule, ns_presenters)

from db_test.apimodels import *
from db_test.data_controls import *
from db_test.request_parsers import *



#==============================================================
# // REFINED ERROR HANDLERS 
#==============================================================

@app.errorhandler(405)
def return_method_not_allowed_error(error):
    return {
        'status': 'the selected method is disallowed for this URL.'
    }, 405

@app.errorhandler(NoAuthorizationError)     # missing Authorization header
def return_auth_failed_error(error):
    return {
        'status': f'unauthenticated request. error message: {str(error)}'
    }, 401

@app.errorhandler(InvalidSignatureError)    # signature verification failed
def return_auth_failed_error(error):
    return {
        'status': f'unauthenticated request. error message: {str(error)}'
    }, 401

@app.errorhandler(InvalidHeaderError)       # missing Bearer in 'Authorization' header
def return_auth_failed_error(error):
    return {
        'status': f'unauthenticated request. error message: {str(error)}'
    }, 401

@app.errorhandler(RevokedTokenError)        # expired/revoked token
def return_auth_failed_error(error):
    return {
        'status': f'unauthenticated request. error message: {str(error)}'
    }, 401

@app.errorhandler(DecodeError)              # any decoding errors (i.e. not enough segments)
def return_auth_failed_error(error):
    return {
        'status': f'invalid token structure. error message: {str(error)}'
    }, 401

# NB: This workaround leverages cases of custom flask-restx errorhandlers being overriden 
# by the native flask/werkzeug errorhandler, which were first noticed within payload 
# validation procedures. Despite it being an effective fix for the issue, I chose to leave it 
# out of the operational code for the sake of better error message informativity.

# credits: https://github.com/noirbizarre/flask-restplus/issues/530#issuecomment-563956695

# @app.after_request
# def log_response_info(response):
#     data_str = response.data.decode("utf-8")
#     data = json.loads(data_str)
#     data.pop("errors", None)
#     data_str = json.dumps(data)
#     response.data = data_str.encode()
#     return response



# check for token validity.
@jwtm.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    """Searches the invalidated tokens database for the provided token's jti."""

    jti = jwt_payload['jti']
    token = db.session.query(TokenBlocklist.id).filter_by(jti = jti).scalar()
    return token is not None

@jwtm.expired_token_loader
def check_if_token_expired(jwt_header, jwt_payload):
    return {
        'status': 'Token has expired; request a new one via /authorisation.'
    }, 401



#==============================================================
# // REQUEST PERMISSIONS
#==============================================================

def elevated_permissions_required():
    """A decorator to protect routes that are to be accessed by Admins or Presenters.

    Invokes :func:`jwt_required()` to receive the JWT and :func:`get_jwt_identity()` to parse 
    its claims for the role assigned. If the said role is Admin or Presenter, grant access and 
    return the args passed; otherwise, return a 403 forbidden status code along with an error
    message.
    """

    def wrapper(fn):
        @wraps(fn)
        def deco(*args, **kwargs):
            jwt_required()
            identity = get_jwt_identity()
            if identity['role'] in {'Admin', 'Presenter'}:
                return fn(*args, **kwargs)
            else:
                return {
                    'status': 'need an elevated permission (Admin/Presenter) to process this request.'
                }, 403
        return deco
    return wrapper

def admin_permissions_required():
    """A decorator to protect routes that are exclusively available to Admins.

    Operates the same way :func:`elevated_permissions_required()` does, yet only grants access to 
    Admins. Invokes :func:`jwt_required()` to receive the JWT and :func:`get_jwt_identity()` to parse 
    its claims for the role assigned. If the said role is Admin, grant access and 
    return the args passed; otherwise, return a 403 forbidden status code along with an error
    message.
    """

    def wrapper(fn):
        @wraps(fn)
        def deco(*args, **kwargs):
            jwt_required()
            identity = get_jwt_identity()
            if identity['role'] == 'Admin':
                return fn(*args, **kwargs)
            else:
                return {
                    'status': 'need an Admin permission to process this request.'
                }, 403
        return deco
    return wrapper

def get_permissions():
    """A supplementary function to decode an incoming JWT and retrieve id, login and role.
    
    Used by more fine-tuned functions that rely on current user's precise identifiers
    (id and login) to further process a request, as opposed to mere role-based permission
    issuance. An example of this is when :meth:`UserById.put()` gets invoked and has to discriminate
    between updating the token-bearing user's parameters or those of another user.
    """

    identity = get_jwt_identity()
    if identity:
        auth_id = identity.get('id', None)
        auth_login = identity.get('login', None)
        auth_role = identity.get('role', None)
        return {
            'auth_id': auth_id,
            'auth_login': auth_login,
            'auth_role': auth_role
        }
    else:
        return None



#==============================================================
# // AUTHENTICATION / AUTHORISATION / USER REG
#==============================================================

# user authentication and authorisation. retrieve user's identity and grant respective role-based permissions.
#   todos: -implement refresh token functionality.
#          -add "/authorisation"-bound redirects for expired/revoked JWTs.

# logs the user in, issues a JWT upon credentials validation.
@ns_auth.route('', doc = {'description': 'Issues an access JWToken for a matched credentials pair.'})
class Auth(Resource):

    @ns_presenters.param('payload', 'Credentials must be compliant with this model.', _in = 'body')
    @ns_auth.doc(
        description = 'Checks the credentials passed in the request body against those in the database.',
        responses = {
            200: 'Returned upon successful credentials validation along with a token generated.',
            401: 'Returned if user credentials validation failed or token structure was invalid.',
            400: 'Returned upon model validation failure.',
            404: 'Returned if a user record with the provided login was not retrieved from the database.'
        }
    )
    @ns_auth.expect(apimodel_auth, validate = True)

    def post(self):

        payload = ns_auth.payload

        login = payload.get('login', None)
        password = payload.get('password', None)

        # retrieve user information from the 'users' table.
        user = retrieve_user_by_login(login)
        
        # user not found.
        if user['status_code'] == 404:
            return {
                'status': user['status']
            }, user['status_code']

        # runs a password check. if a match is found, creates an access token encapsulating user's 
        # identifiers and role for resource access authorisation.
        if check_password_hash(user['status']['password'], password):
            access_token = create_access_token(
                identity = {
                    'id': user['status']['id'],
                    'login': user['status']['login'], 
                    'role': user['status']['role']
                }
            )
        else:
            return {
                'status': 'validation error. failed to authenticate user with the provided password.'
            }, 401

        # returns the generated token in the response body.
        return {
            'access_token': access_token
        }, 200



# logs the user out, revokes (via blocklist) their token.
@ns_auth.route('/logout', doc = {'description': 'Revokes an active JWT.'})
class Logout(Resource):

    @ns_auth.doc(
        description = 'Reads the JWT from the Authorization header, adds to the blocklist.',
        security = 'Bearer',
        responses = {
            200: 'Returned upon JWT blocklisting and successful logout.',
            401: 'Returned if the JWT has been revoked earlier or upon initial auth failure.',
            422: 'Returned if detected a token structure violation or failed to decode.'
        }
    )
    @jwt_required()

    def delete(self):
        jti = get_jwt()['jti']
        db.session.add(TokenBlocklist(jti = jti))
        db.session.commit()
        return {
            'status': 'JWT revoked; logout complete.'
        }, 200


# adds a new user to the 'users' table. by default, denotes their role as Listener.
@ns_suppl.route('/register')
class Register(Resource):

    @ns_suppl.param('payload', 'New user parameters being added must be compliant with this model.', _in = 'body')
    @ns_suppl.doc(
        description = 'Registers a new user. Open, allows registering Listeners and Presenters.',
        responses = {
            201: 'Returned upon successful credentials validation along with a token generated.',
            400: 'Returned upon model validation failure.',
            409: 'Returned if a user with the provided login already exists.',
            422: 'Returned upon invalid credential(s) format detection.'
        }
    )
    @ns_suppl.expect(apimodel_user_post, validate = True)

    def post(self):
        
        # retrieves and validates prospective user attributes from the request body.
        payload = ns_suppl.payload

        login = payload.get('login', None)
        password = payload.get('password', None)
        role = payload.get('role', 'Listener')

        # checks the credentials format.
        if login in {None, ''}:
            return {
                'status': 'missing or invalid login. please retry with proper credentials.'
            }, 422
        if password in {None, ''}: 
            return {
                'status': 'missing or invalid password. please retry with proper credentials.'
            }, 422
        if ' ' in login:
            return {
                'status': 'login must not contain any spaces.'
            }, 422
        if ' ' in password:
            return {
                'status': 'password must not contain any spaces.'
            }, 422
        if role == 'Admin':
            return {
                'status': 'invalid role. must be one of the following: Presenter, Listener.'
            }, 422

        # converts the textual role representation into a corresponding 'roles' table id.
        role = 2 if role == 'Presenter' else 3

        # converts a plaintext password into a SHA256-encrypted value and attempts registering a user.
        resp = register_user(login, generate_password_hash(password), role)
        return {
            'status': resp['status']
        }, resp['status_code']



#==============================================================
# // DATABASE OPERATIONS (CORE)
#==============================================================
#==============================================================
# ⬛ ROLES
#==============================================================

# 'roles' defines a set of available roles for the users. non-retrieval actions are disallowed.
@ns_roles.route('', doc = {'description': 'Role-related operations.'})
class Roles(Resource):

    @ns_roles.doc(
        description = 'Retrieves a list of roles defined for the system.',
        security = 'Bearer',
        responses = {
            200: 'Returned upon successful roles registry retrieval.',
            401: 'Returned for an unauthenticated request.'
        }
    )
    @jwt_required()

    def get(self):
        return {
            'status': output_roles_json()
        }, 200



#==============================================================
# ⬛ USERS
#==============================================================

# 'users' holds all the user-related data: logins, SHA256-encrypted passwords and roles.
@ns_users.route('', doc = {'description': 'User-related operations.'})
class Users(Resource):

    @ns_users.doc(
        description = 'Retrieves a dictionary of all registered users. Conceals password for non-Admin requests.',
        security = 'Bearer',
        responses = {
            200: 'Returned upon successful users registry retrieval.',
            400: 'Returned upon model validation failure.',
            401: 'Returned for an unauthenticated request.'
        }
    )
    @jwt_required()

    def get(self):   
        permissions = get_permissions()
        if not permissions:
            return {
                'status': 'restricted access. need authenticaton to retrieve user data!'
            }, 401
        return {
            'status': output_users_json(permissions['auth_role'])
        }, 200

    # registers a new user. similar ro /supplementary/register, but is in fact an internal,
    # Admin-exclusive action.
    @ns_users.param('payload', 'New user parameters must be compliant with this model.', _in = 'body')
    @ns_users.doc(
        description = 'Registers a new user. Admin-authorised, allows all roles.',
        security = 'Bearer',
        responses = {
            201: 'Returned upon successful credentials validation along with a token generated.',
            400: 'Returned upon model validation failure.',
            401: 'Returned for an unauthenticated request.',
            403: 'Returned for an unauthorised request due to role violation.',
            409: 'Returned if a user with the provided login already exists.',
            422: 'Returned upon invalid credential(s) format detection.'
        }
    )
    @jwt_required()
    @admin_permissions_required()
    @ns_users.expect(apimodel_user_post, validate = True)

    def post(self):

    # retrieves and validates prospective user attributes from the request body.
        payload = ns_suppl.payload

        login = payload.get('login', None)
        password = payload.get('password', None)
        role = payload.get('role', 'Listener')

        # checks the credentials format.
        if login in {None, ''}:
            return {
                'status': 'missing or invalid login. please retry with proper credentials.'
            }, 422
        if password in {None, ''}: 
            return {
                'status': 'missing or invalid password. please retry with proper credentials.'
            }, 422
        if ' ' in login:
            return {
                'status': 'login must not contain any spaces.'
            }, 422
        if ' ' in password:
            return {
                'status': 'password must not contain any spaces.'
            }, 422
        if role not in {'Admin', 'Presenter', 'Listener'}:
            return {
                'status': 'invalid role. must be one of the following: Admin, Presenter, Listener.'
            }, 422

        # converts the textual role representation into a corresponding 'roles' table id.
        role = 1 if role == 'Admin' else 2 if role == 'Presenter' else 3

        # converts a plaintext password into a SHA256-encrypted value and attempts registering a user.
        resp = register_user(login, generate_password_hash(password), role)
        return {
            'status': resp['status']
        }, resp['status_code']

# manages single-user operations (update and deletion), entries are accessed by an integer id.
@ns_users.route('/<int:id>', doc = {'description': 'User-related operations.'})
@ns_users.param('id', 'An id to access the user record by, must be an integer.')
class UserById(Resource):

    # edits a user record for an authenticated request, throws a 401 otherwise.
    @ns_users.param('payload', 'Attributes and values to override a user record with must be compliant with this model.', _in = 'body')
    @ns_users.doc(
        description = 'Edits a user record data.',
        security = 'Bearer',
        responses = {
            200: 'Returned for successfully implemented changes.',
            400: 'Returned for an empty payload or model validation failure.',
            401: 'Returned for an unauthenticated request.',
            403: 'Returned for an unauthorised request due to role violation or an attempt to override an id.',
            404: 'Returned for an unknown entity.',
            409: 'Returned for a conflicting record due to unique constraint violation.',
            422: 'Returned for an unknown attribute.'
        }
    )
    @jwt_required()
    @ns_users.expect(apimodel_user_put, validate = True)

    def put(self, id):
        permissions = get_permissions()
        if not permissions:
            return {
                'status': 'restricted access. need authenticaton to apply changes.'
            }, 401

        auth_id = permissions['auth_id']
        auth_role = permissions['auth_role']

        # retrieves the target record id from the request body. checks for non-null/non-emptiness, throw a 422 if invalid.
        payload = ns_users.payload               

        # retrieve the 'attribute to override: value' changes dictionary. throw an error message if the dict is empty/missing.
        if not payload or not any(payload):
            return {
                'status': 'empty payload. no changes have been transmitted.'
            }, 400

        # disable id overriding.
        if 'id' in payload:          
            return {
                'status': 'restricted access. IDs are designed to be immutable.'
            }, 403

        # universal changes, self-inflicted.
        if auth_id == id:
            if 'role' in payload:
                if auth_role != 'Admin':           
                    return {
                        'status': 'restricted access. need an "Admin" permission to override roles.'
                    }, 403
            if 'login' in payload:
                if payload['login'] in {None, ''}:
                    return {
                        'status': 'missing or invalid login. please retry with proper credentials.'
                    }, 422
                if ' ' in payload['login']:
                    return {
                        'status': 'login must not contain any spaces.'
                    }, 422

            if 'password' in payload:
                # check the plaintext password for non-null/non-emptiness and lack of space chars.
                if payload['password'] in {None, ''}:
                    return {
                        'status': 'missing or invalid password; must not be an empty string.'
                    }, 422                    
                if ' ' in payload['password']:
                    return {
                        'status': 'password must not contain any spaces.'
                    }, 422

                # SHA256-encrypt the provided plaintext password.
                payload['password'] = generate_password_hash(payload['password'])

        # admin-exclusive, id-targeted actions. this also allows overriding user roles.
        else:
            if auth_role != 'Admin':           
                return {
                    'status': 'restricted access. need an "Admin" permission to apply changes to other users data.'
                }, 403

            if 'role' in payload:
                if payload['role'] not in {'Admin', 'Presenter', 'Listener'}:
                    return {
                        'status': 'invalid role. must be one of the following: Admin, Listener, Presenter.'
                    }, 422
                # converts the roles.
                payload['role'] = 1 if payload['role'] == 'Admin'else 2 if payload['role'] == 'Presenter' else 3

            if 'login' in payload:
                if payload['login'] in {None, ''}:
                    return {
                        'status': 'missing or invalid login. please retry with proper credentials.'
                    }, 422
                if ' ' in payload['login']:
                    return {
                        'status': 'login must not contain any spaces.'
                    }, 422

            if 'password' in payload:
                # check the plaintext password for non-null/non-emptiness and lack of space chars.
                if payload['password'] in {None, ''}:
                    return {
                        'status': 'missing or invalid password; must not be an empty string.'
                    }, 422
                if ' ' in payload['password']:
                    return {
                        'status': 'password must not contain any spaces.'
                    }, 422

                # SHA256-encrypt the provided plaintext password.
                payload['password'] = generate_password_hash(payload['password'])

        # attempt an update. return a 200 if successful, otherwise an error message and a corresponding status code.
        resp = q_upd('users', id, **payload)
        return {
            'status': resp['status']
        }, resp['status_code']

    # delete a user record (accessed by an integer id) from the users registry for an Admin-authorised request, throw a 403 otherwise (401 if no authentication).
    @ns_users.doc(
        description = 'Deletes a user record from the registry.',
        security = 'Bearer',
        responses = {
            204: 'Returned upon successful deletion.',
            401: 'Returned for an unauthenticated request.',
            403: 'Returned for an unauthorised request due to role violation.',
            404: 'Returned for a missing record (including prior deletion).'
        }
    )
    @jwt_required()
    @admin_permissions_required()

    def delete(self, id):
        
        # attempt record deletion. return a 204 if successful, otherwise an error message an a corresponding status code.
        resp = q_del_by_id('users', id)                
        return {
            'status': resp['status']
        }, resp['status_code']


# retrieve user data for an individual user with the specified login. conceal the password unless retrieving own data or running with an Admin-level permission.
@ns_users.route('/<string:login>', doc = {'description': 'User-related operations.'})
class UserByLogin(Resource):

    @ns_users.doc(
        description = 'Retrieves data for a single user with the provided login.', #Conceals a password unless processing an Admin-authorised request or retrieving data about self.',
        security = 'Bearer',
        responses = {
            200: 'Returned upon successful user retrieval.',
            401: 'Returned for an unauthenticated request.',
            404: 'Returned if failed to find a user with the provided login.'
        }
    )
    @jwt_required()

    def get(self, login):
        permissions = get_permissions()
        if not permissions:
            return {
                'status': 'restricted access. need authenticaton to display user data.'
            }, 401
        auth_login = permissions['auth_login']
        auth_role = permissions['auth_role']
        conceal_password = False
        if auth_login != login:
            conceal_password = True
        if auth_role == 'Admin':
            conceal_password = False
        user = retrieve_user_by_login(login, conceal_password)
        return {
            'status': user['status']
        }, user['status_code']



#==============================================================
# ⬛ ROOMS
#==============================================================

# 'rooms' is a registry for all the existing locations to host presentations.
@ns_rooms.route('', doc = {'description': 'Room-related operations.'})
class Rooms(Resource):

    # retrieve a list of all available rooms for an authorised request, throw a 403 otherwise.
    @ns_rooms.doc(
        description = 'Retrieves the rooms registry.',
        security = 'Bearer',
        responses = {
            200: 'Returned upon successful retrieval.',
            401: 'Returned for an unauthenticated request.',
            403: 'Returned for an unauthorised request due to role violation.'
        }
    )
    @jwt_required()
    @elevated_permissions_required()

    def get(self):

        return {
            'status': output_room_json()
        }, 200

    # add a new room with the specified name for an Admin-authorised request, throw a 403 otherwise. room name is passed as a stringified value for the 'room_name' key in the request body.
    @ns_rooms.param('payload', 'New room parameters must be compliant with this model.', _in = 'body')
    @ns_rooms.doc(
        description = 'Adds a new room to the registry.',
        security = 'Bearer',
        responses = {
            201: 'Returned upon successfully added room.',
            400: 'Returned upon model validation failure.',
            401: 'Returned for unauthenticated requests.',
            403: 'Returned for an unauthorised request due to role violation.'
        }
    )
    @jwt_required()
    @admin_permissions_required()
    @ns_rooms.expect(apimodel_room_post, validate = True)


    def post(self):

        payload = ns_rooms.payload

        room_name = payload.get('name', None)

        # attempt adding a record. return a 201 if successful, otherwise an error message and a corresponding status code.
        resp = q_add('room', name = room_name)
        return {
            'status': resp['status']
        }, resp['status_code']

@ns_rooms.route('/<int:id>', doc = {'description': 'User-related operations.'})
@ns_rooms.param('id', 'An id to access the room record by, must be an integer.')
class RoomById(Resource):

    # edit room data for an Admin-authorised request, throw a 403 otherwise.
    @ns_presenters.param('payload', 'Attributes and values to override a room with must be compliant with this model.', _in = 'body')
    @ns_rooms.doc(
        description = 'Updates a room data.',
        security = 'Bearer',
        responses = {
            200: 'Returned upon successful room data retrieval.',
            400: 'Returned for an empty payload or model validation failure.',
            401: 'Returned for an unauthenticated request.',
            403: 'Returned for an unauthorised request due to role violation or an attempt to override an id.'
        }
    )
    @jwt_required()
    @admin_permissions_required()
    @ns_rooms.expect(apimodel_room_put, validate = True)
    
    def put(self, id):

        payload = ns_rooms.payload

        # retrieve the 'attribute to override: value' changes dictionary. throw an error message if the dict is empty/missing.
        if not payload or not any(payload):
            return {
                'status': 'empty payload. no changes have been transmitted.'
            }, 400

        # disable id overriding.
        if 'id' in payload:          
            return {
                'status': 'restricted access. IDs are designed to be immutable.'
            }, 403
        
        if 'name' in payload:
            if payload['name'] in {None, ''}:
                return {
                    'status': 'missing or invalid room name.'
                }, 422

        # attempt an update. return a 200 if successful, otherwise an error message and a corresponding status code.
        resp = q_upd('room', id, **payload)
        return {
            'status': resp['status']
        }, resp['status_code']

    # delete a room (accessed by an integer id) from the room registry for an Admin-authorised request, throw a 403 otherwise.    
    @ns_rooms.doc(
        description = 'Deletes a room from the registry.',
        security = 'Bearer',
        responses = {
            200: 'Returned upon successful deletion.',
            401: 'Returned for an unauthenticated request.',
            403: 'Returned for an unauthorised request due to role violation.',
            404: 'Returned for a missing record (including prior deletion).'
        }
    )
    @jwt_required()
    @admin_permissions_required()

    def delete(self, id):

        # attempt record deletion. return a 204 if successful, otherwise an error message an a corresponding status code.
        resp = q_del_by_id('room', id)                
        return {
            'status': resp['status']
        }, resp['status_code']



#==============================================================
# ⬛ PRESENTATIONS
#==============================================================

# 'presentations' holds all the data regarding the presentations available: titles, descriptions, start/end times and URL's.
@ns_presentations.route('', doc = {'description': 'Presentation-related operations.'})
class Presentations(Resource):

    @ns_presentations.doc(
        description = 'Retrieves the presentations registry.',
        security = 'Bearer',
        responses = {
            200: 'Returned upon successful retrieval.',
            400: 'Returned for an empty payload',
            401: 'Returned for an unauthenticated request.',
            403: 'Returned for an unauthorised request due to role violation.'
        }
    )
    @jwt_required(optional = True)

    def get(self):
        auth = False
        permissions = get_permissions()
        if permissions:
            auth = True
        return {
            'status': output_pres_json(auth)
        }, 200

    # add a new presentation with the specified parameters for an Admin/Presenter-authorised request, throw a 403 otherwise (401 if no authentication).
    @ns_presentations.param('payload', 'New presentation parameters must be compliant with this model.', _in = 'body')
    @ns_presentations.doc(
        description = 'Adds a new presentration to the registry.',
        security = 'Bearer',
        responses = {
            201: 'Returned upon successfully adding a new room.',
            400: 'Returned upon model validation failure.',
            401: 'Returned for an unauthenticated request.',
            403: 'Returned for an unauthorised request due to role violation.'
        }
    )
    @jwt_required()
    @elevated_permissions_required()
    @ns_presentations.expect(apimodel_presentation_post, validate = True)

    def post(self):

        # extract the presentation parameters from their corresponding key-value pairs. return an error message if any is missing.
        payload = ns_presentations.payload
        title = payload.get('title', None)
        desc = payload.get('description', None)
        duration = payload.get('duration', None)
        url = payload.get('url', None)
        if None in {title, desc, duration, url} or '' in {title, desc, url} or duration == 0:
            return {
                'status': 'corrupted request body. one or more parameter(s) was omitted or had no value.'
            }, 400

        # attempt adding a record. return a 201 if successful, otherwise an error message and a corresponding status code.
        resp = q_add('presentation', title = title, description = desc, duration = duration, url = url)
        return {
            'status': resp['status']
        }, resp['status_code']

@ns_presentations.route('/<int:id>', doc = {'description': 'Presentation-related operations.'})
@ns_presentations.param('id', 'An id to access the presentation record by, must be an integer.')
class PresentationById(Resource):

    # edit presentation data for an Admin/Presenter-authorised request, throw a 403 otherwise.
    @ns_presentations.param('payload', 'Attributes and values to override a presentation with must be compliant with this model.', _in = 'body')
    @ns_presentations.doc(
        description = 'Edits a presentation record.',
        security = 'Bearer',
        responses = {
            200: 'Returned for successfully implemented changes.',
            400: 'Returned for an empty payload or model validation failure.',
            401: 'Returned for an unauthenticated request.',
            403: 'Returned for an unauthorised request due to role violation or an attempt to override an id.',
            409: 'Returned for a conflict detected.',
            422: 'Returned for an invalid duration value.'
        }
    )
    @jwt_required()
    @elevated_permissions_required()
    @ns_presentations.expect(apimodel_presentation_put, validate = True)

    def put(self, id):

        # retrieve the 'attribute to override: value' changes dictionary. throw an error message if the dict is empty/missing. 
        payload = ns_presentations.payload

        if not payload or not any(payload):
            return {
                'status': 'empty payload. no changes have been transmitted.'
            }, 400

        # disable id overriding.
        if 'id' in payload:          
            return {
                'status': 'restricted access. IDs are designed to be immutable.'
            }, 403
        if 'duration' in payload:
            if payload['duration'] == 0:
                return {
                    'status': 'invalid duration value; must be non-zero.'
                }, 422

        # attempt an update. return a 200 if successful, otherwise an error message and a corresponding status code.
        resp = q_upd('presentation', id, **payload)
        return {
            'status': resp['status']
        }, resp['status_code']
    
    # delete a presentation from the presentations registry for an Admin-authorised request, throw a 403 otherwise (401 if no authentication).
    @ns_presentations.doc(
        description = 'Deletes a presentation record.',
        security = 'Bearer',
        responses = {
            200: 'Returned upon successful deletion.',
            401: 'Returned for an unauthenticated request.',
            403: 'Returned for an unauthorised request due to role violation.',
            404: 'Returned for a missing record (including prior deletion).'
        }
    )
    @jwt_required()
    @admin_permissions_required()
    
    def delete(self, id):

        # attempt record deletion. return a 204 if successful, otherwise an error message an a corresponding status code.
        resp = q_del_by_id('users', id)                
        return {
            'status': resp['status']
        }, resp['status_code']



#==============================================================
# ⬛ SCHEDULE
#==============================================================

# 'schedule' holds the data about presentations available and their respective time slots and locations.
@ns_schedule.route('', doc = {'description': 'Schedule-related operations.'})
class Schedule(Resource):

    @ns_schedule.param('filterby', 'An attribute to filter schedule entries by.')
    @ns_schedule.param('value', 'A value to filter schedule entries by.')
    @ns_schedule.doc(
        description = 'Returns current schedule. Allows specifying a filtering parameter "filterby"\
        with options "room" and "title", and a value to filter by ("value" parameter). If either \
        is missing, output all schedule entries. If "filterby" receives an unknown option, \
        return an error.',
        security = 'Bearer',
        responses = {
            200: 'Returned upon successful schedule record(s) retrieval.',
            400: 'Returned for an invalid query parameter.',
            401: 'Returned for an unauthenticated request.',
            403: 'Returned for an unauthorised request.',
            404: 'Returned if no records were found matching the criterion.',
            422: 'Returned for an unknown filtering attribute.'
        } 
    )
    @jwt_required()
    @ns_schedule.expect(parser_schedule_get, validate = True)

    def get(self):

        params = parser_schedule_get.parse_args()
        filter_attribute = params.get('filterby', None)
        filter_value = params.get('value', None)

        if filter_attribute and filter_value:
            if filter_attribute not in {'room', 'title'}:
                return {
                    'status': 'encountered an unknown attribute. allowed filters are "room", "title".'
                }, 422

            filter_attribute = 'room.name' if filter_attribute == 'room' else 'presentation.title'
        else:
            filter_attribute = filter_value = None

        # stringify a condition and run the query. return the (filtered) schedule records or an error message and a 404. 
        condition_refined = f'{filter_attribute} == "{filter_value}"' if filter_attribute and filter_value else None

        resp = output_schedule(condition_refined)
        return {
            'status': resp['status']
        }, resp['status_code']

    # add a new schedule record with the specified parameters for an Admin/Presenter-authorised request, throw a 403 otherwise.
    @ns_schedule.param('payload', 'New schedule record parameters must be compliant with this model.', _in = 'body')
    @ns_schedule.doc(
        description = 'Adds a new record to the schedule if no conflicts are detected with other rooms and overlapping time slots; otherwise, display these conflicts.',
        security = 'Bearer',
        responses = {
            201: 'Returned upon successful slot booking.',
            400: 'Returned upon model validation failure.',
            401: 'Returned for an unauthenticated request.',
            403: 'Returned for an unauthorised request.',
            404: 'Returned for corrupted metadata.',
            409: 'Returned for a detected conflicting slot.',
            422: 'Returned for invalid time syntax.'
        } 
    )
    @jwt_required()
    @elevated_permissions_required()
    @ns_schedule.expect(apimodel_schedule_post, validate = True)

    def post(self):

        # extract the slot parameters from their corresponding key-value pairs. return an error message if any is missing.
        payload = ns_schedule.payload

        title = payload.get('title', None)
        start_time = payload.get('time_start', None)
        room_name = payload.get('room', None)

        if '' in {title, start_time, room_name}:
            return {
                'status': 'corrupted request body. one or more parameter(s) was omitted or had no value.'
            }, 400

        # attempt adding a schedule slot. return a 201 if successful, otherwise an error message and a corresponding status code.
        resp = book_slot(title, start_time, room_name)

        return {
            'status': resp['status']
        }, resp['status_code']

@ns_schedule.route('/<int:id>', doc = {'description': 'Schedule-related operations.'})
@ns_schedule.param('id', 'An id to access the schedule entry, must be an integer.')
class ScheduleSlotById(Resource):

    # edit a schedule record for an Admin-authorised request, throw a 403 otherwise.
    @ns_presenters.param('payload', 'Attributes and values to override a schedule record with must be compliant with this model.', _in = 'body')
    @ns_schedule.doc(
        description = 'Edits a schedule record.',
        security = 'Bearer',
        responses = {
            200: 'Returned upon successful schedule entry update.',
            400: 'Returned for an empty payload or model validation failure.',
            401: 'Returned for an unauthenticated request.',
            403: 'Returned for an unauthorised request due to role violation or an attempt to override an id.',
            404: 'Returned for corrupted metadata.',
            409: 'Returned for a detected conflict.',
            422: 'Returned for invalid time syntax or blank attribute values.'
        } 
    )
    @jwt_required()
    @admin_permissions_required()
    @ns_schedule.expect(apimodel_schedule_put, validate = True)

    def put(self, id):

        # retrieve the 'payload' dict holding key-value pairs of the overrides. throw an error message if the dict is empty/missing.
        payload = ns_schedule.payload
        if not payload or not any(payload):
            return {
                'status': 'empty payload. no changes have been transmitted.'
            }, 400

        # disable id overriding.
        if 'id' in payload:          
            return {
                'status': 'restricted access. IDs are designed to be immutable.'
            }, 403
        if 'title' in payload:
            if payload['title'] == '':
                return {
                    'status': 'invalid title; must not be an empty string.'
                }, 422
        if 'time_start' in payload:
            if payload['time_start'] == '':
                return {
                    'status': 'invalid time value; must not be an empty string.'
                }, 422
        if 'room' in payload:
            if payload['room'] == '':
                return {
                    'status': 'invalid room value; must not be an empty string.'
                }, 422

        # attempt an update. return a 200 if successful, otherwise an error message and a corresponding status code.
        resp = update_schedule(id, **payload)
        return {
            'status': resp['status']
        }, resp['status_code']

    # delete a schedule entry (accessed by an integer id) from the schedule for an Admin-authorised request, throw a 403 otherwise.
    @ns_schedule.doc(
        description = 'Deletes a schedule record.',
        security = 'Bearer',
        responses = {
            200: 'Returned upon successful deletion.',
            401: 'Returned for an unauthenticated request.',
            403: 'Returned for an unauthorised request due to role violation.',
            404: 'Returned for a missing record (including prior deletion).'
        }
    )
    @jwt_required()
    @admin_permissions_required()
    
    def delete(self):

        # attempt record deletion. return a 204 if successful, otherwise an error message an a corresponding status code.
        resp = q_del_by_id('schedule', id)
        return {
            'status': resp['status']
        }, resp['status_code']



#==============================================================
# ⬛ PRESENTERS
#==============================================================

# 'presenters' holds the presenter-to-presentation correspondences data in accordance with the schedule.
@ns_presenters.route('', doc = {'description': 'Presenters-related operations.'})
class Presenters(Resource):

    @ns_presenters.doc(
        description = 'Returns presenters. Allows specifying a filtering parameter "filterby"\
        with options "presenter" and "title", and a value to filter by ("value" parameter). If \
        either is missing, output all schedule entries. If "filterby" receives an unknown option, \
        return an error.',
        security = 'Bearer',
        responses = {
            200: 'Returned upon successful schedule record(s) retrieval.',
            400: 'Returned for request body format violations.',
            401: 'Returned for an unauthenticated request.',
            403: 'Returned for an unauthorised request.',
            404: 'Returned if no records were found matching the criterion.',
            422: 'Returned for an unknown filtering attribute.'
        } 
    )
    @jwt_required()
    @ns_presenters.expect(parser_presenters_get)
    
    def get(self):
        params = parser_schedule_get.parse_args()
        filter_attribute = params.get('filterby', None)
        filter_value = params.get('value', None)

        if filter_attribute and filter_value:
            if filter_attribute not in {'presenter', 'title'}:
                return {
                    'status': 'encountered an unknown attribute. allowed filters are "presenter", "title"'
                }, 422

            filter_attribute = 'users.login' if filter_attribute == 'presenter' else 'presentation.title'
        else:
            filter_attribute = filter_value = None

        # stringify a condition and run the query. return the (filtered) schedule records or an error message and a 404. 
        condition_refined = f'{filter_attribute} == "{filter_value}"' if filter_attribute and filter_value else None

        resp = output_presenters(condition_refined)
        return {
            'status': resp['status']
        }, resp['status_code']

    # add a new presenter with the specified parameters for an Admin/Presenter-authorised request, throw a 403 otherwise.
    @ns_presenters.param('payload', 'New presenter parameters must be compliant with this model.', _in = 'body')
    @ns_presenters.doc(
        description = 'Assign a new presenter if no conflicts are detected with other rooms and overlapping time slots; otherwise, display these conflicts.',
        security = 'Bearer',
        responses = {
            201: 'Returned upon successful presenter assignment.',
            400: 'Returned upon model validation failure.',
            401: 'Returned for an unauthenticated request.',
            403: 'Returned for an unauthorised request.',
            404: 'Returned if no records were found matching the criterion.',
            422: 'Returned for invalid time syntax.'
        } 
    )
    @jwt_required()
    @admin_permissions_required()
    @ns_presenters.expect(apimodel_presenter_post, validate = True)

    def post(self):

        # extract the slot parameters from their corresponding key-value pairs. return an error message if any is missing.
        payload = ns_presenters.payload

        title = payload.get('title', None)
        start_time = payload.get('time_start', None)
        room_name = payload.get('room', None)
        login = payload.get('login', None)

        if '' in {title, start_time, room_name, login}:
            return {
                'status': 'corrupted request body. one or more parameter(s) was omitted or had no value.'
            }, 400

        # attempt adding a presenter. return a 201 if successful, otherwise an error message and a corresponding status code.
        resp = assign_presenter(title, start_time, room_name, login)
        return {
            'status': resp['status']
        }, resp['status_code']
    
@ns_presenters.route('/<int:id>', doc = {'description': 'Presenters-related operations.'})
@ns_presenters.param('id', 'An id to access the presenter record, must be an integer.')
class PresenterById(Resource):

    # edit presenter data for an Admin-authorised request, throw a 403 otherwise.
    @ns_presenters.param('payload', 'Attributes and values to override a presenter record with must be compliant with this model.', _in = 'body')
    @ns_presenters.doc(
        description = 'Edits a presenter record.',
        security = 'Bearer',
        responses = {
            200: 'Returned for successfully implemented changes.',
            400: 'Returned for an empty payload or model validation failure.',
            401: 'Returned for an unauthenticated request.',
            403: 'Returned for an unauthorised request due to role violation or an attempt to override an id.',
            404: 'Returned for corrupted metadata.',
            409: 'Returned for a detected conflict.',
            422: 'Returned for invalid time syntax or blank attribute values.'
        } 
    )
    @jwt_required()
    @elevated_permissions_required()
    @ns_presenters.expect(apimodel_presenter_put, validate = True)

    def put(self, id):

        # retrieve the 'payload' dict holding key-value pairs of the overrides. throw an error message if the dict is empty/missing.
        payload = ns_presenters.payload
        if not payload or not any(payload):
            return {
                'status': 'empty payload. no changes have been transmitted.'
            }, 400

        # disable id overriding.
        if 'id' in payload:          
            return {
                'status': 'restricted access. IDs are designed to be immutable.'
            }, 403
        if 'title' in payload:
            if payload['title'] == '':
                return {
                    'status': 'invalid title; must not be an empty string.'
                }, 422
        if 'time_start' in payload:
            if payload['time_start'] == '':
                return {
                    'status': 'invalid time value; must not be an empty string.'
                }, 422
        if 'room' in payload:
            if payload['room'] == '':
                return {
                    'status': 'invalid room value; must not be an empty string.'
                }, 422
        if 'login' in payload:
            if payload['login'] == '':
                return {
                    'status': 'invalid room value; must not be an empty string.'
                }, 422

        # attempt an update. return a 200 if successful, otherwise an error message and a corresponding status code.
        resp = update_presenter(id, **payload)
        return {
            'status': resp['status']
        }, resp['status_code']

    # delete a presenter (accessed by an integer id) from the presenters registry for an Admin-authorised request, throw a 403 otherwise.
    @ns_presenters.doc(
        description = 'Deletes a presenter.',
        security = 'Bearer',
        responses = {
            200: 'Returned upon successful deletion.',
            401: 'Returned for an unauthenticated request.',
            403: 'Returned for an unauthorised request due to role violation.',
            404: 'Returned for a missing record (including prior deletion).',
        }
    )
    @jwt_required()
    @admin_permissions_required()
    
    def delete(self):

        # attempt record deletion. return a 204 if successful, otherwise an error message an a corresponding status code.
        resp = q_del_by_id('presenters', id)
        return {
            'status': resp['status']
        }, resp['status_code']
    



#==============================================================
# // SUPPLEMENTARY FUNCTIONS
#==============================================================
#==============================================================
# ⬛ TABLE ATTRIBUTES
#==============================================================

# returns a list of attributes for the specified table.
@ns_suppl.route('/get_attributes/<string:table>')
@ns_suppl.param('table', 'A stringified target table name. Allowed options are "roles", "users", "room", "presentation", "schedule", "presenters".')
@ns_suppl.doc(
    description = 'Retrieves a list of attributes for a table with the provided name.',
    responses = {
        200: 'Returned upon successful retrieval.',
        404: 'Returned if failed to find a table with the provided name.'
    }
)
@ns_suppl.expect(table_parser, validate = True)
class TableAttributes(Resource):

    def get(self, table):
        
        attrlist = list_table_attrs(table)
        if not attrlist:
            return {
                'status': 'failed to retrieve a table with the specified name. check for validity.'
            }, 404
        return {
            'status': attrlist
        }, 200



#==============================================================
# ⬛ SCHEDULE CHECK
#==============================================================

# run an availability check for the specified schedule slot for an Admin/Presenter-authorised request, throw a 403 otherwise.
@ns_suppl.route('/check_schedule')
class ScheduleCheck(Resource):

    @ns_suppl.doc(
        description = 'Runs an availability check for a schedule slot with the specified parameters.',
        security = 'Bearer',
        responses = {
            200: 'Returned for a check with no resulting conflicts.',
            400: 'Returned upon model validation failure.',
            401: 'Returned for an unauthenticated request.',
            403: 'Returned for an unauthorised request.',
            404: 'Returned for corrupted metadata',
            409: 'Returned for a conflicting slot.',
            422: 'Returned for non-ISO time syntax.'
        }
    )
    @jwt_required()
    @elevated_permissions_required()
    @ns_suppl.expect(parser_schedule_check, validate = True)

    def get(self):

        params = parser_schedule_check.parse_args()

        # extract the slot parameters. return an error message for any missing.
        target_title = params.get('title', None)
        target_start_time = params.get('time_start', None)
        target_room = params.get('room', None)

        if '' in {target_title, target_start_time, target_room}:
            return {
                'status': 'corrupted request body. one or more parameter(s) was omitted or had no value.'
            }, 400

        if type(target_title) is not str or type(target_start_time) is not str or type(target_room) is not str:
            return {
                'status': 'invalid type for one or more parameter(s). title, time, room and login must all be strings.'
            }, 400

        # attempt retrieval. return a 200 if successful, otherwise an error message an a corresponding status code.
        resp = check_schedule(target_title, target_start_time, target_room)
        return {
            'status': resp['status']
        }, resp['status_code']



#==============================================================
# ⬛ PRESENTER CHECK
#==============================================================

# run an availability check for the specified presenter for an Admin/Presenter-authorised request, throw a 403 otherwise.
@ns_suppl.route('/check_presenter')
class PresenterCheck(Resource):

    @ns_suppl.doc(
        description = 'Runs an availability check for a presenter and a specified time.',
        security = 'Bearer',
        responses = {
            200: 'Returned for a check with no resulting conflicts.',
            400: 'Returned upon model validation failure',
            401: 'Returned for an unauthenticated request.',
            403: 'Returned for an unauthorised request.',
            404: 'Returned for corrupted metadata',
            409: 'Returned for a conflicting presenter assignment.',
            422: 'Returned for non-ISO time syntax.'
        }
    )
    @jwt_required()
    @elevated_permissions_required()
    @ns_suppl.expect(parser_presenters_check, validate = True)

    def get(self):
        
        params = parser_presenters_check.parse_args() 

        # extract the presenter/slot parameters. return an error message for any missing.
        target_title = params.get('title', None)
        target_start_time = params.get('time_start', None)
        target_room = params.get('room', None)
        user_login = params.get('login', None)

        if '' in {target_title, target_start_time, target_room, user_login}:
            return {
                'status': 'corrupted request body. one or more parameter(s) was omitted or had no value.'
            }, 400

        if type(target_title) is not str or type(target_start_time) is not str or type(target_room) is not str or type(user_login) is not str:
            return {
                'status': 'invalid type for one or more parameter(s). title, time, room and login must all be strings.'
            }, 400

        # attempt retrieval. return a 200 if successful, otherwise an error message an a corresponding status code.
        resp = check_presenter(target_title, target_start_time, target_room, user_login)
        return {
            'status': resp['status']
        }, resp['status_code']



#==============================================================
# ⬛ AUTOASSIGNMENT
#==============================================================

# runs a schedule and a presenter check; books a slot and assigns current user as a presenter.
@ns_suppl.route('/autoassign')
class Autoassign(Resource):

    @ns_suppl.param('payload', 'Attributes and values to autoassign with.', _in = 'body')
    @ns_suppl.doc(
        description = 'Adds a presentation with the specified parameters to the schedule and assigns current user as its primary presenter.',
        security = 'Bearer',
        responses = {
            201: 'Returned upon successful booking and assignment.',
            400: 'Returned upon model validation failure.',
            401: 'Returned for an unauthenticated request.',
            403: 'Returned for an unauthorised request.',
            404: 'Returned for corrupted metadata',
            409: 'Returned for a conflicting slot.',
            422: 'Returned for non-ISO time syntax.'
        }
    )
    @jwt_required()
    @ns_suppl.expect(apimodel_schedule_post, validate = True)

    def post(self):

        permissions = get_permissions()
        if not permissions:
            return {
                'status': 'need authentication to self-assign.'
            }, 401
        auth_login = permissions.get('auth_login', None)
        auth_role = permissions.get('auth_role', None)
        if auth_role not in {'Admin', 'Presenter'}:
            return {
                'status': 'restricted access. need an elevated permission (Presenter/Admin) to self-assign.'
            }, 403

        # extract the presenter/slot parameters from their corresponding key-value pairs. return an error message if any is missing.
        payload = ns_suppl.payload

        target_title = payload.get('title', None)
        target_start_time = payload.get('time_start', None)
        target_room = payload.get('room', None)

        if '' in {target_title, target_start_time, target_room}:
            return {
                'status': 'corrupted request body. one or more parameter(s) was omitted or had no value.'
            }, 400

        # attempt booking a slot and assigning current user as the primary presenter. return a 201 if successful, otherwise an error message an a corresponding status code.
        resp = book_and_autoassign(target_title, target_start_time, target_room, auth_login)
        return {
            'status': resp['status']
        }, resp['status_code']
