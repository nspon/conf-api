from datetime import datetime, timedelta
from isodate import datetime_isoformat, duration_isoformat, parse_datetime, parse_duration, isoerror
from functools import wraps

from flask import Flask # jsonify, make_response, url_for, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, get_jwt, get_jwt_identity, jwt_required
from flask_jwt_extended.exceptions import (NoAuthorizationError, RevokedTokenError, JWTDecodeError, 
    JWTExtendedException, InvalidHeaderError) # UserClaimsVerificationError,
from jwt import InvalidSignatureError, DecodeError
from flask_restx import Api, Namespace, Resource, fields, reqparse

import sqlite3
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import *
from sqlalchemy.ext.automap import automap_base
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError, NoInspectionAvailable, InvalidRequestError
from sqlalchemy.orm.exc import UnmappedInstanceError

authorizations = {
    'Bearer': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        'description': 'Expected input value: **"Bearer JWT"**, where JWT is the \
                        access token value generated in /authorisation.'
    }
}

app = Flask(__name__)
api = Api(
    app,
    version = 'proto',
    title = 'Conf API',
    description = """
        A minimalistic conference scheduling FLask API.

        Upon registration, users can access (and, depending on their roles, handle) data about 
        themselves, available rooms, upcoming presentations, current schedule and a list of presenters. 

        SQLAlchemy-operated database (ORM scheme for conferences data, core for the token blocklist);
        documentated with Flask-RESTX/Swagger;
        JWT-based auth procedures.

        Navigate to /supplementary/register to get started or use the following Admin credentials: 
            "john_doe_adm" for login; "1234" for password.

        repo @ http://github.com/nspon
    """,
    doc = '/',
    authorizations = authorizations
)

# API namespaces 
ns_auth = api.namespace('authorisation', description = 'Manages JWT-based user login/auth and logout; supports POST, DELETE.')
ns_roles = api.namespace('roles', description = 'Manages data for roles; supports GET.')
ns_users = api.namespace('users', description = 'Manages data for users; supports GET, POST, PUT, DELETE.')
ns_rooms = api.namespace('rooms', description = 'Manages data for rooms; supports GET, POST, PUT, DELETE.')
ns_presentations = api.namespace('presentations', description = 'Manages data for presentations, supports GET, POST, PUT, DELETE.')
ns_schedule = api.namespace('schedule', description = 'Manages current schedule, supports GET, POST, PUT, DELETE.')
ns_presenters = api.namespace('presenters', description = 'Manages data for presenters, supports GET, POST, PUT, DELETE.')
ns_suppl = api.namespace('supplementary', description = 'Manages supplementary operations; supports GET, POST.')

# app config parameters
app.config['SECRET_KEY'] = 'cf0c80c9e0897a28b04a7a3bcc921c7b743bbfbf66ccb02d883013ea415094f9'
app.config['JSON_SORT_KEYS'] = False

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////inv_tokens_database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes = 15)

jwtm = JWTManager(app)
db = SQLAlchemy(app)

from db_test.data_controls import (list_table_attrs, output_roles_json, output_users_json, 
    output_room_json, output_pres_json, output_schedule, output_presenters, q_add, q_upd, 
    q_del_by_id, retrieve_user_by_login, check_schedule, check_presenter, register_user, book_slot, 
    assign_presenter, book_and_autoassign, update_schedule, update_presenter)

from db_test import data_controls, routes_restx

db.create_all()
