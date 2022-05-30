"""Specifies the database mapping and defines data handling functions.

For the sake of readability, the following functions are split into the following groups:

SUPPLEMENTARY RETRIEVAL COMMANDS
    These functions facilitate accessing conf_database tables and their attributes by 
        stringified names.
    Mainly used within data_controls.py functions, but list_table_attrs can output
        table attributes to the /supplementary/get_attributes/{table} endpoint user.

BULK RETRIEVAL COMMANDS
    These functions output ALL entries for their respective conf_database tables:
        -Roles
        -Users
        -Room
        -Presentation
        -Presenters     * also allows filtering by attributes
        -Schedule       * also allows filtering by attributes

UNIVERSAL DATA HANDLING COMMANDS
    These functions enables non-retrieval operations on singular conf_database data entries, 
        such as insertion, update and deletion.

SPECIAL DATA HANDLING COMMANDS
    These functions are also oriented towards single data entries found by the query, but can 
        also include retrieval opertaions. They facilitate running checks, adding schedule slots,
        registering users, updating, etc.
"""

from db_test import (Session, sqlite3, automap_base, create_engine, 
    IntegrityError, NoInspectionAvailable, UnmappedInstanceError, InvalidRequestError, 
    parse_datetime, datetime_isoformat, duration_isoformat, timedelta, isoerror, db)

# conference database prepping
Base = automap_base()
engine = create_engine('sqlite:///conf_database.db', connect_args = {"check_same_thread": False})
Base.prepare(engine, reflect = True)

roles = Base.classes.roles
users = Base.classes.users
room = Base.classes.room
presentation = Base.classes.presentation
schedule = Base.classes.schedule
presenters = Base.classes.presenters


session = Session(engine)

# token database setup
class TokenBlocklist(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    jti = db.Column(db.String(36), nullable = False)
    # created_at = db.Column(db.DateTime, nullable=False)   # reserved  



#==============================================================
# // SUPPLEMENTARY RETRIEVAL COMMANDS (GET)
#==============================================================

def reftable(table_name: str):
    """Returns the table automap object with the specified name.

    Invokes :func:`getattr` to retrieve a table object. Internal use only.

    :param str table_name: a stringified name to reference a table object by (e.g. "users").
    :return: a dictionary object containing data for all existing rooms.
    :rtype: dict
    """

    return getattr(Base.classes, table_name, None)

def list_table_attrs(table_name: str):
    """Retrieves a list of attributes for a table with the specified name.

    If called through its API endpoint, returns a list of table attributes.

    :param str table_name: a stringified name to reference a table object by.
    :return: a list of all attributes for the target table; None if no table was found.
    :rtype: dict
    """
    try: 
        table = getattr(Base.classes, table_name)
        return table.__table__.columns.keys()
    except AttributeError:
        return None



#==============================================================
# // BULK RETRIEVAL COMMANDS (GET)
#==============================================================

def output_roles_json() -> dict:
    """Returns a dict of defined roles for the system.

    :return: a dictionary object containing data for all defined roles.
    :rtype: dict
    """

    q_roles = session.query(roles).all()
    attrlist = list_table_attrs('roles')
    roles_dict = {
        f'role_{role.id}': {
            attr: getattr(role, attr) for attr in attrlist
        } for role in q_roles
    }
    return roles_dict

def output_users_json(role: str) -> dict:
    """Returns a dict of registered users and their data; conceal passwords for non-Admin users.

    :param str role: determines if users' passwords are to be displayed (visible if "Admin").
    :return: a dictionary object containing data for all registered users.
    :rtype: dict
    """

    q_users = session.query(users).all()
    attrlist = list_table_attrs('users')
    if role != 'Admin':
        attrlist.remove('password')
    users_dict = {
        f'user_{user.id}': {
            attr: getattr(user, attr) if attr != 'role'
            else user.roles.name for attr in attrlist
        } for user in q_users
    }
    return users_dict

def output_room_json() -> dict:
    """Returns a dict of all existing rooms.

    :return: a dictionary object containing data for all existing rooms.
    :rtype: dict
    """

    q_room = session.query(room).all()
    attrlist = list_table_attrs('room')
    room_dict = {
        f'room_{room.id}': {
            attr: getattr(room, attr)for attr in attrlist
        } for room in q_room
    }
    return room_dict

def output_pres_json(auth: bool = False) -> dict:
    """Returns a dict of all presentations; conceal their URLs for unauthenticated users.

    :param bool auth: determines if presentation URLs are to be displayed (only accessible to 
    authenticated users).
    :return: a dictionary object containing data for all existing presentations.
    :rtype: dict
    """

    q_presentation = session.query(presentation).all()
    attrlist = list_table_attrs('presentation')
    if not auth:
        attrlist.remove('url') 
    presentation_dict = {
        f'presentation_{pres.id}': {
            attr: getattr(pres, attr) for attr in attrlist
        } for pres in q_presentation
    }
    return presentation_dict

def output_schedule(condition) -> dict:
    """Returns a dict of all existing schedule records (those fitting a condition, if provided). 

    :param str condition: specifies a condition to filter schedule entries with. must be passed as a
    string of the 'a == "val"' format, where a is an attribute (room_id or presentation_id), and
    val is the corresponding integer value. defaults to None, which retrieves all schedule entries.
    :return: a dictionary object containing data for the schedule entries found *or* an error
    message in case no data was found; an int to be used as an HTTP status code.
    :rtype: dict
    """

    attrlist = list_table_attrs('schedule')
    joined_query = (
        session.query(schedule).join(room).join(presentation).where(eval(condition)) if condition
        else session.query(schedule).join(room).join(presentation).all()
    )
    schedule_dict = {
        f'slot_{slot.id}': {
            'room_name' if attr == 'room_id' 
            else 'title' if attr == 'presentation_id'
            else attr: slot.room.name if attr == 'room_id' 
            else slot.presentation.title if attr == 'presentation_id' 
            else getattr(slot, attr) 
            for attr in attrlist
        } for slot in joined_query
    }
    return {
        'status': schedule_dict if any(schedule_dict) else 'no records found matching this condition.',
        'status_code': 200 if any(schedule_dict) else 404
    }

def output_presenters(condition) -> dict:
    """returns a dict of all presenters (those fitting a condition, if provided). 

    :param condition: specifies a condition to filter schedule entries with. must be passed 
    as a string of the 'a == "val"' format, where 'a' is an attribute (user_id or presentation_id), 
    and 'val' is the corresponding integer value.
    :type condition: string or None
    :return: a dictionary object containing data for the presenters found *or* an error message
    in case no data was found; an int to be used as an HTTP status code.
    :rtype: dict
    """

    attrlist = list_table_attrs('presenters')
    joined_query = (
        session.query(presenters).join(users).join(presentation).where(eval(condition)) if condition 
        else session.query(presenters).join(users).join(presentation).all()
    )
    presenters_dict = {
        f'presenter_{presenter.id}': {
            'presenter_login' if attr == 'user_id' 
            else 'presentation_title' if attr == 'presentation_id'
            else attr: presenter.users.login if attr == 'user_id' 
            else presenter.presentation.title if attr == 'presentation_id'
            else getattr(presenter, attr)
            for attr in attrlist
        } for presenter in joined_query
    }
    return {
        'status': presenters_dict if any(presenters_dict) else 'no records found matching this condition.',
        'status_code': 200 if any(presenters_dict) else 404
    }



#==============================================================
# // UNIVERSAL DATA HANDLING COMMANDS (ADD, UPDATE, DELETE)
#==============================================================

def q_add(table_name: str, **kwargs) -> dict:
    """Adds a new row with specified keyed parameters (kwargs) to a designated table (table_name).

    Raises an sqlalchemy.exc.IntegrityError to be handled by the calling function if the 
    unique constraint is violated and performs a session rollback.

    :param str table_name: a stringified name reference to a target table of insertion.
    :param **kwargs: a key-value collection of the data being added; keys must be table attributes.
    :return: a dictionary object containing the data entry insertion status *or* an error message 
    in case an exception was raised; an int to be used as an HTTP status code.
    :rtype: dict
    :raises sqlite3.IntegrityError: if a unique constraint was violated upon database insertion.
    """

    table = reftable(table_name)
    if not table:
        return {
            'status': 'failed to locate a table with the specified name!',
            'status_code': 404
        }
    try:
        session.add(table(**kwargs))
        session.commit()
        params = {attribute: value for attribute, value in kwargs.items()}
        return {
            'status': f'a record with the parameters {params} has been added to "{table_name}".',
            'status_code': 201
        }

    except IntegrityError as unique_violation:
        session.rollback()
        raise sqlite3.IntegrityError('failed to add an entity to the table') from unique_violation

def q_upd(table_name: str, id: int, **kwargs) -> dict:
    """Updates the selected database entry within table_name with kwargs-specified parameters.

    Returns a status message and an integer to represent the HTTP status code.

    :param str table_name: a stringified name reference to a target table of update.
    :param int id: an integer id of the data entry being modified.
    :param **kwargs: a key-value collection of the data being modified; keys must be table attributes.
    :return: a dictionary object containing the data entry update status *or* an error message
    in case an exception was raised; an int to be used as an HTTP status code.
    :rtype: dict
    """

    table = reftable(table_name)
    try:
        record = session.query(table).filter(table.id == id).update(kwargs)
        session.commit()
        return {
            'status': 'changes applied!' if record == 1 else 'failed to get this record; changes dismissed!',
            'status_code': 200 if record == 1 else 404
        }

    except NoInspectionAvailable:
        session.rollback()
        return {
            'status': 'failed to locate a table with the specified name! NIA',
            'status_code': 404
        }
    except AttributeError:
        session.rollback()
        return {
            'status': 'failed to locate a table with the specified id!',
            'status_code': 404
        }
    except UnmappedInstanceError:
        session.rollback()
        return {
            'status': 'failed to retrieve a record with the specified id!',
            'status_code': 404
        }
    except InvalidRequestError:
        session.rollback()
        return {
            'status': 'encountered an unknown attribute!',
            'status_code': 422
        }
    except IntegrityError as unique_violation:
        session.rollback()
        return {
            'status': 'unique constraint violation!',
            'status_code': 409
        }

def q_del_by_id(table_name: str, id: int) -> dict:
    """Deletes a row with the specified id from the table (table_name).

    Returns a status message (optional) and an integer to represent the HTTP status code.

    :param str table_name: a stringified name reference to a target table of update.
    :param int id: an integer id of the data entry being deleted.
    :return: a dictionary object containing a NoneType status upon successful deletion *or* an error 
    message in case an exception was raised; an int to be used as an HTTP status code.
    :rtype: dict
    """

    table = reftable(table_name)
    try:
        del_record = session.get(table, id)
        session.delete(del_record)
        print(del_record)
        session.commit()
        return {
            # f'record with id {id} has been deleted from "{table_name}"'
            'status': None,
            'status_code': 204
    }
    except NoInspectionAvailable:
        return {
            'status': 'failed to locate a table with the specified name!',
            'status_code': 404
        }
    except UnmappedInstanceError:
        session.rollback()
        return {
            'status': 'failed to retrieve a record with this id!',
            'status_code': 404
        }




#==============================================================
# // SPECIAL DATA HANDLING COMMANDS
#==============================================================

# // GET

def retrieve_user_by_login(username: str, conceal_password: bool = False) -> dict:
    """Retrieves a dict of an individual user's information. 
    
    Conceal their password if needed.
    Returns a status message and an integer to represent the HTTP status code:
    200 for a successful retrieval, along with the information dict,
    404 for a missing user.

    :param str username: a stringified login/username of a user record retrieved.
    :param bool conceal_password: determines whether the password is to be 
    excluded from the output.
    :return: a dictionary object containing user data retrieval status *or* an error message in case 
    an exception was raised; an int to be used as an HTTP status code.
    :rtype: dict
    """
    
    user = session.query(users).filter_by(login = username).first()
    if not user:
        return {
            'status': 'failed to retrieve user with the specified username.',
            'status_code': 404
        }
    attrlist = list_table_attrs('users')
    if conceal_password is True:
        attrlist.remove('password')
    userdata_dict = {
        attr: getattr(user, attr) if attr != 'role' else user.roles.name for attr in attrlist
    }
    return {
        'status': userdata_dict,
        'status_code': 200
    }

def retrieve_metadata(presentation_title: str, start_time: str, room_name: str, user_login: str = None) -> dict:
    """Returns metadata dict for a request to add an entry to schedule/presenter registry.
    
    This also helps to run the corresponding checks for these registries. Internal use only.
    If no requested entity is found, return an error message and throw a 404.

    :param str presentation_title: a stringified title of a target presentation.
    :param str start_time: target start time, represented by an ISO8601-formatted string.
    :param str room_name: a stringified name of a target room.
    :param user_login: a stringified login of a target user/presenter. 
    (optional, used for presenter-related calling functions)
    :type user_login: string or None
    :return: a dictionary object containing schedule entry metadata *or* an error message in case 
    an exception was raised; an int to be used as an HTTP status code.
    :rtype: dict
    """

    # retrieve the user id.
    if user_login:
        try:
            user_id = int(session.query(users).filter_by(login = user_login).first().id)
        except AttributeError:
            return {
                'status': 'failed to retrieve a user with the provided login',
                'status_code': 404
            }

    # retrieve the presentation id and time variables.
    try:
        target_pres = session.query(presentation).filter_by(title = presentation_title).first()
        presentation_id = int(target_pres.id)
        duration = timedelta(minutes = int(target_pres.duration))
        endtime = parse_datetime(start_time) + duration
    except AttributeError:
        return {
            'status': 'failed to retrieve a presentation with the provided title.',
            'status_code': 404
        }
    except isoerror.ISO8601Error:
        return {
            'status': 'invalid datetime syntax. should follow ISO8601: YYYY-MM-DDTHH:MM:SSZ',
            'status_code': 422
        }
    except ValueError:
        return {
            'status': 'one or more time designators are out of range.',
            'status_code': 422
        }

    # retrieve the room id.
    try:
        room_id = int(session.query(room).filter_by(name = room_name).first().id)
    except AttributeError:
        return {
            'status': 'failed to retrieve a room with the provided name.',
            'status_code': 404
        }

    metadata_dict = {
        'user_id': user_id if user_login else None,
        'presentation_title': presentation_title,
        'presentation_id': presentation_id,
        'start_time': start_time,
        'duration': duration_isoformat(duration),
        'end_time': datetime_isoformat(endtime),
        'room_id': room_id,
        'room_name': room_name
    }
    return {
        'status': metadata_dict,
        'status_code': 200
    }

def check_schedule(presentation_title: str, start_time: str, room_name: str) -> dict:
    """Runs an availability check for the requested time and room. 
    
    Returns a dictionary of conflicting slots, should any be found.

    :param str presentation_title: a stringified title of a target presentation.
    :param str start_time: target start time, represented by an ISO8601-formatted string.
    :param str room_name: a stringified name of a target room.
    :return: a dictionary object containing schedule conflicts check result *or* an error message 
    in case an exception was raised; slot metadata; an int to be used as an HTTP status code.
    :rtype: dict
    """
    
    # collect supporting metadata.
    md_resp = retrieve_metadata(presentation_title, start_time, room_name)

    # corrupted metadata.
    if md_resp['status_code'] in {404, 422}:
        return {
            'status': md_resp['status'],
            'status_code': md_resp['status_code']   # 404
        }

    else:    # 200
        payload = md_resp['status']

        starttime = payload['start_time']
        endtime = payload['end_time']
        room_id = payload['room_id']

        # invoke the check. 
        q_sch_conflicts = session.query(schedule).where(
            starttime < schedule.time_end).where(
            endtime > schedule.time_start).where(
            schedule.room_id == room_id
        )

        attrlist = list_table_attrs('schedule')

        # put together a dictionary for all the slots found.
        conflicts = {
            f'conflicting_slot_{slot.id}': {
                'room_name' if attr == 'room_id'
                else 'presentation_title' if attr == 'presentation_id'
                else attr: slot.room.name if attr == 'room_id'
                else slot.presentation.title if attr == 'presentation_id'
                else getattr(slot, attr) for attr in attrlist
            } for slot in q_sch_conflicts
        }

        # return all the taken slots for the provided time/location pair.
        return {
            'status': conflicts if any(conflicts) else 'the selected slot is clear for booking.',
            'status_code': 409 if any(conflicts) else 200,  # 204?
            'metadata': md_resp['status']
        }

def check_presenter(presentation_title: str, desired_start_time: str, room_name: str, user_login: str) -> dict:
    """Runs an availability check for the requested presentation, room and user.
    
    Returns a dictionary of conflicting assignments, should any be found.

    :param str presentation_title: a stringified title of a target presentation.
    :param str start_time: target start time, represented by an ISO8601-formatted string.
    :param str room_name: a stringified name of a target room.
    :param str user_login: a stringified login of a target user/presenter.
    :return: a dictionary object containing presenter conflicts check result *or* an error message 
    in case an exception was raised; slot metadata; an int to be used as an HTTP status code.
    :rtype: dict
    """

    # collect supporting metadata.
    md_resp = retrieve_metadata(presentation_title, desired_start_time, room_name, user_login)

    # corrupted metadata.
    if md_resp['status_code'] in {404, 422}:
        return {
            'status': md_resp['status'],
            'status_code': md_resp['status_code']
        }

    elif md_resp['status_code'] == 200:
        payload = md_resp['status']

        user_id = payload['user_id']
        starttime = payload['start_time']
        endtime = payload['end_time']

        # invoke the check.
        q_pres_conflicts = session.query(schedule).where(
            schedule.presentation_id.in_(
                session.query(presenters.presentation_id).distinct().where(
                    presenters.user_id == user_id
                )
            )
        ).where(
            starttime < schedule.time_end
        ).where(
            endtime > schedule.time_start
        )

        attrlist = list_table_attrs('schedule')

        # put together a dictionary for all the slots found.
        conflicts = {
            f'conflicting_slot_{slot.id}': {
                'room_name' if attr == 'room_id'
                else 'presentation_title' if attr == 'presentation_id'
                else attr: slot.room.name if attr == 'room_id'
                else slot.presentation.title if attr == 'presentation_id'
                else getattr(slot, attr) for attr in attrlist
            } for slot in q_pres_conflicts
        }

        #return slots forcing the presenter to be in several locations at once.
        return {
            'status': conflicts if any(conflicts) else 'the selected slot is clear for assignment.',
            'status_code': 409 if any(conflicts) else 200,  # 204?
            'metadata': md_resp['status']
        }



# // ADD

def register_user(login: str, password: str, role: int) -> dict:
    """Registers a user with the specified credentials.

    :param str login: a stringified user login to register with.
    :param str password: a stringified user password to protect data with.
    :param int role: a user role used to grant permissions with. proposed values are 
    1, 2 and 3, corresponding to role id's in the 'roles' table of the database.
    :return: a dictionary object containing a registration message *or* an error message in case 
    an exception was raised; an int to be used as an HTTP status code.
    :rtype: dict
    """

    try:
        q_add('users', login = login, password = password, role = role)
        return {
            'status': 'registration complete!',
            'status_code': 201
        }
    except sqlite3.IntegrityError:
        return {
            'status': 'registration declined. a user with the provided login already exists!', 
            'status_code': 409
        }

def book_slot(req_pres_title: str, req_start_time: str, req_room_name: str) -> dict:
    """adds a new entry to the 'schedule' table.
    
    with the specified presentation, time and room values.
    return a dictionary of conflicting slots, should any be found.

    :param str req_presentation_title: a stringified title of a target presentation.
    :param str req_start_time: target start time, represented by an ISO8601-formatted string.
    :param str req_room_name: a stringified name of a target room.
    :return: a dictionary object containing an added booking message *or* an error message in case 
    an exception was raised; an int to be used as an HTTP status code.
    :rtype: dict
    """

    # check availability.
    conflicts = check_schedule(req_pres_title, req_start_time, req_room_name)

    # check for metadata integrity.
    if conflicts['status_code'] in {404, 422}:
        print('corrupted metadata.')
        return {
            'status': conflicts['status'],
            'status_code': conflicts['status_code']
        }

    # output any conflicting slots, if found.
    elif conflicts['status_code'] == 409:
        print('located conflicting slot(s); unable to book this slot.')
        return {
            'status': conflicts['status'],
            'status_code': conflicts['status_code']
        }
    # clear for booking.
    else:   # 201
        print('clear for scheduling.')
        md = conflicts['metadata']

        presentation_id = md['presentation_id']
        room_id = md['room_id']
        time_start = md['start_time']
        time_end = md['end_time']

        # add a new entry.
        newslot = q_add('schedule', presentation_id = presentation_id, room_id = room_id, time_start = time_start, time_end = time_end)
        return {
            'status': newslot['status'],
            'status_code': 201
        }     

def assign_presenter(req_pres_title: str, req_start_time: str, req_room_name: str, req_presenter_login: str) -> dict:
    """Adds a new entry to the 'presenters' table.

    Takes specified presentation, time, room and presenter login values.
    Return a dictionary of conflicting assignments, should any be found.

    :param str req_presentation_title: a stringified title of a target presentation.
    :param str req_start_time: target start time, represented by an ISO8601-formatted string.
    :param str req_room_name: a stringified name of a target room.
    :param str req_presenter_login: a stringified login of a target user/presenter.
    :return: a dictionary object containing an assigned presenter message *or* an error message 
    in case an exception was raised; an int to be used as an HTTP status code.
    :rtype: dict
    """

    # check availability.
    conflicts = check_presenter(req_pres_title, req_start_time, req_room_name, req_presenter_login)

    # check for metadata integrity.
    if conflicts['status_code'] in {404, 422}:
        print('corrupted metadata.')
        return {
            'status': conflicts['status'],
            'status_code': conflicts['status_code']
        }

    # output any conflicting slots, if found.
    elif conflicts['status_code'] == 409:
        print('located conflicting slot(s); unable to assign this presenter.')
        return {
            'status': conflicts['status'],
            'status_code': conflicts['status_code']
        }

    # clear for assignment.
    else:   # 204
        print('clear for assignment.')
        md = conflicts['metadata']

        user_id = md['user_id']
        presentation_id = md['presentation_id']

        # add a new entry.
        newslot = q_add('presenters', user_id = user_id, presentation_id = presentation_id)
        return {
            'status': newslot['status'],
            'status_code': 201
        }     
    
def book_and_autoassign(req_pres_title: str, req_start_time: str, req_room_name: str, req_presenter_login: str) -> dict:
    """Runs :func:`book_slot` and :func:`assign_presenter` procedures simultaneously.
    
    Primary use is for first-time additions (i.e. presentations without any current presenters 
    associated).
    Returns a dictionary of conflicting slots or assignments, should any be found.

    :param str req_presentation_title: a stringified title of a target presentation.
    :param str req_start_time: target start time represented by an ISO8601-formatted string.
    :param str req_room_name: a stringified name of a target room.
    :param str req_presenter_login: a stringified login of a target user/presenter.
    :return: a dictionary object containing a combined booking/assignment message *or* a respective 
    error message in case any of these failed; an int to be used as an HTTP status code.
    :rtype: dict
    """

    # attempt booking.
    booking = book_slot(req_pres_title, req_start_time, req_room_name)

    if booking['status_code'] != 201:
        return {
            'status': booking['status'],
            'status_code': booking['status_code']
        }
    else:
        # clear for assignment upon a successful booking.
        assignment = assign_presenter(req_pres_title, req_start_time, req_room_name, req_presenter_login)

        if assignment['status_code'] != 201:
            return {
                'status': assignment['status'],
                'status_code': assignment['status_code']
            }
        else:
            # return with both booking and assignment successful.
            return {
                'status': {
                    'booking': booking['status'],
                    'assignment': assignment['status']
                },
                'status_code': 201
            }



# // UPDATE

def update_schedule(id: int, **kwargs) -> dict:
    """Edits a schedule record with keyword-passed arguments.
    
    Returns a dictionary of conflicting slots, should any be found.

    :param int id: an integer id of a record to be updated.
    :param **kwargs: a key-value collection of the data being added;
    keys must be 'title', 'time_start' or 'room'.
    :keyword title: presentation title to override with; must be a string.
    :keyword time_start: start time to reschedule for, must be an ISO8601-formatted string.
    :keyword room: room name to override with, must be a string.
    :return: a dictionary object containing a schedule update status message *or* an 
    error occured; an int to be used as an HTTP status code.
    :rtype: dict
    """

    current_record = session.get(schedule, id)

    presentation_title = kwargs.get('title', current_record.presentation.title)    
    time_start = kwargs.get('time_start', current_record.time_start)
    room_name = kwargs.get('room', current_record.room.name)

    conf = check_schedule(presentation_title, time_start, room_name)

    # check for metadata integrity:
    if conf['status_code'] in {404, 422}:
        return {
            'status': conf['status'],
            'status_code': conf['status_code']
        }
    md = conf['metadata']
    payload = conf['status']

    presentation_id = md['presentation_id']
    room_id = md['room_id']
    time_end = md['end_time']

    if conf['status_code'] == 409:
        del payload[f'conflicting_slot_{id}']
        if any(payload):
            return {
                'status': payload,
                'status_code': conf['status_code']
            }
            
    resp = q_upd('schedule', id, room_id = room_id, presentation_id = presentation_id, time_start = time_start, time_end = time_end)
    return {
        'status': resp['status'],
        'status_code': resp['status_code']
    }

def update_presenter(id: int, **kwargs) -> dict:
    """Edits a presenter record with keyword-passed arguments.
    
    Returns a dictionary of conflicting assignments, should any be found.

    :param id: an integer id of a record to be updated.
    :param **kwargs: a key-value collection of the data being added;
    keys must be 'title' or 'login'.
    :keyword title: presentation title to override with; must be a string.
    :keyword login: presenter login to assign, must be a string.
    :return: a dictionary object containing a presenter reassignment status message *or* an 
    error occured; an int to be used as an HTTP status code.
    :rtype: dict
    """

    current_record = session.get(schedule, id)

    presentation_title = kwargs.get('title', current_record.presentation.title)    
    time_start = current_record.time_start
    room_name = current_record.room.name
    login = kwargs.get('login', current_record.users.login)

    conf = check_presenter(presentation_title, time_start, room_name, login)

    # check for metadata integrity:
    if conf['status_code'] in {404, 422}:
        return {
            'status': conf['status'],
            'status_code': conf['status_code']
        }
    md = conf['metadata']
    payload = conf['status']

    presentation_id = md['presentation_id']
    user_id = md['user_id']

    if conf['status_code'] == 409:
        del payload[f'conflicting_slot_{id}']
        if any(payload):
            return {
                'status': payload,
                'status_code': conf['status_code']
            }
            
    resp = q_upd('presenters', id, presentation_id = presentation_id, user_id = user_id)
    return {
        'status': resp['status'],
        'status_code': resp['status_code']
    }
