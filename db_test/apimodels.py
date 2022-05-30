"""Defines request body models for routes to expect when handling incoming POST/PUT requests."""

from db_test import api, fields

apimodel_auth = api.model(
    'Auth', {
        'login': fields.String(
            'login',
            title = 'login',
            example = 'Fujiwara',
            description = 'User login passed for authentication.',
            required = True
        ),
        'password': fields.String(
            'password',
            title = 'password',
            example = '43t_3sdjc$k!J',
            description = 'User password passed for authentication.',
            required = True
        )
    }
)

apimodel_user_post = api.model(
    'User_post', {
        'login': fields.String(
            'login',
            title = 'login',
            example = 'aWittyUsername',
            description = 'New user login; must not contain space characters.',
            required = True
        ),
        'password': fields.String(
            'password',
            title = 'password',
            example = 'pass1337',
            description = 'New user password; must not contain space characters.',
            required = True
        ),
        'role': fields.String(
            'role',
            title = 'role',
            example = 'Listener',
            description = 'New user role; must be one of the following: "Admin", "Presenter", "Listener". Defaults to Listener.', 
            required = False
        )
    }
)

apimodel_user_put = api.model(
    'User_put', {
        'login': fields.String(
            'login',
            title = 'login',
            example = 'aWittyUsername',
            description = 'New user login; must not contain space characters.',
            required = False
        ),
        'password': fields.String(
            'password',
            title = 'password',
            example = 'pass1337',
            description = 'New user password; must not contain space characters.',
            required = False
        ),
        'role': fields.String(
            'role',
            title = 'role',
            example = 'Listener',
            description = 'New user role; must be one of the following: "Admin", "Presenter", "Listener (default)".', 
            required = False
        )
    }
)

apimodel_room_post = api.model(
    'Room_post', {
        'name': fields.String(
            'room_name',
            title = 'room_name',
            example = 'GYM',
            description = 'A new room name.',
            required = True
        )
    }
)

apimodel_room_put = api.model(
    'Room_put', {
        'name': fields.String(
            'room name',
            title = 'room_name',
            example = 'Primera',
            description = 'A room name to override.',
            required = False
        )
    }
)

apimodel_presentation_post = api.model(
    'Presentation_post', {
        'title': fields.String(
            'title',
            title = 'title',
            example = 'BERT models 101: a crash course',
            description = 'Presentation title (string).',
            required = True
        ),
        'description': fields.String(
            'description',
            title = 'description',
            example = 'A comprehensive overview of BERT models functionality and advancements made in 2021. Presented by John M. Doe, Ph.D',
            description = 'A brief description of the presentation (string).',
            required = True
        ),
        'duration': fields.Integer(
            'duration',
            title = 'duration',
            example = '54',
            description = 'Presentation duration in minutes.',
            required = True
        ),
        'url': fields.String(
            'url',
            title = 'url',
            example = 'https://bitly.com/98K8eH',
            description = 'The presentation URL (string).',
            required = True
        )
    }
)

apimodel_presentation_put = api.model(
    'Presentation_put', {
        'title': fields.String(
            'title',
            title = 'title',
            example = 'BERT models 101: a crash course',
            description = 'Presentation title (string).',
            required = False
        ),
        'description': fields.String(
            'description',
            title = 'description',
            example = 'A comprehensive overview of BERT models functionality and advancements made in 2021. Presented by John M. Doe, Ph.D',
            description = 'A brief description of the presentation (string).',
            required = False
        ),
        'duration': fields.Integer(
            'duration',
            title = 'duration',
            example = '54',
            description = 'Presentation duration in minutes.',
            required = False
        ),
        'url': fields.String(
            'url',
            title = 'url',
            example = 'https://bitly.com/98K8eH',
            description = 'The presentation URL (string).',
            required = False
        )
    }
)

apimodel_schedule_post = api.model(
    'Schedule_post', {
        'title': fields.String(
            'title',
            title = 'title',
            example = 'nltk 101',
            description = 'Requested presentation title.',
            required = True
        ),
        'time_start': fields.String(
            'time_start',
            title = 'time_start',
            example = '1970-01-01T00:00:00',
            description = 'Requested presentation start time; must be in ISO8601 format.',
            required = True
        ),
        'room': fields.String(
            'room',
            title = 'room',
            example = 'Primera',
            description = 'Requested room name.',
            required = True
        )
    }
)

apimodel_schedule_put = api.model(
    'Schedule_put', {
        'title': fields.String(
            'title',
            title = 'title',
            example = 'nltk 101',
            description = 'Requested presentation title.',
            required = False
        ),
        'time_start': fields.String(
            'time_start',
            title = 'time_start',
            example = '1970-01-01T00:00:00',
            description = 'Requested presentation start time; must be in ISO8601 format.',
            required = False
        ),
        'room': fields.String(
            'room',
            title = 'room',
            example = 'Primera',
            description = 'Requested room name.',
            required = False
        )
    }
)

apimodel_presenter_post = api.model(
    'Presenter_add', {
        'title': fields.String(
            'title',
            title = 'title',
            example = 'modern socioeconometrics',
            description = 'Requested presentation title (string).',
            required = True
        ),
        'time_start': fields.String(
            'time_start',
            title = 'time_start',
            example = '1970-01-01T00:00:00',
            description = 'Requested presentation start time (string, ISOformat).',
            required = True
        ),
        'room': fields.String(
            'room',
            title = 'room',
            example = 'Primera',
            description = 'Requested location name (string).',
            required = True
        ),
        'login': fields.String(
            'login',
            title = 'login',
            example = 'Keisuke',
            description = 'Requested presenter login (string).',
            required = True
        ),
    }
)

apimodel_presenter_put = api.model(
    'Presenter_put', {
        'title': fields.String(
            'title',
            title = 'title',
            example = 'modern socioeconometrics',
            description = 'Requested presentation title.',
            required = False
        ),
        'login': fields.String(
            'login',
            title = 'login',
            example = 'ElonMusk',
            description = 'Requested presenter login.',
            required = False
        )
    }
)
