from db_test import reqparse

# defines request parsers for incoming GET requests. 

parser_base = reqparse.RequestParser()

parser_schedule_get = parser_base.copy()
parser_schedule_get.add_argument(
    'filterby',
    type = str,
    location = 'args',
    required = False,
    help = 'An attribute to filter records by.',
    choices = ['room', 'title']
)
parser_schedule_get.add_argument(
    'value',
    type = str,
    location = 'args',
    required = False,
    help = 'A value to filter records by.'
)


parser_presenters_get = parser_schedule_get.copy()
parser_presenters_get.replace_argument(
    'filterby',
    type = str,
    location = 'args',
    required = False,
    help = 'An attribute to filter records by.',
    choices = ['title', 'presenter']
)


parser_schedule_check = parser_base.copy()
parser_schedule_check.add_argument(
    'title',
    type = str,
    location = 'args',
    required = True,
    nullable = False,
    help = 'Presentation title, e.g. "modern socioeconometrics".'
)
parser_schedule_check.add_argument(
    'time_start',
    type = str,
    location = 'args',
    required = True,
    nullable = False,
    help = 'ISO8601-formatted start time, e.g. "1970-01-01T00:00:00".'
)
parser_schedule_check.add_argument(
    'room',
    type = str,
    location = 'args',
    required = True,
    nullable = False,
    help = 'Room name, e.g. "Primera".'
)


parser_presenters_check = parser_schedule_check.copy()
parser_presenters_check.add_argument(
    'login',
    type = str,
    location = 'args',
    required = True,
    nullable = False,
    help = 'Presenter login, e.g. "m.n.rothbard".'
)


table_parser = parser_base.copy()
table_parser.add_argument(
    'table',
    type = str,
    location = 'args',
    required = True,
    nullable = False,
    help = 'A table name to retrieve attributes for.',
    choices = ['roles', 'users', 'room', 'presentation', 'schedule', 'presenters']
)
