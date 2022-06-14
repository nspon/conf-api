conf_api is a minimalistic REST API used for scheduling presentations.

----

Launch options are as follows:

via cmd/powershell:   
    -navigate to the root folder of the project; 
    -run "set FLASK_APP=exec.py" or "export set FLASK_APP=exec.py" depending on the OS in question;
    -run "python -m flask run"
    -navigate to localhost:5000 in a browser.

via Docker:
    -run "docker run -dp XXXX:5000 nspon/conf_api" in the terminal;
    -navigate to localhost:XXXX in a browser.

direct launch:
    -run the "exec.py" file.
    -navigate to localhost:5000 in a browser.

Upon a successful launch, one should be able to see a SwaggerUI with a brief description of the project and a list of the namespaces/endpoints defined.

----

included are the following:
-db_test package, containing all the data handling scripts;
-exec.py file to launch the application;
-Dockerfile to set up the Docker image;
-conf_datapase.db file to store the conference-related data;
-inv_tokens_database.db file to store invalidated/revoked JWTokens' JTIs;
-requirements.txt file to list all the dependencies needed to run the app;
-README.md.

db_test contents:
-apimodels.py - establishes the incoming POST/PUT request body formats for the API to expect;
-data_controls.py - defines all the database handling functions;
-request_parsers.py - documents query parameters for GET requests on particular endpoints.
-routes_native.py - defines the app routing and endpoints by means of Flask only; treated as obsolete and .gitignore'd.
-routes_restx.py - defines the routing with the use of Flask-RESTX, documented with Swagger.

The conference database is configured via SQLAlchemy's ORM & Automap; the invalidated tokens database is configured via SQLAlchemy Core.
There are 6 tables in the conference database:
-roles - stores the three roles defined within the app, these are not subject to change and only receive GET requests;
-users - stores all the user data: logins, SHA265-encrypted passwords, role IDs;
-room - stores the existing room names;
-presentation - stores the presentations data: titles, descriptions, durations, URLs; 
-schedule - a many-to-many association table to represent the current conferences schedule. References the room and presentation by their respective IDs, also storing the start and end times.
    * This does not have a distinct slot structure, as presentations added can be of arbitrary duration.
      Rather, adding presentations should follow a 'head-to-tail' fashion, running a check for a chosen time beforehand.
      This deals with overlaps and rooms by returning a conflict error message in case more than presentation is being scheduled for the same time. 
-presenters - a many-to-many association table to match presenters with their schedule slots. References the user and presentation by their respective ID's.
    * Handling the presenters data follows a similar pattern to the one in 'schedule', and should produce a warning in case a presenter appears to be in two rooms simultaneously.

The application is a CRUD service for scheduling conferences and handling all related data.
Most of the functionality is accessible with authenticated requests, yet the schedule itself and a list of presentations can facilitate an unauthenticated request (the latter will conceal the presentations' URLs.).
A list of attributes for a chosen table can also be obtained without authentication. 

New users can sign up by sending a POST request to the /supplementary/register, admins can also register new users granting them the Admin role.

Once registered, users can authenticate themselves. This is done by sending a POST request to /authorisation, providing their credentials in the request body.
An access JWT with an expiration time of 15 minutes gets issued in the response upon successful user validation.
To make subsequent authorised requests, this JWT needs to be passed in the 'Authorization' header as "Bearer JWT", where JWT represents the token value obtained.
To log out of the system, one should make a DELETE request to /authorisation/logout. The revoked token's JTI is added to the inv_tokens_database.db and is thus blocklisted.
NB: the token does not get blocklisted upon expiration!

There are three user roles defined for the system.
-Listeners can access all the registries except 'rooms' and edit data about themselves.
-Presenters share their permissions, but can also add and edit data in the 'schedule' and 'presentations' registries.
-Admins have full control of the data, all the deletion and some of the update operations are exclusively accessible to them.

The API contains several namespaces, part of which are used for CRUD operations on tables of the same names, with others having special use.
The latter ones are "authorisation", which documents the auth procedure and logout, and "supplementary", which allows running schedule and presenter availability checks, table attributes lookup and enables an authorised user to select a time and self-assign as a presenter.

While the majority of bulk retrieval operations do not require or take any arguments and output the entire registry as the response, there are several exceptions.
Notably, a request to display current schedule or a list of presenters can optionally take in an attribute to filter by (room/presentation and user/presentation, respectively) and a corresponding value, passed as query parameters.
At the same time, retrieving information about an individual user takes in a required 'login' argument, passed as a part of the path.
Running an availabilty check on schedule needs 3 arguments (title, start time and room); running a check on presenters needs the same arguments and a login.

Create-operations mostly take in a set of arguments in accordance with their respective documented apimodels.
When creating a resource, certain registries will alert the user should a conflict take place with an existing record.
This is expected of user logins (raised a unique constraint error), schedule and presenter records (query condition-regulated), but adding a presentation title or a room name that already exists is acceptable.

Update-operations take in their expected arguments in the same fashion, while the record to be updated is accessed by a numeric ID (integer), passed in as a part of the path.
For obvious reasons, overriding IDs is not supported and will alert the user of this.
Conflicting items handling follows the same pattern as that in Create-operations. 

Lastly, Delete-operations receive an IDs of the record subject to deletion in the same way, as a path-contained integer.

--

Prospective development:
-introducing the use of refresh tokens to enhance and smoothen user authorisation;
-facilitating multiple databases support (presumably through binds);
-implementing redirects for incoming unathenticated requests to protected endpoints;
-setting up views and the HTML representation of the contents;
-enabling database lock;
-overall refactoring and optimisation.
