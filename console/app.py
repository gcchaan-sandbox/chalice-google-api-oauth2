from ast import literal_eval
import datetime
from http.cookies import SimpleCookie
from urllib.parse import urlencode

from chalice import Chalice, Response
import google.oauth2.credentials
import google_auth_oauthlib.flow
from googleapiclient.discovery import build

CLIENT_SECRETS_FILE = "chalicelib/client_secret.json"
REDIRECT_URI = 'http://localhost:8000/oauth2callback'
SCOPES = [
    'https://www.googleapis.com/auth/calendar.events',
    'https://www.googleapis.com/auth/calendar.readonly'
]

app = Chalice(app_name='console')


@app.route('/')
def index():
    return {'hello': 'world'}


@app.route('/authorize')
def authorize():

    # Use the client_secret.json file to identify the application requesting
    # authorization. The client ID (from that file) and access scopes are required.
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES)

    # Indicate where the API server will redirect the user after the user completes
    # the authorization flow. The redirect URI is required.
    flow.redirect_uri = REDIRECT_URI

    # Generate URL for request to Google's OAuth 2.0 server.
    # Use kwargs to set optional request parameters.
    authorization_url, state = flow.authorization_url(
        # Enable offline access so that you can refresh an access token without
        # re-prompting the user for permission. Recommended for web server apps.
        access_type='offline',
        # Enable incremental authorization. Recommended as a best practice.
        include_granted_scopes='true')
    print('state')
    print(state)
    return Response(
        body='',
        headers={
            'Location': authorization_url,
            'Set-Cookie': "state=%s" % (state)
            },
        status_code=302
        )


@app.route('/oauth2callback')
def oauth2callback():
    req = app.current_request
    cookieData = req.headers.get('Cookie')
    cookie = SimpleCookie()
    cookie.load(cookieData)
    state = cookie.get('state').value
    print('Cookie')
    print(req.headers.get('Cookie'))
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
    CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = REDIRECT_URI
    authorization_response = 'https://' + req.headers.get('host') + req.context.get('path') + '?' + urlencode(req.query_params)
    flow.fetch_token(authorization_response=authorization_response)
    credentials = flow.credentials
    credentials_dict = credentials_to_dict(credentials)

    return Response(
        body='',
        headers={
            'Location': '/client',
            'Set-Cookie': "credentials=\"%s\"" % (credentials_dict)
            },
        status_code=302
        )


@app.route('/client')
def client():
    req = app.current_request
    cookieData = req.headers.get('Cookie')
    cookie = SimpleCookie()
    cookie.load(cookieData)
    print('cookieData')
    print(cookieData)
    cookie_credentials = literal_eval(cookie.get('credentials').value)
    if (cookie_credentials is None):
        return Response(
            body='',
            headers={'Location': '/authorize'},
            status_code=302
            )
    credentials = google.oauth2.credentials.Credentials(
        **cookie_credentials)

    service = build('calendar', 'v3', credentials=credentials)
    now = datetime.datetime.utcnow().isoformat() + 'Z'
    events_result = service.events().list(calendarId='primary', timeMin=now,
                                        maxResults=10, singleEvents=True,
                                        orderBy='startTime').execute()
    events = events_result.get('items', [])
    return {'files': events}


def credentials_to_dict(credentials):
    return {'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes}
