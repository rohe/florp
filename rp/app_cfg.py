PORT = 5001
SERVER_NAME = '127.0.0.1:{}'.format(PORT)
BASE_URL = 'https://{}'.format(SERVER_NAME)

HTML_HOME = 'html'

SECRET_KEY = 'secret_key'
SESSION_COOKIE_NAME = 'florp_session'

PREFERRED_URL_SCHEME = 'https'
KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]
KEYS = {
    'public_path': '{}/keys/rp_jwks',
    'private_path': '{}/priv/rp_jwks',
    'key_defs': KEYDEFS
}
PUBLIC_JWKS_PATH = '{}/{}'.format(BASE_URL, KEYS['public_path'])
SERVICES = ['ProviderInfoDiscovery', 'Registration', 'Authorization',
            'AccessToken', 'RefreshAccessToken', 'UserInfo']

VERIFY_SSL = False

CLIENT_PREFS = {
    "application_type": "web",
    "application_name": "rphandler",
    "contacts": ["ops@example.com"],
    "response_types": ["code", "id_token", "id_token token", "code id_token",
                       "code id_token token", "code token"],
    "scope": ["openid", "profile", "email", "address", "phone"],
    "token_endpoint_auth_method": ["client_secret_basic", 'client_secret_post'],
    'services': SERVICES
}

# The keys in this dictionary are the OPs short user friendly name
# not the issuer (iss) name.

CLIENTS = {
    # The ones that support webfinger, OP discovery and client registration
    # This is the default, any client that is not listed here is expected to
    # support dynamic discovery and registration.
    "": {
        "client_preferences": CLIENT_PREFS,
        "redirect_uris": None,
        "services": {
            'WebFinger': {},
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {},
            'RefreshAccessToken': {},
            'UserInfo': {}
        }
    },
    "google": {
        "issuer": "https://accounts.google.com/",
        "client_id": "xxxxxxxxx.apps.googleusercontent.com",
        "client_secret": "2222222222",
        "redirect_uris": ["{}/authz_cb/google".format(BASE_URL)],
        "behaviour": {
            "response_types": ["code"],
            "scope": ["openid", "profile", "email"],
            "token_endpoint_auth_method": ["client_secret_basic",
                                           'client_secret_post']
        },
        "allow": {
            "issuer_mismatch": True
        },
        # "userinfo_request_method": "GET",
        "services": {
            'ProviderInfoDiscovery': {},
            'Authorization': {},
            'AccessToken': {},
            'RefreshAccessToken': {},
            'UserInfo': {}
        }
    }
}
