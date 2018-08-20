import os

from flask.app import Flask

from oidcmsg.key_jar import init_key_jar
from oidcrp import RPHandler

dir_path = os.path.dirname(os.path.realpath(__file__))


def init_oidc_rp_handler(app):
    _jwks_def = app.config.get('KEYS')
    _jwks_def['public_path'] = _jwks_def['public_path'].format(dir_path)
    _jwks_def['private_path'] = _jwks_def['private_path'].format(dir_path)
    _kj = init_key_jar(**_jwks_def)
    rph = RPHandler(base_url=app.config.get('BASE_URL'), hash_seed="BabyHoldOn",
                    keyjar=_kj, jwks_path=app.config.get('PUBLIC_JWKS_PATH'),
                    client_configs=app.config.get('CLIENTS'),
                    services=app.config.get('SERVICES'),
                    verify_ssl=app.config.get('VERIFY_SSL'))

    return rph


def oidc_provider_init_app(name=None, **kwargs):
    name = name or __name__
    app = Flask(name, static_url_path='', **kwargs)
    app.config.from_pyfile(os.path.join(dir_path,'app_cfg.py'))

    app.users = {'test_user': {'name': 'Testing Name'}}

    try:
        from .views import oidc_rp_views
    except ImportError:
        from views import oidc_rp_views

    app.register_blueprint(oidc_rp_views)

    # Initialize the oidc_provider after views to be able to set correct urls
    app.rph = init_oidc_rp_handler(app)

    return app