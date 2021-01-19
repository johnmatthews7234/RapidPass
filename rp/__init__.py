''' Init file for RapidPass '''

import os
from flask import Flask
from flask_qrcode import QRcode

def create_app(test_config=None):
    # Create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        #Change this key before going into production.
        SECRET_KEY = b'\xd7\x85+\xfb\xcb\xe8\x1f\xd2\x10\x82\x80\x03\xab\xc1{\x94',
        DATABASE = os.path.join( app.instance_path, 'rp.sqlite')
    )
    qrcode = QRcode(app)

    if test_config is None:
        #Load the instance config, if it exists when not testing
        app.config.from_pyfile( 'config.py', silent=True)
    else:
        # Load the test config if passed in
        app.config.from_mapping(test_config)

    # Ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    from . import db
    db.init_app(app)

    from . import auth
    app.register_blueprint(auth.bp)

    from rp import config
    app.register_blueprint(config.bp)

    from rp import rapidpass
    app.register_blueprint(rapidpass.bp)
    
    return app

