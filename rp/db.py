''' Sets up the basic database functions '''

import sqlite3
import click

from flask import current_app, g
from flask.cli import with_appcontext

def get_db():
    ''' If there isn't a db in the settings, creates one and sends it up
        Otherwise, just sends it along'''
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    ''' Grabs the DB and closes same '''
    database = g.pop('db', None)
    if database is not None:
        database.close()

def init_db():
    ''' Initialises the database for the first time of running by running schema.sql '''
    database = get_db()
    with current_app.open_resource('schema.sql') as f:
        database.executescript(f.read().decode('utf8'))

@click.command('init-db')
@with_appcontext
def init_db_command():
    ''' Clear the existing data and create new tables. '''
    init_db()
    click.echo('Initialised the database.')

def init_app(app):
    ''' adds init-db to the command list '''
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
