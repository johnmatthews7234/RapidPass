'''All the AUTH'''

import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from rp.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/register', methods=('GET', 'POST'))
def register():
    ''' Login screen and send to register screen '''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        realname = request.form['realname']
        orgname = request.form['orgname']
        billing = request.form['billing']
        venuename = request.form['venuename']
        venueaddress = request.form['venueaddress']

        db = get_db()
        error = None

        # username check
        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        elif not realname:
            error = 'Preferred name is required'
        elif db.execute(
            'SELECT id FROM user WHERE username = ?', (username,)
        ).fetchone() is not None:
            error = 'User {} is aready registered'.format(username)
        
        # Org check
        if not orgname:
            error = 'Organisation Name is required'
        elif not billing:
            error = 'Billing information is required'
        elif db.execute(
            'SELECT id FROM organisation WHERE orgname = ?', (orgname,)
        ).fetchone() is not None:
            error = 'Organisation {} is aready registered'.format(orgname)
        
        # venue check
        if not venuename:
            error = 'Venue name is required.'
        elif not venueaddress:
            error = 'Venue address is required'


        if error is None:
            db.execute(
                'INSERT INTO organisation (orgname, billing) VALUES (?, ?)',
                (orgname, billing)
            )
            db.commit()
            org_id = db.execute(
                'SELECT id FROM organisation WHERE orgname = ?', (orgname,)
            ).fetchone()
            db.execute(
                'INSERT INTO user (username, password, realname, organisation_id)'
                ' VALUES (?, ?, ?, ?)',
                (username, generate_password_hash(password), realname, org_id['id'])
            )
            db.execute(
                'INSERT INTO venue (venuename, venueaddress, organisation_id) VALUES (?, ?, ?)',
                (venuename, venueaddress, org_id['id'])
            )
            db.commit()
            return redirect(url_for('auth.login'))
        flash(error)
    return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    ''' Checks if logon is real and sends to config
        Otherwise, asks user to log on'''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?',
            (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('config.index'))
        flash(error)
    return render_template('auth/login.html')

@bp.before_app_request
def load_logged_in_user():
    ''' Grabs user information for logged in user. Or makes user log on'''
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user where id = ?',
            (user_id,)
        ).fetchone()

@bp.route('/logout')
def logout():
    '''clears session for current user. Forcing a log back in.'''
    session.clear()
    return redirect(url_for('auth.login'))

def login_required(view):
    ''' Checks for logged on user for each view that needs one.
        Redirects to logon if user unavailable.'''
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    return wrapped_view
