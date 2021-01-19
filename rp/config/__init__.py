import os
import csv
from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for, send_file
)


from werkzeug.exceptions import abort
from werkzeug.security import check_password_hash, generate_password_hash
from tempfile import mkstemp

from rp.auth import login_required
from rp.db import get_db


bp = Blueprint('config', __name__, url_prefix='/config')


@bp.route('/config')
@login_required
def index():
    db = get_db()

    orgdata = db.execute(
        'SELECT o.id, orgname, billing, username, realname'
        ' FROM organisation o JOIN user u ON o.id = u.organisation_id'
        ' WHERE u.id = ?', (g.user['id'],)
    ).fetchone()

    venuedata = db.execute (
        'SELECT v.id, venuename, venueaddress'
        ' FROM organisation o JOIN venue v ON v.organisation_id = o.id'
        ' WHERE o.id = ?', (orgdata['id'],)
    ).fetchall()
    return render_template('config/index.html', orgdata=orgdata, venuedata=venuedata)

@bp.route('/edituser', methods=['GET', 'POST'])
@login_required
def edituser():
    db = get_db()
    userdata = db.execute(
            'SELECT username, password, realname'
            ' FROM user'
            ' WHERE id = ?',
            (g.user['id'],)
        ).fetchone()

    if request.method == 'POST':
        cpassword = request.form['cpassword']
        npassword = request.form['npassword']
        realname = request.form['realname']
        error = None

        db = get_db()
        userdata = db.execute(
            'SELECT username, password, realname'
            ' FROM user'
            ' WHERE id = ?', (g.user['id'],)
        ).fetchone()

        if not check_password_hash(userdata['password'], cpassword):
            error = 'Incorrect Password'
        if realname is None:
            error = 'A real name is required'
        if error is not None:
            flash(error)
        else:
            if npassword is not None:
                db.execute(
                    'UPDATE user SET password = ? WHERE id = ?',
                    (generate_password_hash(npassword), g.user['id'],)
                )
                db.commit()
            if realname is not userdata['realname']:
                db.execute('UPDATE user SET realname = ? WHERE id = ?',
                    (realname, g.user['id'],)
                )
                db.commit()
            return redirect(url_for('config.index'))
    return render_template('config/edituser.html', userdata=userdata)
    

@bp.route('/editorg', methods=['GET', 'POST'])
@login_required
def editorg():
    db=get_db()
    orgdata = db.execute(
        'SELECT o.id, orgname, billing'
        ' FROM organisation o JOIN user u ON o.id = u.organisation_id'
        ' WHERE u.id = ?', (g.user['id'],)
    ).fetchone()
    if request.method == 'POST':
        error = None
        orgname = request.form['orgname']
        billing = request.form['billing']

        if orgname is None:
            error = 'Organisation name is required.'
        if billing is None:
            error = 'Billing information is required.'
        if error is not None:
            flash(error)
        else:
            db.execute(
                'UPDATE organisation SET orgname = ?, billing = ?'
                ' WHERE id = ?', (orgname, billing, orgdata['id'])
            )
            db.commit()
            return redirect(url_for('config.index'))
    return render_template('config/editorg.html', orgdata=orgdata)

@bp.route('/<int:orgid>/addvenue', methods=['GET', 'POST'])
@login_required
def addvenue(orgid):
    if request.method == 'POST':
        db = get_db()
        error = None
        venuename = request.form['venuename']
        if venuename is None:
            error = 'Venue Name is required.'
        venueaddress = request.form['venueaddress']
        if venueaddress is None:
            error = 'Venue Address is required.'
        
        if error is not None:
            flash(error)
        else:
            db.execute(
                'INSERT INTO venue (venuename, venueaddress, organisation_id)'
                ' VALUES (?, ?, ?)', (venuename, venueaddress, orgid)
            )
            db.commit()
            return redirect(url_for('config.index'))
    return render_template('config/addvenue.html', orgid=orgid)
    

def get_venue(myid):
    venue = get_db().execute(
        'SELECT v.id, v.venuename, v.venueaddress, v.organisation_id'
        ' FROM venue v JOIN user u ON v.organisation_id = u.organisation_id'
        ' WHERE v.id = ? AND u.id = ?', 
        (myid, g.user['id'],)
    ).fetchone()
    if venue  is None:
        abort(404, "Venue id {0} doesn't exist".format(myid))
    return venue

def get_visits(myid):
    db = get_db()
    mycheck = db.execute(
        'SELECT v.id, u.id'
        ' FROM venue v JOIN user u ON v.organisation_id = u.organisation_id'
        ' WHERE v.id = ? AND u.id = ?',
        (myid, g.user['id'])
    ).fetchone()
    if mycheck is None:
        abort(404, "Venue id {0} doesn't exist".format(myid))
    visits =  get_db().execute(
        'SELECT firstname, lastname, phone, visited'
        ' FROM visitor WHERE venue_id = ?', (myid,)
    ).fetchall()
    return visits

@bp.route('/<int:venueid>/viewvenue')
@login_required
def viewvenue(venueid):
    venue = get_venue(venueid)
    visits = get_visits(venueid)
    visitsurl = request.url_root + str(venueid)
    return render_template('config/viewvenue.html', venue=venue, visits=visits, visitsurl=visitsurl)

@bp.route('/<int:venueid>/editvenue', methods=['GET', 'POST'])
@login_required
def editvenue(venueid):
    db = get_db()
    mycheck = db.execute(
        'SELECT v.id, u.id'
        ' FROM venue v JOIN user u ON v.organisation_id = u.organisation_id'
        ' WHERE v.id = ? AND u.id = ?',
        (venueid, g.user['id'])
    ).fetchone()
    if mycheck is None:
        abort(404, "Venue id {0} doesn't exist".format(id))
    if request.method == 'POST':
        error = None
        venuename = request.form['venuename']
        if venuename is None:
            error = 'Venue name is required.'
        venueaddress = request.form['venueaddress']
        if venueaddress is None:
            error = 'Venue address is required.'
        if error is not None:
            flash(error)
        else:
            db.execute(
                'UPDATE venue SET venuename = ?, venueaddress = ?'
                ' WHERE id = ?',
                (venuename, venueaddress, venueid,)
            )
            db.commit()
            return redirect(url_for('config.index'))
    else:
        venuedata = db.execute(
            'SELECT id, venuename, venueaddress'
            ' FROM venue'
            ' WHERE id = ?',
            (venueid,)
        ).fetchone()
        return render_template('config/editvenue.html', venuedata=venuedata)


@bp.route('/<int:venueid>/deletevenue', methods=['POST'])
@login_required
def deletevenue(venueid):
    db = get_db()
    mycheck = db.execute(
        'SELECT v.id, u.id'
        ' FROM venue v JOIN user u ON v.organisation_id = u.organisation_id'
        ' WHERE v.id = ? AND u.id = ?',
        (venueid, g.user['id'])
    ).fetchone()
    if mycheck is None:
        abort(404, "Venue id {0} doesn't exist".format(venueid))
    db.execute('DELETE FROM venue WHERE id = ?', (venueid,))
    db.execute('DELETE FROM visitor WHERE venue_id = ?', (venueid,))
    db.commit()
    return redirect(url_for('configure.index'))

@bp.route('/<int:venueid>/downloadcsv')
@login_required
def downloadcsv(venueid):
    visits = get_visits(venueid)
    handle, filepath = mkstemp()
    with os.fdopen(handle, "wb") as f:
        _writer = csv.writer(f)
        _writer.writerow([b'First Name', b'Last Name', b'Phone', b'Date'])
        _writer.writerows(visits)
    return send_file(filepath, attachment_filename='visits.csv')

