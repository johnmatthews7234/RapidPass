
from flask import (
    Blueprint, flash, render_template, request
)

from werkzeug.exceptions import abort
from rp.db import get_db

bp = Blueprint('rapidpass',__name__)

@bp.route('/<int:venueid>', methods=('GET', 'POST'))
def check_in(venueid):
    db = get_db()
    venue = db.execute(
        'SELECT v.venuename, v.venueaddress, o.orgname'
        ' FROM venue v JOIN organisation o ON v.organisation_id = o.id'
        ' WHERE v.id = ?', (venueid,)
    ).fetchone()
    if venue is None:
        abort(404, "Venue id {0} doesn't exist.".format(venueid))

    if request.method == 'POST':
        error = None
        firstname = request.form['firstname']
        if firstname is None:
            error = 'First name is required.'
        lastname = request.form['lastname']
        if lastname is None:
            error = 'Last name is required'
        phone = request.form['phone']
        if phone is None:
            error = 'Phone number (or other contact detail) is required.'
        if error is not None:
            flash(error)
        else:
            get_db().execute(
                'INSERT INTO visitor'
                ' (firstname, lastname, phone, venue_id) VALUES (?, ?, ?, ?)',
                (firstname, lastname, phone, venueid)
            )
            db.commit()
            return render_template('rapidpass/thankyou.html', venue=venue)
    else:
        return render_template('rapidpass/checkin.html', venue=venue)

    
