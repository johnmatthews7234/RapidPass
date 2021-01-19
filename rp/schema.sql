DROP TABLE IF EXISTS user;
DROP TABLE IF EXISTS organisation;
DROP TABLE IF EXISTS venue;
DROP TABLE IF EXISTS visitor;

CREATE TABLE organisation (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    orgname TEXT NOT NULL,
    billing TEXT NOT NULL
);

CREATE TABLE user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    realname TEXT NOT NULL,
    organisation_id REFERENCES organisation (id)
);

CREATE TABLE venue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    venuename TEXT NOT NULL,
    venueaddress TEXT NOT NULL,
    organisation_id INT NOT NULL REFERENCES organisation (id)
        ON DELETE RESTRICT
);

CREATE TABLE visitor (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    firstname TEXT NOT NULL,
    lastname TEXT NOT NULL,
    phone TEXT NOT NULL,
    visited TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    venue_id REFERENCES venue (id)
);
