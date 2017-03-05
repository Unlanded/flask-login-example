#! env/bin/python

from datetime import datetime, timedelta    # For session expiration
from flask import Flask, redirect, url_for, request, abort, make_response, render_template
from flask_login import (LoginManager, UserMixin, login_required, login_user, logout_user,
                         current_user)
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import pbkdf2_sha256
from urllib.parse import urlparse, urljoin
from uuid import uuid4


app = Flask(__name__)
app.config.from_object('config')
db = SQLAlchemy(app)

# flask-login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


# Minimal user model
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text, unique=True)
    password_hash = db.Column(db.String(87))
    role = db.Column(db.String(10))
    session_token = db.Column(db.Text)
    session_expiry = db.Column(db.DateTime)

    def __init__(self, username):
        self.username = username

    def __repr__(self):
        return "<User: id={}, name={}>".format(self.id, self.name)

    @property
    def password(self):
        # a la Miguel Grinberg
        raise AttributeError('password is not a readable attribute.')

    @password.setter
    def password(self, password):
        self.password_hash = pbkdf2_sha256.hash(password)
        
    def renew_session(self, expiry_seconds):
        self.session_expiry = datetime.utcnow() + timedelta(seconds=expiry_seconds)

    def start_session(self, expiry_seconds):
        self.session_token = str(uuid4())
        # Use UTC to avoid problems with Daylight Saving Time
        self.session_expiry = datetime.utcnow() + timedelta(seconds=expiry_seconds)
    
    # Override because we are using a session token instead of user id as the remember token.
    def get_id(self):
        return self.session_token

    def verify_password(self, password):
        return pbkdf2_sha256.verify(password, self.password_hash)


# A protected route
@app.route('/')
@login_required
def home():
    return make_response(render_template('main.html'))


# A protected route with role check.
@app.route('/shutdown')
@login_required
def shutdown():
    if current_user.role != 'admin':
        return abort(401)
        
    shutdown = request.environ.get('werkzeug.server.shutdown')
    if not shutdown:
        return abort(500)
    shutdown()
    return 'Shutting down.'


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        next_url = request.args.get("next")
        if not is_safe_url(next_url):
            return abort(400)
        
        user = User.query.filter_by(username=request.form['username']).first()

        if not user:
            return abort(401)

        if user.verify_password(request.form['password']):
            # Start a new 30-second session
            user.start_session(30)
            db.session.add(user)
            db.session.commit()
            login_user(user)

            return redirect(next_url)
        else:
            return abort(401)
    else:
        return make_response(render_template('login.html'))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return make_response(render_template('logout.html'))


# Handle failed login
@app.errorhandler(401)
def login_fail(e):
    return make_response(render_template('fail.html'))


# Callback to reload the user object
@login_manager.user_loader
def load_user(session_token):
    user = User.query.filter_by(session_token=session_token).first()
    if user and datetime.utcnow() < user.session_expiry:
        user.renew_session(30)
        db.session.add(user)
        db.session.commit()
        return user


def create_db():
    db.create_all()

    # create some users
    for i in range(1, 11):
        u = User('user' + str(i))
        u.password = u.username + '_secret'
        if u.username == 'user1':
            u.role = 'admin'
        else:
            u.role = 'user'

        db.session.add(u)
    db.session.commit()


if __name__ == "__main__":
    create_db()
    app.run()
