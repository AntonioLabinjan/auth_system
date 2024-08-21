from flask import Flask, render_template, request, redirect, session, url_for, flash, abort
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import HTTPException
import re
from functools import wraps
import time

app = Flask(__name__)
app.secret_key = 'dis_iz_sikret'  # Should be kept secret and ideally stored in environment variables

# Database Configuration
DATABASE = 'auth_database.db'

# Rate Limiting
failed_login_attempts = {}
RATE_LIMIT = 5  # Max attempts
BLOCK_TIME = 300  # Block time in seconds

# Initialize the database
def init_auth_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        conn.commit()

# Database connection
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Password Validation
def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search("[a-z]", password):
        return False, "Password must contain a lowercase letter."
    if not re.search("[A-Z]", password):
        return False, "Password must contain an uppercase letter."
    if not re.search("[0-9]", password):
        return False, "Password must contain a digit."
    if not re.search("[!@#$%^&*]", password):
        return False, "Password must contain a special character."
    return True, ""

# CSRF Token Generation
@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.pop('_csrf_token', None)
        if not token or token != request.form.get('_csrf_token'):
            abort(403)

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = generate_password_hash(str(time.time()))
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

# Rate limiting decorator
def rate_limit(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        ip = request.remote_addr
        now = time.time()
        if ip in failed_login_attempts:
            attempts, last_attempt_time = failed_login_attempts[ip]
            if attempts >= RATE_LIMIT and now - last_attempt_time < BLOCK_TIME:
                flash(f"Too many login attempts. Try again after {BLOCK_TIME//60} minutes.", "error")
                return redirect(url_for('login'))
            elif now - last_attempt_time > BLOCK_TIME:
                failed_login_attempts[ip] = [0, now]
        else:
            failed_login_attempts[ip] = [0, now]
        return func(*args, **kwargs)
    return wrapped

@app.route('/')
def reroute():
    return redirect(url_for('auth_home'))

@app.route('/auth_home')
def auth_home():
    if 'user_id' in session:
        return render_template('home.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        password_valid, message = validate_password(password)

        if not password_valid:
            flash(message, 'error')
            return render_template('signup.html')

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()

        if user:
            flash('Email is already registered', 'error')
        else:
            cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                           (username, email, hashed_password))
            conn.commit()
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))

        cursor.close()
        conn.close()

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
@rate_limit
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        ip = request.remote_addr

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            failed_login_attempts[ip] = [0, time.time()]  # Reset on successful login
            return redirect(url_for('auth_home'))
        else:
            attempts, last_attempt_time = failed_login_attempts.get(ip, [0, time.time()])
            failed_login_attempts[ip] = [attempts + 1, time.time()]
            flash('Invalid credentials', 'error')

        cursor.close()
        conn.close()

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, HTTPException):
        return e
    return render_template('500.html'), 500

if __name__ == '__main__':
    init_auth_db()  # Initialize the database
    app.run(debug=True)
