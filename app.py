from flask import Flask, request, render_template, redirect, session, url_for, flash
import sqlite3
import hashlib
import jwt
from datetime import datetime, timedelta
from functools import wraps

# Create Flask app
app = Flask(__name__)
app.secret_key = 'simple_secret_key'  # Used for flash messages and session management

# JWT secret key for signing tokens
JWT_SECRET = 'simple_secret_key'

# Function to initialize the SQLite database
def init_db():
    conn = sqlite3.connect('users.db')  # Create/connect to the database
    cursor = conn.cursor()
    
    # Create users table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

init_db()

def create_token(username):
    payload = {
        'username': username,
        'exp': datetime.utcnow() + timedelta(minutes=1)  # Token expires in 30 minutes
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    return token

def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            flash("Please log in to access this page.")
            return redirect(url_for('login'))

        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            request.username = data['username']  # Store username in request context
        except jwt.ExpiredSignatureError:
            flash("Session expired. Please log in again.")
            return redirect(url_for('login'))
        except jwt.InvalidTokenError:
            flash("Invalid session. Please log in again.")
            return redirect(url_for('login'))

        return f(*args, **kwargs)
    return decorated_function


from flask import make_response  # Import to set cookies

@app.route('/')
def home():
    session.pop('_flashes', None)  # Force clear flash messages
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash("Username and password are required")
            return render_template('register.html')

        # Hash the password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            flash("Registration successful! Please log in.")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username already exists")
            return render_template('register.html')
        finally:
            conn.close()

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, hashed_password))
        user = cursor.fetchone()
        conn.close()

        if user:
            token = create_token(username)
            print("Generated JWT:", token)
            resp = make_response(redirect(url_for('protected')))
            resp.set_cookie('token', token, httponly=True)
            flash("Login successful")
            return resp
        else:
            flash("Invalid username or password")
            return render_template('login.html')

    return render_template('login.html')


@app.route('/protected')
@token_required
def protected():
    username = getattr(request, 'username', None)
    return render_template('protected.html', username=username)


if __name__ == '__main__':
    init_db()
    app.run(debug=True,port=3000)
