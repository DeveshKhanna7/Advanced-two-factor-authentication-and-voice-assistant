from flask import Flask, render_template, request, redirect, url_for, session
import pyotp
import qrcode
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = b'secret_key_for_flask_session'

def generate_secret():
    return pyotp.random_base32()

def generate_qr_code(secret, username, issuer_name='YourApp'):
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name=issuer_name)
    img = qrcode.make(uri)
    return img

def verify_code(secret, user_input):
    totp = pyotp.TOTP(secret)
    return totp.verify(user_input)

def is_token_expired(expiration_time):
    return datetime.utcnow() > expiration_time

@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    if 'secret' not in session:
        secret_key = generate_secret()
        session['secret'] = secret_key
        session['expiration_time'] = datetime.utcnow() + timedelta(minutes=5)
        qr_code = generate_qr_code(secret_key, username)
        return render_template('index.html', username=username, qr_code=qr_code.show())

    if is_token_expired(session['expiration_time']):
        session.pop('secret', None)
        return redirect(url_for('index'))

    return render_template('index.html', username=username)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users_database and users_database[username]['password'] == password:
            session['username'] = username
            return redirect(url_for('index'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('secret', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
