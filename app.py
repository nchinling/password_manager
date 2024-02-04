import os
from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
import subprocess

basedir = os.path.abspath(os.path.dirname(__file__))
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')

app = Flask(__name__)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///passwords.db'

app.config['SQLALCHEMY_DATABASE_URI'] =\
        'sqlite:///' + os.path.join(basedir, 'passwords.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    app_name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    encrypted_password = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f'<Password {self.username}>'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    account_password = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        return render_template('index.html')
    
    # Fetch all app names from the database
    app_names = [password.app_name for password in Password.query.distinct(Password.app_name)]
    
    return render_template('index.html', app_names=app_names)

@app.route('/app/<app_name>', methods=['GET', 'POST'])
def app_page(app_name):
    if request.method == 'POST':
        key = request.form['key']
        
        # Retrieve the password for the given app_name and key
        password = Password.query.filter_by(app_name=app_name).first()
        
        if password:
            # Decrypt the password using the provided key
            decrypt_command = f"echo '{password.encrypted_password}' | openssl enc -d -aes-256-cbc -a -salt -pass pass:'{key}'"
            decrypted_password = subprocess.check_output(decrypt_command, shell=True).decode().strip()
            
            return render_template('app_page.html', app_name=app_name, password=decrypted_password)
        else:
            return "Password not found for the given app and key."
    
    return render_template('app_page.html', app_name=app_name)


@app.route('/create_password', methods=['GET', 'POST'])
def create_password():
    if request.method == 'POST':
        app_name = request.form['app']
        username = request.form['username']
        password = request.form['password']
        reentered_password = request.form['reentered_password']

        if password != reentered_password:
            password_mismatch_message = 'Passwords do not match!'
            return render_template('create_password.html', password_mismatch_message=password_mismatch_message,
                                    app_name=app_name, username=username, password=password, reentered_password=reentered_password)
        
        # Encrypt the password using OpenSSL
        encrypt_command = f"echo '{password}' | openssl enc -aes-256-cbc -a -salt -pass pass:'{ENCRYPTION_KEY}'"
        encrypted_password = subprocess.check_output(encrypt_command, shell=True).decode().strip()
        
        # Save the encrypted password to the database
        new_password = Password(app_name=app_name, username=username, encrypted_password=encrypted_password)
        db.session.add(new_password)
        db.session.commit()

        return render_template('create_password.html', encrypted_password=encrypted_password)
    return render_template('create_password.html')


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
