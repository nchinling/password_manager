import os, secrets
from flask import Flask, render_template, request, redirect, url_for, session 
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
import subprocess

basedir = os.path.abspath(os.path.dirname(__file__))
key = ""

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
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
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<Password {self.username}>'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    account_password = db.Column(db.String(100), nullable=False)
    apps = db.relationship('Password', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Query the database for the user with the provided email
        user = User.query.filter_by(email=email).first()
        
        if user and user.account_password == password:
            # If the user exists and the password matches, set the user in the session
            session['user_id'] = user.id
            return redirect(url_for('home'))
        else:
            # If user does not exist or password does not match, show an error message
            error_message = "Invalid email or password. Please try again."
            return render_template('login.html', email=email, password=password,error=error_message)
    
    return render_template('login.html', email="nchinling@gmail.com", password="840109105351")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        email = request.form['email']
        account_password = request.form['password']
        
        # Check if email already exists in the database
        existing_user = User.query.filter((User.email == email)).first()
        if existing_user:
            error_message = "Email already exists. Please choose another one."
            return render_template('register.html', error=error_message)
        
        # Create a new user
        new_user = User(name=name, username=username, email=email, account_password=account_password)
        db.session.add(new_user)
        db.session.commit()
        
        # Redirect to the login page after successful registration
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/home', methods=['GET'])
def home():
    
    # Fetch all app names from the database
    app_names = [password.app_name for password in Password.query.distinct(Password.app_name)]
    
    return render_template('home.html', app_names=app_names)

@app.route('/app/<app_name>', methods=['GET', 'POST'])
def app_page(app_name):
    global key
    if request.method == 'POST':
        key = request.form['key']
        
        # Retrieve the password for the given app_name and key
        password = Password.query.filter_by(app_name=app_name).first()
        
        if password:
            # Decrypt the password using the provided key
            decrypt_command = f"echo '{password.encrypted_password}' | openssl enc -d -aes-256-cbc -a -salt -pass pass:'{key}'"
            try:
                decrypted_password = subprocess.check_output(decrypt_command, shell=True).decode().strip()
                return render_template('app_page.html', app_name=app_name, app_username = password.username, password=decrypted_password)
            except subprocess.CalledProcessError:
                return render_template('app_page.html', app_name=app_name, error_message="Incorrect key")
        else:
            return render_template('app_page.html', app_name=app_name, error_message="Password not found for the given app and key")
    
    return render_template('app_page.html', app_name=app_name)


@app.route('/create_password', methods=['GET', 'POST'])
def create_password():
    if request.method == 'POST':
        app_name = request.form['app']
        username = request.form['username']
        password = request.form['password']
        reentered_password = request.form['reentered_password']
        key = request.form["key"]

        user_id = session.get('user_id')
        if password != reentered_password:
            password_mismatch_message = 'Passwords do not match!'
            return render_template('create_password.html', password_mismatch_message=password_mismatch_message,
                                    app_name=app_name, username=username, password=password, reentered_password=reentered_password)
        
        # Encrypt the password using OpenSSL
        encrypt_command = f"echo '{password}' | openssl enc -aes-256-cbc -a -salt -pass pass:'{key}'"
        encrypted_password = subprocess.check_output(encrypt_command, shell=True).decode().strip()
        
        # Save the encrypted password to the database
        new_password = Password(app_name=app_name, username=username, encrypted_password=encrypted_password, user_id=user_id)
        db.session.add(new_password)
        db.session.commit()

        return render_template('create_password.html', encrypted_password=encrypted_password)
    return render_template('create_password.html')


@app.route('/edit_app/<app_name>', methods=['POST'])
def edit_app(app_name):
    global key
    edited_username = request.form['edited_username']
    edited_password = request.form['edited_password']
    user_id = session.get('user_id')

    existing_password_object = Password.query.filter_by(app_name=app_name).first()

    if existing_password_object:
        # Encrypt the password using OpenSSL
        encrypt_command = f"echo '{edited_password}' | openssl enc -aes-256-cbc -a -salt -pass pass:'{key}'"
        encrypted_password = subprocess.check_output(encrypt_command, shell=True).decode().strip()
        
        existing_password_object.username = edited_username
        existing_password_object.encrypted_password = encrypted_password
        db.session.commit()

        success_message = "Saved successfully"
    else:
        success_message = "Password entry not found"
    
    return render_template('app_page.html', app_name=app_name, success_message=success_message)


# delete app 
@app.route('/delete_app/<app_name>', methods=['POST'])
def delete_app(app_name):
    if request.method == 'POST':
       
        password = Password.query.filter_by(app_name=app_name).first()
        if password:
            # Delete entry
            db.session.delete(password)
            db.session.commit()
            return redirect(url_for('home'))
        else:
            return "An error occurred."


@app.route('/logout') 
def logout(): 
    session.pop('user_id', None) 
    return render_template('index.html')


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
