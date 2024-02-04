import os
from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
import subprocess

basedir = os.path.abspath(os.path.dirname(__file__))

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

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        app_name = request.form['app']
        username = request.form['username']
        password = request.form['password']
        
        # Encrypt the password using OpenSSL
        encrypt_command = f"echo '{password}' | openssl enc -aes-256-cbc -a -salt -pass pass:'{app_name}'"
        encrypted_password = subprocess.check_output(encrypt_command, shell=True).decode().strip()
        
        # Save the encrypted password to the database
        new_password = Password(app_name=app_name, username=username, encrypted_password=encrypted_password)
        db.session.add(new_password)
        db.session.commit()

        return render_template('index.html', encrypted_password=encrypted_password)
    return render_template('index.html')

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
