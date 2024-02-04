from flask import Flask, render_template, request
import subprocess

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        app_name = request.form['app']
        username = request.form['username']
        password = request.form['password']
        
        # Encrypt the password using OpenSSL
        encrypt_command = f"echo '{password}' | openssl enc -aes-256-cbc -a -salt -pass pass:'{app_name}'"
        encrypted_password = subprocess.check_output(encrypt_command, shell=True).decode().strip()
        
        # Decrypt the password (just for demonstration purposes)
        decrypt_command = f"echo '{encrypted_password}' | openssl enc -d -aes-256-cbc -a -salt -pass pass:'{app_name}'"
        decrypted_password = subprocess.check_output(decrypt_command, shell=True).decode().strip()

        return render_template('index.html', encrypted_password=encrypted_password, decrypted_password=decrypted_password)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
