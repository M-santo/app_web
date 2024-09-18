from flask import Flask, request, jsonify, send_file
from flask import render_template
from flask_sqlalchemy import SQLAlchemy
from flask import send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import csv
import xml.etree.ElementTree as ET
import os
import requests

app = Flask(__name__)
CORS(app)

app = Flask(__name__, static_url_path='', static_folder='static')

app.config['UPLOADS_DEFAULT_DEST'] = 'uploads'
app.config['UPLOADS_DEFAULT_URL'] = 'http://localhost:5000/uploads'

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua_chave_secreta'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('index.html') 

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(username=data['username'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'Registered successfully'})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password, data['password']):
        login_user(user)
        return jsonify({'message': 'Logged in successfully'})
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'})

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'message': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'No selected file'}), 400
    if file and (file.filename.endswith('.csv') or file.filename.endswith('.xml')):
        filename = os.path.join('uploads', file.filename)
        file.save(filename)
        processed_file = process_file(filename)
        return send_file(processed_file, as_attachment=True)
    return jsonify({'message': 'Invalid file type'}), 400

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOADS_DEFAULT_DEST'], filename)

def process_file(filename):
    # Implemente o algoritmo XYZ aqui
    # Este é um exemplo simples que apenas copia o arquivo
    output_filename = 'processed_' + os.path.basename(filename)
    with open(filename, 'r') as input_file, open(output_filename, 'w') as output_file:
        output_file.write(input_file.read())
    return output_filename

@app.route('/modify_algorithm', methods=['POST'])
@login_required
def modify_algorithm():
    data = request.get_json()
    instructions = data['instructions']
    
    # Aqui você chamaria a API do ChatGPT para gerar as modificações
    # Este é um exemplo simulado
    modified_code = get_chatgpt_modifications(instructions)
    
    # Aqui você aplicaria as modificações ao algoritmo XYZ
    # Este é um exemplo simulado
    apply_modifications(modified_code)
    
    return jsonify({'message': 'Algorithm modified successfully'})

def get_chatgpt_modifications(instructions):
    # Simulated ChatGPT API call
    # In a real scenario, you would make an API call to ChatGPT here
    return f"Modified code based on: {instructions}"

def apply_modifications(modified_code):
    # Here you would apply the modifications to your XYZ algorithm
    # This is just a placeholder
    print(f"Applying modifications: {modified_code}")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)