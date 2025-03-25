from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import requests
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)

# Set up the secret key and database
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database and login manager
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Create a user class to store user data
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Set up the user_loader function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Login failed. Please check your credentials.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists, please choose a different one.', 'danger')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        new_user = User(username=username, password=hashed_password)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully. Please log in.', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('An error occurred while creating the account. Please try again.', 'danger')
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/update_profile', methods=['GET', 'POST'])
@login_required
def update_profile():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Update the user's data
        current_user.username = username
        if password:
            current_user.password = generate_password_hash(password, method='pbkdf2:sha256')

        try:
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))
        except IntegrityError:
            db.session.rollback()
            flash('An error occurred while updating your profile. Please try again.', 'danger')
            return redirect(url_for('update_profile'))

    return render_template('update_profile.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully!', 'success')
    return redirect(url_for('home'))

@app.route('/chatbox')
@login_required
def chatbox():
    return render_template('chatbox.html')

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    user_message = request.json.get('message')
    
    api_url = "https://api-inference.huggingface.co/models/facebook/blenderbot-400M-distill"
    headers = {"Authorization": f"Bearer {os.getenv('HF_API_TOKEN')}"}
    data = {"inputs": user_message}
    
    response = requests.post(api_url, headers=headers, json=data)
    response_data = response.json()
    
    bot_reply = response_data.get('generated_text', 'Sorry, I could not understand that.')
    
    return jsonify({"reply": bot_reply})

@app.route('/test_token', methods=['GET'])
def test_token():
    api_token = os.getenv('HF_API_TOKEN')
    if api_token:
        return f"Token is set: {api_token}", 200
    else:
        return "Token not set.", 400

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='127.0.0.1', port=8000)
