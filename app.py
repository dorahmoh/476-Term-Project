from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from models import db, User, VaultItem
from utils.password_generator import PasswordGenerator  # Import the password generator
from utils.data_proxy import SensitiveDataProxy
from datetime import timedelta
from flask_bcrypt import Bcrypt
import json
import re


app = Flask(__name__)
app.secret_key = 'key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
bcrypt = Bcrypt(app)

# Session timeout
app.permanent_session_lifetime = timedelta(minutes=15)

# Password Strength Check (for weak password warning)
def is_strong_password(password):
    # Check password length
    if len(password) < 8:
        return False
    # Check for lowercase letters
    if not re.search(r"[a-z]", password):
        return False
    # Check for uppercase letters
    if not re.search(r"[A-Z]", password):
        return False
    # Check for digits
    if not re.search(r"[0-9]", password):
        return False
    # Check for special characters
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

# Singleton pattern for user session
class UserSession:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(UserSession, cls).__new__(cls)
            cls._instance.user_id = None
        return cls._instance

user_session = UserSession()





@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('vault'))
    return redirect(url_for('login'))


@app.route('/generate_password')
def generate_password():
    # Generate a password with default settings (12 characters, special chars, uppercase)
    password_generator = PasswordGenerator(length=12, use_special=True, use_upper=True)
    password = password_generator.generate()
    return jsonify({"password": password})

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        master_password = request.form['master_password']
        confirm_password = request.form['confirm_password']

        # Validate email format
        if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email):
            flash('Invalid email format. Please enter a valid email.', 'danger')
            return render_template('register.html')

        # Check if passwords match
        if master_password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
            return render_template('register.html')

        # Check if the password is weak
        if not is_strong_password(master_password):
            flash('Weak password. Ensure it includes at least one uppercase letter, one lowercase letter, one number, and one special character.', 'danger')
            return render_template('register.html')

        # Validate security questions: only letters allowed
        security_question_1 = request.form['security_question_1']
        security_question_2 = request.form['security_question_2']
        security_question_3 = request.form['security_question_3']

        if not all(re.match(r"^[a-zA-Z\s]+$", answer) for answer in [security_question_1, security_question_2, security_question_3]):
            flash('Security questions must contain only letters and spaces.', 'danger')
            return render_template('register.html')

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(master_password).decode('utf-8')

        # Process the security questions
        security_questions = json.dumps({
            "q1": security_question_1,
            "q2": security_question_2,
            "q3": security_question_3
        })

        # Save the new user to the database
        user = User(email=email, master_password=hashed_password, security_answers=security_questions)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('vault'))

    return render_template('register.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.master_password, password):
            session['user_id'] = user.id
            user_session.user_id = user.id
            session.permanent = True
            flash('Logged in successfully.', 'success')
            return redirect(url_for('vault'))
        flash('Invalid email or password.', 'danger')
    return render_template('login.html')

@app.route('/vault', methods=['GET', 'POST'])
def vault():
    if 'user_id' not in session:
        flash('Please log in to access the vault.', 'danger')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    if request.method == 'POST':
        # Create a new item
        item_type = request.form['item_type']
        data = {
            "username": request.form.get('username'),
            "password": request.form.get('password'),
            "url": request.form.get('url'),
            "credit_card_number": request.form.get('credit_card_number'),
            "cvv": request.form.get('cvv')
        }
        item = VaultItem(user_id=user_id, item_type=item_type, data=data)
        db.session.add(item)
        db.session.commit()
        flash('Item added successfully.', 'success')

    items = VaultItem.query.filter_by(user_id=user_id).all()
    # Mask sensitive data
    for item in items:
        for key, value in item.data.items():
            if value:
                if key in ['password', 'cvv', 'credit_card_number']:  # Fields to mask
                    item.data[key] = '****'  # Mask these fields initially

    return render_template('vault.html', items=items)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    user_session.user_id = None
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/password-generator', methods=['GET'])
def password_generator():
    length = int(request.args.get('length', 12))
    use_special = request.args.get('use_special', 'true') == 'true'
    use_upper = request.args.get('use_upper', 'true') == 'true'

    generator = PasswordBuilder().set_length(length).include_special_characters(use_special).include_uppercase(use_upper)
    password = generator.build()
    return jsonify({"password": password})

# Error handler for unauthorized access
@app.errorhandler(401)
def unauthorized(e):
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure the database tables are created
    app.run(debug=True)
