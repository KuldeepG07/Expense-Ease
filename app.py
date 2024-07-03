from datetime import date, datetime, timedelta, timezone
from functools import wraps
import random
import re
from werkzeug.utils import secure_filename
import pyotp
from sqlalchemy import Date, or_
from flask_wtf import CSRFProtect
from flask import Flask, flash, jsonify, make_response, redirect, render_template, request, send_file, session, url_for
from flask_sqlalchemy import SQLAlchemy
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from collections import defaultdict
from bs4 import BeautifulSoup
from flask_mail import Mail, Message
from authlib.integrations.flask_client import OAuth
from itsdangerous import URLSafeTimedSerializer
from api_key import *
import bcrypt
import os
import pdfkit

app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///expensetracker.db"
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)
app.config['SECRET_KEY'] = "expense_tracker"
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
app.config['UPLOAD_FOLDER'] = 'static/images'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg'}
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'k4gabani@gmail.com'
app.config['MAIL_PASSWORD'] = 'rbod pifg mxoa ppoj'
app.config['MAIL_DEFAULT_SENDER'] = ('Expense Ease','k4gabani@gmail.com')

mail = Mail(app)
otp_secret = pyotp.random_base32()
csrf = CSRFProtect(app)
oauth = OAuth(app)
db = SQLAlchemy(app)

google = oauth.register(
    name = 'google',
    client_id = CLIENT_ID_GOOGLE,
    client_secret = CLIENT_SECRET_GOOGLE,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params  =None,
    token_url='https://oauth2.googleapis.com/token',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params = None,
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs',
    api_base_url = 'https://www.googleapis.com/oauth2/v1/',
    client_kwargs = {'scope':'email openid profile'}
)

github = oauth.register(
    name = 'github',
    client_id = CLIENT_ID_GITHUB,
    client_secret = CLIENT_SECRET_GITHUB,
    authorize_url='https://github.com/login/oauth/authorize',
    authorize_params  =None,
    access_token_url='https://github.com/login/oauth/access_token',
    access_token_params = None,
    api_base_url = 'https://api.github.com/',
    client_kwargs = {'scope':'user:email'}
)

# Session Management
@app.before_request
def session_amangement():
    session.permanent = True
    now = datetime.now() 
    
    if 'last_activity' in session:
        
        last_activity = datetime.fromisoformat(session['last_activity']) 
        print(last_activity)
        session_lifetime = app.config['PERMANENT_SESSION_LIFETIME']
        
        if now - last_activity > session_lifetime:
            session.clear()
            flash('Session out', 'warning')
            return redirect(url_for('login'))
    session['last_activity'] = now.isoformat()


# Models 
class Users(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    joined_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    image = db.Column(db.String, default='default_profile.png')

    def __init__(self, username, password, name, email, image=None):
        self.name = name
        self.email = email
        self.username = username
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        if image is None:
            self.image = 'default_profile.png'

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))
    
class Categories(db.Model):
    __tablename__ = 'categories'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False, unique=True)

class PaymentMethods(db.Model):
    __tablename__ = 'paymentmethods'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False, unique=True)

class Invoices(db.Model):
    __tablename__ = 'invoices'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(Date, nullable=False)
    description = db.Column(db.String(255), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    payee = db.Column(db.String(100), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=False)
    payment_method_id = db.Column(db.Integer, db.ForeignKey('paymentmethods.id'), nullable=False, default=1)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    category = db.relationship('Categories', backref=db.backref('invoices', lazy=True))
    payment_method = db.relationship('PaymentMethods', backref=db.backref('paymentmethods', lazy=True))
    user = db.relationship('Users', backref=db.backref('invoices', lazy=True))


# Allowed file extension function for Profile photo
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# Function to populate data as soon as database created
def seed_categories_methods():
    categories = [{'name':'Household'},
                  {'name':'Food'},
                  {'name':'HealthCare'},
                  {'name':'Entertainment'},
                  {'name':'Transportation'},
                  {'name':'Education'},
                  {'name':'Shopping'},
                  {'name':'Insaurance'},
                  {'name':'Travel'},
                  {'name':'Other'}]
    
    payment_methods = [{'name':'QR/UPI'},
                       {'name':'Netbanking'},
                       {'name':'Cards'},
                       {'name':'EMI'},
                       {'name':'Wallet'},
                       {'name':'Instant Bank transfer'},
                       {'name':'Cash'}]
    
    for cat in categories:
        existing_category = Categories.query.filter_by(name=cat['name']).first()
        if not existing_category:
            category = Categories(name=cat['name'])
            db.session.add(category)
    
    for met in payment_methods:
        existing_method = PaymentMethods.query.filter_by(name=met['name']).first()
        if not existing_method:
            method = PaymentMethods(name=met['name'])
            db.session.add(method)

    db.session.commit()


# Routes
@app.route('/')
def home():
    return render_template('login.html')


@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        existing_user = Users.query.filter_by(username=username).first()

        if existing_user:
            return render_template('register.html', signup_message="User already exists with this Username")

        if not valid_password(password):
            return render_template('register.html', signup_message="Password must be 7-20 characters long, contain at least one uppercase letter, one lowercase letter, one number, and one special symbol.")

        if not valid_email_format(email):
            return render_template('register.html', signup_message="Invalid email format.")

        timeotp = pyotp.TOTP(otp_secret, interval=180)
        otp = timeotp.now()

        try:
            msg_title = "OTP for Registration"
            msg_content = render_template('emails/otp_email.html', otp=otp, name=name)
            msg = Message(msg_title, recipients=[email], html=msg_content)
            mail.send(msg)

            session['user_data'] = {'name': name, 'username': username, 'email': email, 'password': password}
            session['otp'] = otp
            session['otp_expiry'] = (datetime.now() + timedelta(minutes=3)).isoformat()
            flash('OTP sent successfully','success')
            return redirect('/otp-verification')
        except Exception as e:
            db.session.rollback()
            print(f"Error: {e}")
            return render_template('register.html', signup_message="Error while sending OTP. Please try again later.")

    return render_template('register.html')

@app.route('/otp-verification', methods=['GET','POST'])
def otp_verification():
    if request.method == 'POST':
        user_otp = request.form['otp']
        
        if 'otp' in session and 'otp_expiry' in session:
            otp_expiry = datetime.fromisoformat(session['otp_expiry'])
            if datetime.now() > otp_expiry:
                flash("OTP has expired. Please register again.")
                return redirect('/register')
            if session['otp'] == user_otp:
                user_data = session.pop('user_data', None)
                if user_data:
                    name = user_data['name']
                    username = user_data['username']
                    email = user_data['email']
                    password = user_data['password']
                    user = Users(name=name, password=password, email=email, username=username)
                    try:
                        msg_title = "Registration Successfull"
                        msg_content = render_template('emails/registration_email.html', user=user)
                        msg = Message(msg_title, recipients=[email], html=msg_content)
                        mail.send(msg)

                        db.session.add(user)
                        db.session.commit()
                        flash("Registration Successfull","success")
                        return redirect('/login')
                    except Exception as e:
                        flash("Something went wrong. Please try again later.")
                        return render_template('register.html')
            else:
                flash("Invalid OTP. Please re-enter valid OTP.","danger")
    return render_template('otp_verification.html')


# Login
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = Users.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session['username'] = user.username
            session['name'] = user.name
            session['email'] = user.email
            session['password'] = user.password
            session['last_activity'] = datetime.now().isoformat()
            return redirect('/dashboard')
        else:
            return render_template('login.html', login_message="Invalid Username or Password")
    return render_template('login.html')


# Login with Google
@app.route('/login_google')
def login_google():
    try:
        google = oauth.create_client('google')
        redirect_uri = url_for('authorize_google', _external=True)
        return google.authorize_redirect(redirect_uri)
    except Exception as e:
        app.logger.error(f"Error during Google Login: {e}")
        return "Error occured during google login",500
    
@app.route('/authorize_google')
def authorize_google():
    try:
        google = oauth.create_client('google')
        token = google.authorize_access_token()
        resp = google.get('userinfo', token=token)
        user_info = resp.json()

        email = user_info['email']
        username = email.split('@')[0]
        name = user_info.get('name', 'Google User')

        user = Users.query.filter_by(email=email).first()
        if not user:
            original = username
            counter=1
            while Users.query.filter_by(username=username).first():
                username = f"{original}{counter}"
                counter += 1

            default_password = bcrypt.hashpw(os.urandom(16), bcrypt.gensalt()).decode('utf-8')
            user = Users(username=username, name=name, email=email, password=default_password)

            try:
                db.session.add(user)
                db.session.commit()

                token = serializer.dumps(email, salt='password-reset-salt')
                reset_url = url_for('reset_password', token=token, _external=True)

                msg_title = "Welcome to Expense Ease - Set Your Password"
                msg_content = render_template('emails/welcome_email.html', user=user, reset_url=reset_url)
                msg = Message(msg_title, recipients=[email], html=msg_content)
                mail.send(msg)
                
            except Exception as e:
                db.session.rollback()
                flash("Error while creating a new user. Please try again later.", "danger")
                return redirect(url_for('login'))

        session['username'] = user.username
        session['name'] = user.name
        session['email'] = user.email
        session['oauth_token'] = token
        return redirect(url_for('dashboard'))
    except Exception as e:
        app.logger.error(f"Error during Google OAuth authorization: {e}")
        flash("Google OAuth authorization: access_denied")
        return redirect(url_for('login'))


# Login with Github
@app.route('/login_github')
def login_github():
    try:
        github = oauth.create_client('github')
        redirect_uri = url_for('authorize_github', _external=True)
        return github.authorize_redirect(redirect_uri)
    except Exception as e:
        app.logger.error(f"Error during Google Login: {e}")
        return "Error occured during google login",500
    
@app.route('/authorize_github')
def authorize_github():
    try:
        github = oauth.create_client('github')
        token = github.authorize_access_token()
        resp = github.get('user', token=token)
        user_info = resp.json()
        print(user_info)

        email = user_info['email']
        if email is None:
            flash("Github OAuth authorization: unable to retrieve email")
            return redirect(url_for('login'))
        username = user_info['login']
        name = user_info.get('name', 'Github User')

        user = Users.query.filter_by(email=email).first()
        if not user:
            original = username
            counter=1
            while True:
                username = f"{original}{counter}" if counter > 1 else original
                if not Users.query.filter_by(username=username).first():
                    break
                counter += 1

            default_password = bcrypt.hashpw(os.urandom(16), bcrypt.gensalt()).decode('utf-8')
            user = Users(username=username, name=name, email=email, password=default_password)

            try:
                db.session.add(user)
                db.session.commit()

                token = serializer.dumps(email, salt='password-reset-salt')
                reset_url = url_for('reset_password', token=token, _external=True)

                msg_title = "Welcome to Expense Ease - Set Your Password"
                msg_content = render_template('emails/welcome_email.html', user=user, reset_url=reset_url)
                msg = Message(msg_title, recipients=[email], html=msg_content)
                mail.send(msg)
                
            except Exception as e:
                db.session.rollback()
                print(e)
                flash("Error while creating a new user. Please try again later.", "danger")
                return redirect(url_for('login'))

        session['username'] = user.username
        session['name'] = user.name
        session['email'] = user.email
        session['oauth_token'] = token
        return redirect(url_for('dashboard'))
    except Exception as e:
        app.logger.error(f"Error during Github OAuth authorization: {e}")
        print(e)
        flash("Github OAuth authorization: access_denied")
        return redirect(url_for('login'))

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=360) 
    except:
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return render_template('reset_password.html', token=token)

        if not valid_password(password):
            flash('Password must be 7-20 characters long, contain at least one uppercase letter, one lowercase letter, one number, and one special symbol.', 'danger')
            return redirect(url_for('reset_password', token=token))

        user = Users.query.filter_by(email=email).first()
        if user:
            user.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            db.session.commit()
            flash('Your password has been updated!', 'success')
            return redirect(url_for('login'))
        else:
            flash('User not found.', 'danger')
            return redirect(url_for('register'))

    return render_template('reset_password.html')

def valid_password(password):
    if (len(password) < 7 or len(password) > 20 or
            not re.search("[a-z]", password) or
            not re.search("[A-Z]", password) or
            not re.search("[0-9]", password) or
            not re.search("[@#$%^&+=]", password)):
        return False
    return True

def valid_email_format(email):
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(regex, email) is not None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash("Sesion Expired: You need to be logged in to access this page.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Dashboard and Further Routes
@app.route('/dashboard')
@login_required
def dashboard():
    if session['username']:
        user = Users.query.filter_by(username=session['username']).first()
        categories = Categories.query.all()
        payment_methods = PaymentMethods.query.all()
        total_expense = calculate_total_expense(user.id)
        year_expense = calculate_current_year_expense(user.id)
        month_expense = calculate_current_month_expense(user.id)
        week_expense = calculate_current_week_expense(user.id)
        recent_invoices_of_user = db.session.query(Invoices).filter(Invoices.user_id == user.id).order_by(Invoices.date.desc()).limit(5).all()

        return render_template('dashboard.html', user=user, total_expense=total_expense, year_expense=year_expense, month_expense=month_expense, week_expense=week_expense, 
                               recent_invoices_of_user=recent_invoices_of_user, categories=categories, payment_methods=payment_methods,
                               active_page='home')
    else: 
        return redirect('login')


@app.route('/profile')
@login_required
def profile():
    if session['username']:
        user = Users.query.filter_by(username=session['username']).first()
        return render_template('profile.html',user=user, active_page='profile')

@app.route('/updateprofile/<int:userid>', methods=['GET','POST'])
@login_required
def updateprofile(userid):
    user = Users.query.filter_by(id=userid).first()
    if not user:
        flash("User not found","danger")
        return redirect(url_for('profile'))
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        if not email or not name:
            flash("Email and Name are required fields.","danger")
            return render_template('updateprofile.html', user=user)
        user.email = email
        user.name = name

        try:
            db.session.commit()
            flash("Profile updated successfully.","success")
            return redirect(url_for('profile'))
        except Exception as exc:
            db.session.rollback()
            flash("Error updating profile. Please try again.", "danger")
            return render_template('updateprofile.html', user=user)
    return render_template('updateprofile.html', user=user)

@app.route('/changepassword/<int:userid>', methods=['GET','POST'])
@login_required
def changepassword(userid):
    user = Users.query.filter_by(id=userid).first()
    if not user:
        flash("User not found","danger")
        return redirect(url_for('profile'))
    if request.method == 'POST':
        oldpwd = request.form.get('oldpwd')
        newpwd = request.form.get('newpwd')
        conpwd = request.form.get('conpwd')
        if not oldpwd or not newpwd or not conpwd:
            flash("All fields are required.","danger")
            return render_template('changepwd.html', user=user)
        
        if user.check_password(newpwd):
            flash("New password is same as Old password","danger")
            return render_template('changepwd.html', user=user)
        
        if not user.check_password(oldpwd):
            flash("Old password is incorrect","danger")
            return render_template('changepwd.html', user=user)
        
        if newpwd != conpwd:
            flash("New password and Confirm password do not match","danger")
            return render_template('changepwd.html', user=user)
        
        user.password = bcrypt.hashpw(newpwd.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        try:
            db.session.commit()
            flash("Password changed successfully.","success")
            return redirect(url_for('profile'))
        except Exception as exc:
            db.session.rollback()
            flash("Error changing password. Please try again.", "danger")
            return render_template('changepwd.html', user=user)
    return render_template('changepwd.html', user=user)


# Forgot_password

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        user = Users.query.filter_by(username=username).first()
        if user:
            timeotp = pyotp.TOTP( otp_secret, interval=180)
            otp = timeotp.now()
            session['otp'] = otp
            session['username'] = username

            msg_title = "Reset Password OTP"
            msg_content = render_template('emails/forgot_password_email.html', otp=otp, name=user.name, username=username)
            msg = Message(msg_title, html=msg_content)
            mail.send(msg)

            return redirect(url_for('verify_otp'))
        else:
            flash('Username does not exist', 'danger')
            return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        otp = request.form['otp']
        if otp == session.get('otp'):
            return redirect(url_for('change_password'))
        else:
            flash('Invalid OTP', 'danger')
            return redirect(url_for('verify_otp'))
    return render_template('verify_otp_reset_pwd.html')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password == confirm_password:
            username = session.get('username')
            user = Users.query.filter_by(username=username).first()
            user.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            db.session.commit()
            flash('Password successfully changed', 'success')
            return redirect(url_for('login'))
        else:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('change_password'))
    return render_template('change_password.html')


# Profile Photo

@app.route('/upload-photo', methods=['POST'])
@login_required
def upload_photo():
    if 'profile_photo' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('profile'))
    
    file = request.files['profile_photo']
    
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('profile'))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        user = Users.query.filter_by(username=session['username']).first()
        user.image = filename
        db.session.commit()
        
        flash("Profile photo updated successfully", "success")
        return redirect(url_for('profile'))
    else:
        flash("File type not allowed", "danger")
        return redirect(url_for('profile'))

# Add Expense

@app.route('/add_expense',methods=['POST'])
@login_required
def add_expense():
    date_str = request.form.get('date')
    date = datetime.strptime(date_str, '%Y-%m-%d')
    description = request.form.get('description')
    category_id = request.form.get('category_id')
    amount = request.form.get('amount')
    payment_method_id = request.form.get('payment_method_id')
    payee = request.form.get('payee')
    
    try:
        date = datetime.strptime(date_str, '%Y-%m-%d').date()
        if date > datetime.now().date():
            flash("The date cannot be in the future", "warning")
            return redirect(url_for('dashboard'))
    except ValueError:
        flash("Invalid date format", "warning")
        return redirect(url_for('dashboard'))

    try:
        amount = float(amount)
        if amount < 0 or amount == 0:
            flash("Enter a valid amount", "warning")
            return redirect(url_for('dashboard'))
    except ValueError:
        flash("Enter a valid amount", "warning")
        return redirect(url_for('dashboard'))

    user = Users.query.filter_by(username=session['username']).first()
   
    new_invoice = Invoices(
        description=description,
        category_id=category_id,
        payment_method_id=payment_method_id,
        amount=amount,
        date=date,
        payee=payee,
        user_id=user.id
    )
    try:
        db.session.add(new_invoice)
        db.session.commit()
        flash("Expense added successfully.", "success")
        return redirect(url_for('dashboard'))
    except Exception as exc:
        db.session.rollback()
        flash("Error adding expense. Please try again.", "danger")
        return redirect('dashboard')

# Calculate Functions

def calculate_total_expense(id):
    return db.session.query(db.func.sum(Invoices.amount)).filter(Invoices.user_id == id).scalar() or 0

def calculate_current_year_expense(id):
    start_of_year = date(datetime.now().year, 1, 1)
    end_of_year = date(datetime.now().year, 12, 31)
    return db.session.query(db.func.sum(Invoices.amount)).filter(
        Invoices.user_id == id,
        Invoices.date >= start_of_year,
        Invoices.date <= end_of_year
    ).scalar() or 0

def calculate_current_month_expense(id):
    start_of_month = datetime(datetime.now().year, datetime.now().month, 1)
    end_of_month = (start_of_month.replace(month=start_of_month.month + 1) - timedelta(days=1)) if start_of_month.month < 12 else datetime(datetime.now().year, 12, 31, 23, 59, 59)
    return db.session.query(db.func.sum(Invoices.amount)).filter(
    Invoices.user_id == id,
    Invoices.date >= start_of_month,
    Invoices.date <= end_of_month
    ).scalar() or 0
    
def calculate_current_week_expense(id):
    start_of_week = datetime.now() - timedelta(days=datetime.now().weekday())
    start_of_week = start_of_week.replace(hour=0, minute=0, second=0, microsecond=0)
    end_of_week = start_of_week + timedelta(days=6, hours=23, minutes=59, seconds=59)
    return db.session.query(db.func.sum(Invoices.amount)).filter(
        Invoices.user_id == id,
        Invoices.date >= start_of_week,
        Invoices.date <= end_of_week
    ).scalar() or 0

# View all functions

@app.route('/all-expenses')
@login_required
def view_all_expenses():
    user = Users.query.filter_by(username=session['username']).first()
    category_ids = request.args.getlist('category_ids')
    payment_methods_ids = request.args.getlist('payment_methods_ids')
    month_ids = request.args.getlist('month_ids')
    selected_year = request.args.get('year')
    categories = Categories.query.all()
    payment_methods = PaymentMethods.query.all()

    query = db.session.query(Invoices).filter(Invoices.user_id == user.id)

    if 'all' not in category_ids and category_ids:
        query = query.filter(Invoices.category_id.in_(category_ids))

    if 'all' not in payment_methods_ids and payment_methods_ids:
        query = query.filter(Invoices.payment_method_id.in_(payment_methods_ids))

    if 'all' not in month_ids and month_ids:
        query = query.filter(db.extract('month', Invoices.date).in_(month_ids))

    if selected_year and selected_year != 'all':
        query = query.filter(db.extract('year', Invoices.date) == int(selected_year))

    all_expenses = query.all()
    current_year = datetime.now().year
    years = list(range(current_year, current_year - 8, -1))
    return render_template('viewallexpenses.html', all_expenses=all_expenses, categories=categories, payment_methods=payment_methods,
                            years=years, active_page='home')

@app.route('/search-expenses')
@login_required
def view_search_expenses():
    user = Users.query.filter_by(username=session['username']).first()
    query = db.session.query(Invoices).filter(Invoices.user_id == user.id)
    categories = Categories.query.all()
    payment_methods = PaymentMethods.query.all()
    search_item = request.args.get('search').lower()

    print(search_item)
    if search_item:
        query = db.session.query(Invoices).join(Invoices.category).filter(or_(Invoices.description.ilike(f"%{search_item}%"),
                Categories.name.ilike(f"%{search_item}%")
                )
            )
    all_expenses = query.all()
    return render_template('viewallexpenses.html', user=user, all_expenses=all_expenses, categgories=categories, payment_methods=payment_methods,
                           active_page='home')


@app.route('/addexpenses')
@login_required
def addexpenses():
    user = Users.query.filter_by(username=session['username']).first()
    categories = Categories.query.all()
    payment_methods = PaymentMethods.query.all()
    return render_template('addexpenses.html', user=user, active_page='home', categories=categories, payment_methods=payment_methods)

@app.route('/save_expenses', methods=['POST'])
@login_required
def save_expenses():
    user = Users.query.filter_by(username=session['username']).first()
    expenses = request.json.get('expenses', [])
    if expenses:
        try:
            for exp in expenses:
                invoice = Invoices(
                    date=datetime.strptime(exp['date'], '%Y-%m-%d').date(),
                    description=exp['description'],
                    amount=exp['amount'],
                    payee=exp['payee'],
                    category_id=exp['category_id'],
                    payment_method_id=exp['payment_method_id'],
                    user_id=user.id
                )
                db.session.add(invoice)
            db.session.commit()
            return jsonify(success=True)
        except Exception as e:
            db.session.rollback()
            return jsonify(success=False, error=str(e))
    return jsonify(success=False, error="No expense-data present in Table.")

@app.route('/updateexpenses')
@login_required
def updateexpenses():
    user = Users.query.filter_by(username=session['username']).first()
    all_expenses = db.session.query(Invoices).filter(Invoices.user_id == user.id).all()
    return render_template('updateexpenses.html', user=user, all_expenses=all_expenses, active_page='home')

@app.route('/delete_expense/<int:expense_id>', methods=['POST'])
@login_required
def delete_expense(expense_id):
    expense = Invoices.query.get(expense_id)
    if expense:
        try:
            db.session.delete(expense)
            db.session.commit()
            flash("Expense deleted successfully.", "success")
        except Exception as e:
            db.session.rollback()
            flash("Error deleting expense. Please try again.", "danger")
    else:
        flash("Expense not found.", "danger")
    return redirect(url_for('updateexpenses'))

@app.route('/update_expense/<int:expense_id>', methods=['GET','POST'])
@login_required
def update_expense(expense_id):
    expense = Invoices.query.get(expense_id)
    if not expense:
        flash("Expense not found.", "danger")
        return redirect(url_for('updateexpenses'))
    if request.method == 'POST':
        date_str = request.form.get('date')
        description = request.form.get('description')
        category_id = request.form.get('category_id')
        amount = request.form.get('amount')
        payment_method_id = request.form.get('payment_method_id')
        payee = request.form.get('payee')
        try:
            date = datetime.strptime(date_str, '%Y-%m-%d').date()
            if date > datetime.now().date():
                flash("The date cannot be in the future", "warning")
                return redirect(url_for('update_expense', expense_id=expense_id))
        except ValueError:
            flash("Invalid date format", "warning")
            return redirect(url_for('update_expense', expense_id=expense_id))

        try:
            amount = float(amount)
            if amount < 0 or amount == 0:
                flash("Enter a valid amount", "warning")
                return redirect(url_for('update_expense', expense_id=expense_id))
        except ValueError:
            flash("Enter a valid amount", "warning")
            return redirect(url_for('update_expense', expense_id=expense_id))

        expense.date = date
        expense.description = description
        expense.category_id = category_id
        expense.amount = amount
        expense.payment_method_id = payment_method_id
        expense.payee = payee
        
        try:
            db.session.commit()
            flash("Expense updated successfully.", "success")
            return redirect(url_for('updateexpenses'))
        except Exception as e:
            db.session.rollback()
            flash("Error updating expense. Please try again.", "danger")
            return redirect(url_for('update_expense', expense_id=expense_id))

    categories = Categories.query.all()
    payment_methods = PaymentMethods.query.all()
    return render_template('update_expense.html', expense=expense, payment_methods=payment_methods, categories=categories)

# Graph Route

def get_expense_data_for_bargraph(user_id, selected_year):
    expenses = db.session.query(Invoices).filter(Invoices.user_id == user_id).all()
    monthly_expense = defaultdict(float)
    for expense in expenses:
        e_year = expense.date.year
        e_month = expense.date.month
        if e_year == selected_year:
            monthly_expense[e_month] += expense.amount
    months = list(range(1, 13))
    monthly_expenses = [monthly_expense.get(month, 0) for month in months]
    return months, monthly_expenses

def get_categorywise_expense_data(user_id, selected_year2, selected_month):
    expenses = db.session.query(Invoices).filter(Invoices.user_id == user_id).all()
    expense_by_category = defaultdict(float)
    for expense in expenses:
        e_year = expense.date.year
        e_month = expense.date.month
        if e_year == selected_year2 and e_month == selected_month:
            expense_by_category[expense.category.name] += expense.amount
    categories = list(expense_by_category.keys())
    monthly_expenses_by_category = list(expense_by_category.values())
    return categories, monthly_expenses_by_category

def get_yearly_expense_data(user_id, start_year, end_year):
    expenses = db.session.query(Invoices).filter(Invoices.user_id == user_id).all()
    expense_over_years = defaultdict(float)
    for expense in expenses:
        e_year = expense.date.year
        if start_year <= e_year <= end_year:
            expense_over_years[e_year] += expense.amount
    years = sorted(expense_over_years.keys())
    annual_amount_per_year = [expense_over_years[year] for year in years]
    return years, annual_amount_per_year

@app.route('/analytics', methods=['GET', 'POST'])
@login_required
def analytics():
    user = Users.query.filter_by(username=session['username']).first()
    expenses = db.session.query(Invoices).filter(Invoices.user_id == user.id).all()

    c_year = datetime.now().year    
    c_month = datetime.now().month

    # First Graph
    selected_year = request.args.get('year', c_year, type=int)
    months, monthly_expenses = get_expense_data_for_bargraph(user.id, selected_year)
    bar_data = list(zip(months, monthly_expenses))
    
    # Second Graph
    selected_year2 = request.args.get('year2', c_year, type=int)
    selected_month = request.args.get('month', c_month, type=int)
    categories, monthly_expenses_by_category = get_categorywise_expense_data(user.id, selected_year2, selected_month)
    pie_data = list(zip(categories, monthly_expenses_by_category))

    # Third Graph
    start_year = request.args.get('start_year', c_year - 3, type=int)
    start_year = request.args.get('start_year', c_year - 3, type=int)
    end_year = request.args.get('end_year', c_year, type=int)
    expense_over_years = defaultdict(float)
    for expense in expenses:
        e_year = expense.date.year
        if start_year <= e_year <= end_year:
            expense_over_years[e_year] += expense.amount
    
    years = list(range(start_year, end_year + 1))
    annual_amount_per_year = [expense_over_years.get(year, 0) for year in years]
    line_data = list(zip(years, annual_amount_per_year))

    return render_template('analytics.html', user=user, bar_data=bar_data, pie_data=pie_data, line_data=line_data,selected_year=selected_year,
                           selected_year2=selected_year2, selected_month=selected_month,start_year=start_year, end_year=end_year, 
                           c_year=c_year, c_month=c_month, monthly_expenses=monthly_expenses, categories=categories, 
                           monthly_expenses_by_category=monthly_expenses_by_category, years=years, annual_amount_per_year=annual_amount_per_year, 
                           active_page='analytics')

# Route - Download PDFs

@app.route('/download-pdf')
@login_required
def download_full_pdf():
    user = Users.query.filter_by(username=session['username']).first()
    if not user:
        return redirect(url_for('login'))
    
    expenses = Invoices.query.filter_by(user_id=user.id).all()
    date = datetime.today()

    rendered = render_template('generate_full_pdf.html', user=user, expenses=expenses, date=date)
    config = pdfkit.configuration(wkhtmltopdf=r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe')

    pdf = pdfkit.from_string(rendered, False, configuration=config)
    response = make_response(pdf)
    response.headers['Content-Type'] = 'apploication/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=expensereport.pdf'
    return response

@app.route('/generate-graph-data-pdf', methods=['POST'])
@login_required
def generate_graph_data_pdf():
    user = Users.query.filter_by(username=session['username']).first()
    data_table = request.form['table']
    filename = request.form['filenm']
    title = request.form['title']
    date = datetime.now()

    bs4_soup = BeautifulSoup(data_table, 'html.parser')

    headers = [th.get_text() for th in bs4_soup.find_all('th')]
    rows = []
    for tr in bs4_soup.find_all('tr')[1:]:
        cells = [td.get_text() for td in tr.find_all('td')]
        rows.append(cells)

    rendered = render_template('generate_graph_data_pdf.html', user=user, headers=headers, rows=rows, title=title, date=date)
    config = pdfkit.configuration(wkhtmltopdf=r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe')

    pdf = pdfkit.from_string(rendered, False, configuration=config)
    response = make_response(pdf)
    response.headers['Content-Type'] = 'apploication/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename={}.pdf'.format(filename)
    return response

@app.route('/about')
@login_required
def about():
    return render_template('about.html', active_page='about')

@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    return redirect('login')

if __name__ == '__main__':
    app.run(debug=True)