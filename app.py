from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from flask_ngrok import run_with_ngrok

try:
    from dotenv import load_dotenv
    load_dotenv()
except ModuleNotFoundError:
    print("The 'python-dotenv' package is not installed. Please install it with 'pip install python-dotenv'.")

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')

# Configure database connection using environment variables
app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"mysql+pymysql://{os.getenv('DB_USERNAME', 'root')}:{os.getenv('DB_PASSWORD', '')}@"
    f"{os.getenv('DB_HOST', 'localhost')}/{os.getenv('DB_NAME', 'testdb')}"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User Model
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # 'regional_head' or 'inoc_manager'

# Schedule Model
class Schedule(db.Model):
    __tablename__ = 'schedules'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.String(20), nullable=False)
    person_in_charge = db.Column(db.String(150), nullable=False)
    region = db.Column(db.String(100), nullable=False)  # Region column
    telephone_number = db.Column(db.String(15), nullable=True)  # New column for telephone number


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
    return render_template('/login.html')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        
        # Check if user already exists
        user_exists = User.query.filter_by(username=username).first()
        if user_exists:
            flash('Username already exists')
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2')
            new_user = User(username=username, password=hashed_password, role=role)
            db.session.add(new_user)
            db.session.commit()
            flash('User registered successfully!')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role == 'regional_head':
        return render_template('regional_head.html')
    elif current_user.role == 'inoc_manager':
        date_filter = request.args.get('date')  # Get the date query parameter
        if date_filter:
            schedules = Schedule.query.filter_by(date=date_filter).all()  # Filter by date
        else:
            schedules = Schedule.query.all()
        return render_template('inoc_manager.html', schedules=schedules)
    return "Unauthorized Access"

@app.route("/add_schedule", methods=['POST'])
@login_required
def add_schedule():
    if current_user.role == 'regional_head':
        date = request.form['date']
        person_in_charge = request.form['person_in_charge']
        region = request.form['region']  # Capture the region field
        telephone_number = request.form['telephone_number']  # Capture the new telephone number field
        schedule = Schedule(date=date, person_in_charge=person_in_charge, region=region, telephone_number=telephone_number)
        db.session.add(schedule)
        db.session.commit()
        flash('Schedule added successfully!')
        return redirect(url_for('dashboard'))
    return "Unauthorized Access"

@app.route("/")
def home():
    return redirect(url_for('login'))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == "__main__":
    # Ensure database tables are created
    with app.app_context():
        db.create_all()
    
    # Only run Ngrok in development
    if app.config['DEBUG']:
        run_with_ngrok(app)
    
    app.run(debug=True)
