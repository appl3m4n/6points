from flask import Flask, render_template, request, redirect, url_for
import pymysql

from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)

# Database configuration
db_user = "root"
db_password = ""
db_name = "users_db"
db_connection_name = "localhost"

app.config['SECRET_KEY'] = 'thisisasecretkey'
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Helper function to get database connection
def get_db_connection():
    return pymysql.connect(
        host='127.0.0.1',
        user=db_user,
        password=db_password,
        db=db_name,
        cursorclass=pymysql.cursors.DictCursor
    )

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

@login_manager.user_loader
def load_user(user_id):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM login WHERE id = %s", (user_id,))
            user_data = cursor.fetchone()
        if user_data:
            return User(user_data['id'], user_data['username'], user_data['password'])
    finally:
        connection.close()
    return None

# RegisterForm class
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        connection = get_db_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT * FROM login WHERE username = %s", (username.data,))
                existing_user = cursor.fetchone()
            if existing_user:
                raise ValidationError('That username already exists. Please choose a different one.')
        finally:
            connection.close()

# LoginForm class
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

# Routes
@app.route('/')
def index():
    # Connect to the database
    connection = get_db_connection()
    views = 0
    try:
        with connection.cursor() as cursor:
            # Retrieve current views
            cursor.execute("SELECT count FROM page_views WHERE id = 1")
            result = cursor.fetchone()
            if result:
                views = result['count']
            
            # Increment the views count
            cursor.execute("UPDATE page_views SET count = count + 1 WHERE id = 1")
            connection.commit()
    finally:
        connection.close()

    return render_template('index_open.html', views=views)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    error = None  # Variable to store the error message
    if request.method == 'POST':  # Check if the form is submitted
        username = form.username.data
        password = form.password.data

        # Custom validation for username and password length
        if len(username) < 4:
            error = "Username must be at least 4 characters long."
        elif len(password) < 8:
            error = "Password must be at least 8 characters long."
        else:
            connection = get_db_connection()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT * FROM login WHERE username = %s", (username,))
                    user_data = cursor.fetchone()
                if user_data and bcrypt.check_password_hash(user_data['password'], password):
                    user = User(user_data['id'], user_data['username'], user_data['password'])
                    login_user(user)
                    return redirect(url_for('index'))
                else:
                    error = "Invalid username or password."
            finally:
                connection.close()

    return render_template('login.html', form=form, error=error)



@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    error = None  # Variable to store the error message
    if request.method == 'POST':  # Check if the form is submitted
        username = form.username.data
        password = form.password.data

        # Debugging: Print inputs
        print(f"Username: {username}, Password: {password}")

        # Custom validation for username and password length
        if len(username) < 4:
            error = "Username must be at least 4 characters long."
        elif len(password) < 8:
            error = "Password must be at least 8 characters long."
        else:
            connection = get_db_connection()
            try:
                with connection.cursor() as cursor:
                    # Check if the username already exists
                    cursor.execute("SELECT * FROM login WHERE username = %s", (username,))
                    existing_user = cursor.fetchone()
                    if existing_user:
                        error = "That username already exists. Please choose a different one."
                    else:
                        # Hash the password and save the user in the database
                        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                        cursor.execute("INSERT INTO login (username, password) VALUES (%s, %s)", (username, hashed_password))
                        connection.commit()
                        print("User successfully registered!")  # Debugging
                        return redirect(url_for('login'))
            finally:
                connection.close()
        print(f"Error: {error}")  # Debugging
    return render_template('register.html', form=form, error=error)

@app.route('/option1')
def option1():
    return render_template('option1.html', current_user=current_user)

@app.route('/option2')
def option2():
    return render_template('option2.html', current_user=current_user)

@app.route('/option3')
def option3():
    return render_template('option3.html', current_user=current_user)

@app.route('/option4')
def option4():
    return render_template('option4.html', current_user=current_user)

@app.route('/subscribe', methods=['POST'])
@login_required
def subscribe():
    # Handle the payment and subscription logic here (e.g., integrate with a payment gateway)
    
    # For now, we simulate a successful payment process
    # You can integrate with a payment API like Stripe, PayPal, etc.
    
    # For this example, assume the payment is successful
    flash("Payment successful! You are now subscribed.", "success")
    
    # After the subscription, you can redirect the user to the main page or a new page
    return redirect(url_for('index'))



if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
