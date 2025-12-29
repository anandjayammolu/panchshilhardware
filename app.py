from flask import Flask, render_template, redirect, url_for, session, flash
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect, generate_csrf
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, ValidationError
import bcrypt
import sqlite3
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key'
csrf = CSRFProtect(app)

# CSRF token for templates
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

# ---------- DATABASE ----------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, 'database.db')

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE,
            password BLOB
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT,
            mobile TEXT,
            message TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """)

init_db()

# ---------- FORMS ----------
class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")

    def validate_email(self, field):
        with sqlite3.connect(DATABASE) as conn:
            cur = conn.cursor()
            cur.execute("SELECT id FROM users WHERE email=?", (field.data,))
            if cur.fetchone():
                raise ValidationError("Email already registered")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class ContactForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    mobile = StringField("Mobile", validators=[DataRequired()])
    message = TextAreaField("Message", validators=[DataRequired()])
    submit = SubmitField("Send")

# ---------- ROUTES ----------
@app.route('/')
def index():
    form = ContactForm()
    return render_template('index.html', form=form)

@app.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        pw = bcrypt.hashpw(form.password.data.encode(), bcrypt.gensalt())
        with sqlite3.connect(DATABASE) as conn:
            conn.execute(
                "INSERT INTO users VALUES (NULL,?,?,?)",
                (form.name.data, form.email.data, pw)
            )
        flash("Registration successful. Please login.")
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        with sqlite3.connect(DATABASE) as conn:
            conn.row_factory = sqlite3.Row
            user = conn.execute(
                "SELECT * FROM users WHERE email=?",
                (form.email.data,)
            ).fetchone()
        if user and bcrypt.checkpw(form.password.data.encode(), user['password']):
            session['user_id'] = user['id']
            return redirect(url_for('dashboard'))
        flash("Invalid email or password")
    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        user = conn.execute(
            "SELECT * FROM users WHERE id=?",
            (session['user_id'],)
        ).fetchone()
    return render_template('dashboard.html', user=user)

@app.route('/contact', methods=['POST'])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        with sqlite3.connect(DATABASE) as conn:
            conn.execute("""
            INSERT INTO contacts (name,email,mobile,message)
            VALUES (?,?,?,?)
            """, (
                form.name.data,
                form.email.data,
                form.mobile.data,
                form.message.data
            ))
        flash("Thank you! We will contact you soon.")
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully")
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)
