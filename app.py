from flask import Flask, render_template, request
from flask import session, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash

import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin):
    pass


class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')



@login_manager.user_loader
def load_user(user_id):
    user = User()
    user.id = user_id
    return user


def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn


def create_tables():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            message TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.close()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash('Этот email уже используется!', 'error')
        else:
            hashed_password = generate_password_hash(password)
            cursor.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, hashed_password))
            conn.commit()
            flash('Вы успешно зарегистрировались!', 'success')
            return redirect(url_for('login'))

        conn.close()

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            user_obj = User()
            user_obj.id = user['id']
            login_user(user_obj)
            return redirect(url_for('profile'))
        else:
            flash('Неверный email или пароль!', 'error')

        conn.close()

    return render_template('login.html', form=form)


@app.route('/profile')
def profile():
    if 'user_id' in session:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
        user = cursor.fetchone()

        if user:
            cursor.execute('SELECT * FROM messages WHERE user_id = ?', (session['user_id'],))
            messages = cursor.fetchall()
            conn.close()
            return render_template('profile.html', user=user, messages=messages)

    flash('Вы не авторизованы!', 'error')
    return redirect(url_for('login'))


# Маршрут для отправки сообщений
@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user_id' in session:
        message = request.form['message']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO messages (user_id, message) VALUES (?, ?)', (session['user_id'], message))
        conn.commit()
        conn.close()

        flash('Сообщение успешно отправлено!', 'success')
    else:
        flash('Вы не авторизованы!', 'error')

    return redirect(url_for('profile'))


# Маршрут для выхода из аккаунта
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Вы успешно вышли из аккаунта!', 'success')
    return redirect(url_for('login'))


if __name__ == '__main__':
    create_tables()
    app.run(debug=True)
