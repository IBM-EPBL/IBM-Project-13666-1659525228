from flask import Flask,request, render_template, url_for, redirect, flash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from flask_wtf import FlaskForm
import sqlite3
import joblib
from sklearn.preprocessing import OrdinalEncoder
import pandas as pd
import requests

# NOTE: you must manually set API_KEY below using information retrieved from your IBM Cloud account.
API_KEY = "iX5xF0JyPhYIfWGg37VPe14p1D7OMDPgPG1cl1yQJfJg"
token_response = requests.post('https://iam.cloud.ibm.com/identity/token', data={"apikey": API_KEY, "grant_type": 'urn:ibm:params:oauth:grant-type:apikey'})
mltoken = token_response.json()["access_token"]

header = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + mltoken}

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = 'B7-1A3E'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    conn = connect_db()
    user = conn.execute('SELECT * FROM user WHERE id = ?',
                        (user_id,)).fetchone()
    usr_obj = User(user[0], user[1], user[2])
    return usr_obj


def connect_db():
    conn = sqlite3.connect('database.db')
    return conn

class User:   

    def __init__(self, id, email, username):
        self.id = id
        self.username = username
        self.email = email

    def to_json(self):        
        return {"username": self.username,
                "email": self.email}

    def is_authenticated(self):
        return True

    def is_active(self):   
        return True           

    def is_anonymous(self):
        return False          

    def get_id(self):         
        return str(self.id)

class RegisterForm(FlaskForm):
    email = StringField(validators=[
        InputRequired(), Length(min=4, max=50)], render_kw={"placeholder": "Email"})
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    rollnumber = StringField(validators=[
        InputRequired(), Length(min=5, max=10)], render_kw={"placeholder": "RollNumber"})
    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        conn = connect_db()
        existing_user_username = conn.execute('SELECT * FROM user WHERE username = ?',
                                              (username.data,)).fetchone()
        conn.commit()
        conn.close()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Try another one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


class UpdateForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    oldpassword = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Previous Password"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Update')


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        conn = connect_db()
        user = conn.execute('SELECT * FROM user WHERE username = ?',
                            (form.username.data,)).fetchone()
        conn.commit()
        conn.close()
        if user:
            if bcrypt.check_password_hash(user[4], form.password.data):
                usr_obj = User(user[0], user[1], user[2])
                login_user(usr_obj)
                return redirect(url_for('welcome'))

            else:
                print('Hi')
                flash(f'Invalid credentials, check and try logging in again.', 'danger')
                return redirect(url_for('login'))
                
    return render_template('login.html', form=form)


@app.route('/welcome', methods=['GET', 'POST'])
@login_required
def welcome():
    return render_template('welcome.html')

@app.route('/predict', methods=['POST'])
def predictSpecies():
    sell = float(request.form['sell'])
    ot = float(request.form['ot'])
    vt = float(request.form['vt'])
    gb = float(request.form['gb'])
    pps=float(request.form['pps'])
    km=float(request.form['km'])
    ft=float(request.form['ft'])
    brand=float(request.form['brand'])
    nr=float(request.form['nr'])
    age=float(request.form['age'])
    arr = [[sell, ot, vt, gb,pps,km,ft,brand,nr,age]]


    payload_scoring = {"input_data": [{"field": [['sell', 'ot', 'vt', 'gb','pps','km','ft','brand','nr','age']], "values":arr}]}

    response_scoring = requests.post('https://us-south.ml.cloud.ibm.com/ml/v4/deployments/a4a92034-8fcd-4e79-ab7c-521a5d8cb7d5/predictions?version=2022-11-15', json=payload_scoring, headers={'Authorization': 'Bearer ' + mltoken})
    print(response_scoring)
    predictions =  response_scoring.json()
    pr = predictions['predictions'][0]['values'][0][0]
    print("final prediction",pr)
    return render_template('predict.html',predict1=pr)



@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    conn = connect_db()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        conn.execute('INSERT INTO user (email, username, roll_number, pass_word) VALUES (?, ?, ?, ?)',
                     (form.email.data, form.username.data, form.rollnumber.data, hashed_password))
        conn.commit()
        conn.close()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@ app.route('/update', methods=['GET', 'POST'])
def update():
    form = UpdateForm()
    conn = connect_db()
    if form.validate_on_submit():
        conn = connect_db()
        user = conn.execute('SELECT * FROM user WHERE username = ?',
                            (form.username.data,)).fetchone()
        if user:
            if bcrypt.check_password_hash(user[4], form.oldpassword.data):
                print(user)
                hashed_password1 = bcrypt.generate_password_hash(
                    form.password.data)
                conn.execute('UPDATE user set pass_word = ? where username = ?',
                             (hashed_password1, form.username.data))
                conn.commit()
                conn.close()
                flash(f'Password changed successfully.', 'success')
                return redirect(url_for('home'))
            else:
                flash(f'Invalid password, Enter valid password.', 'danger')
                return redirect(url_for('update'))
        else:
            flash(f'Invalid user, Enter valid User.', 'danger')
            return redirect(url_for('update'))
    return render_template('update.html', form=form)


if __name__ == "__main__":
    app.run(debug=True)
