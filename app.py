from os import getloadavg
from flask import Flask, render_template, flash, request
from flask.helpers import url_for
from flask_login import LoginManager, login_manager, current_user, login_user, logout_user, login_required
from flask_login.mixins import UserMixin
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, form
from flask_bootstrap import Bootstrap
from werkzeug.utils import redirect
from wtforms.fields.simple import StringField, PasswordField, BooleanField, SubmitField, FileField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo, Length
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.urls import url_parse
from werkzeug.utils import secure_filename
# import pymysql
import cred
import mysql.connector


# pymysql.install_as_MySQLdb()
app = Flask(__name__)

Bootstrap(app)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://username:password@server/db_name'

conn = 'mysql+pymysql://{0}:{1}@{2}/{3}'.format(cred.dbuser, cred.dbpass, cred.dbhost, cred.dbname)

app.config['SQLALCHEMY_DATABASE_URI'] = conn
app.config['SECRET_KEY'] = 'you will never know'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app)

migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

#                        *************** model: user ***************
class User(db.Model, UserMixin):
    # for sign in 
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(128))

    # for profile
    location = db.Column(db.String(20), nullable=True)
    hobby = db.Column(db.String(100), nullable=True)
    fav_food = db.Column(db.String(100), nullable=True)
    fav_movie = db.Column(db.String(100), nullable=True)
    fav_game = db.Column(db.String(100), nullable=True)
    marriage = db.Column(db.String(20), nullable=True)

    # image path
    img_path = db.Column(db.String(100))

    def set_img_path(self, path):
        self.img_path = path


    def set_location(self, location):
        self.location = location
    def get_location(self):
        return self.location

    def set_hobby(self, hobby):
        self.hobby = hobby

    def get_hobby(self):
        return self.hobby

    def set_fav_food(self, fav_food):
        self.fav_food = fav_food

    def get_fav_food(self):
        return self.fav_food

    def set_fav_movie(self, fav_movie):
        self.fav_movie = fav_movie

    def get_fav_movie(self):
        return self.fav_movie

    def set_fav_game(self, fav_game):
        self.fav_game = fav_game
    
    def get_fav_game(self):
        return self.fav_game

    def set_marriage(self, marriage):
        self.marriage = marriage

    def get_marriage(self):
        return self.marriage

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

#                        *************** form: login ***************
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

#                        *************** form: register ***************
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')
            
#                        *************** form: profile ***************
class ProfileForm(FlaskForm):
    location = StringField('location')
    hobby = StringField('hobby')
    fav_food = StringField('fav_food')
    fav_movie = StringField('fav_movie')
    fav_game = StringField('fav_game')
    marriage = StringField('marriage')
    img = FileField('image', validators=[DataRequired()])
    submit = SubmitField('complete')


#                        *************** route: register ***************

@app.route('/register', methods=['GET', 'POST'])
# def register():
#     if current_user.is_authenticated:
#         return redirect(url_for('index'))
#     form = RegistrationForm()
#     if form.validate_on_submit():
#         user = User(username=form.username.data, email=form.email.data)
#         user.set_password(form.password.data)
#         db.session.add(user)
#         db.session.commit()
#         return redirect(url_for('login'))
#     return render_template('register.html', title='Register', form=form)
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username1')
        email = request.form.get('email1')
        password = request.form.get('password1')
        user = User(username=username, email=email)
        user.set_password(password)
        print("adding user ...")
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', title='Register')

#                        *************** route: login ***************

@app.route('/login', methods=['GET', 'POST'])
# def login():
#     if current_user.is_authenticated:
#         return redirect(url_for('index'))
#     form = LoginForm()
#     if form.validate_on_submit():
#         user = User.query.filter_by(username=form.username.data).first()
#         if user is None or not user.check_password(form.password.data):
#             flash('Invalid username or password')
#             return redirect(url_for('login'))
#         login_user(user, remember=form.remember_me.data)
#         next_page = request.args.get('next')


#         # set the user's status to True, which means logged in
#         # user.login_set_status()
#         # print(user.status)
#         db.session.commit()
#         if not next_page or url_parse(next_page).netloc != '':
#             next_page = url_for('index')
#         return redirect(next_page)
#     return render_template('login.html', title='Sign In', form=form)
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember-me')
        user = User.query.filter_by(username=username).first()
        if user is None or not user.check_password(password):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=remember)
        next_page = request.args.get('next')
        db.session.commit()
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In')

#                        *************** route: /index or / ***************
@app.route('/')
@app.route('/index')
def index():
    if current_user.is_authenticated:
        user = {'username': current_user.username}
        return render_template('index.html', user=user)
    return render_template('index.html')
#                        *************** route: logout ***************

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

#                        *************** route: profile ***************
@login_required
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    user = User.query.filter_by(username=current_user.username).first()
    return render_template('profile.html', user=user)
    # if form.validate_on_submit():
        
    #     user.set_location(form.location.data)
    #     user.set_hobby(form.hobby.data)
    #     user.set_fav_food(form.fav_food.data)
    #     user.set_fav_movie(form.fav_movie.data)
    #     user.set_fav_game(form.fav_game.data)
    #     user.set_marriage(form.marriage.data)

    #     # save the image first
    #     filename = secure_filename(form.file.data.filename)
    #     form.file.data.save("static/" + filename)

    #     # set the image path for the user
    #     user.set_img_path("static/" + filename)

    #     db.session.commit()

    #     redirect(url_for('profile'))


#                        *************** route: edit_profile ***************
@login_required
@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    # form = ProfileForm()
    user = User.query.filter_by(username=current_user.username).first()
    info = {"location": user.get_location(),
            "hobby": user.get_hobby(),
            "fav_food": user.get_fav_food(),
            "fav_movie": user.get_fav_movie(),
            "fav_game": user.get_fav_game(),
            "marriage": user.get_marriage()
            }
    return render_template('editProfile.html', title='Edit profile', info=info)

#                        *************** route: save_profile ***************
@login_required
@app.route('/save_profile', methods=['GET', 'POST'])
def save_profile():
    if request.method == 'POST':
        user = User.query.filter_by(username=current_user.username).first()
        user.set_location(request.form.get('location'))
        user.set_hobby(request.form.get('hobby'))
        user.set_fav_food(request.form.get('fav_food'))
        user.set_fav_movie(request.form.get('fav_movie'))
        user.set_fav_game(request.form.get('fav_game'))
        user.set_marriage(request.form.get('marriage'))
        db.session.commit()
        return redirect(url_for('profile'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

if __name__ == "__main__":
    mydb = mysql.connector.connect(host='db', port='3306', user='root', password='passwd123', database='users')
    my_cursor = mydb.cursor()
    my_cursor.execute("CREATE DATABASE users")
    my_cursor.execute("CREATE TABLE user(id int not null auto_increment primary key, username VARCHAR(20) not null, email VARCHAR(120) not null, password_hash VARCHAR(128), location VARCHAR(20), hobby VARCHAR(100), fav_food VARCHAR(100), fav_movie VARCHAR(100), fav_game VARCHAR(100), marriage VARCHAR(20), img_path VARCHAR(100))")
    app.run(host="0.0.0.0", debug=True)

