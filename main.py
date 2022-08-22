from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
import time


app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


# #CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(1000), nullable=False)
    is_authenticated = db.Column(db.Boolean, nullable=False)
    is_active = db.Column(db.Boolean, nullable=False)
    is_anonymous = db.Column(db.Boolean, nullable=False)

    def get_id(self):
        return str(self.id)


# Line below only required once, when creating DB.
db.create_all()


# class LoginForm(FlaskForm):
#     user = StringField('Email: ', validators=[DataRequired()])
#     password = StringField('Password: ', validators=[DataRequired()])
#     submit = SubmitField('Let Me In, Please')


@app.route('/')
def home():
    return render_template("index.html", current_user=current_user)


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        if User.query.filter_by(email=email).first():
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
        password = request.form.get('password')


        generated_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        print(generated_hash)

        # One should really get authenticated by email verification but that implementation will have to come later
        new_user = User(name=name, email=email, password=generated_hash, is_authenticated=True, is_active=True, is_anonymous=False)
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)

        return redirect(url_for('secrets', name=name))

    return render_template("register.html")


@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=user_id).first()


@app.route('/login', methods=['GET', 'POST'])
def login():
    # form = LoginForm()
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            # user.is_authenticated = True
            # db.session.commit()
            if check_password_hash(user.password, password):
                login_user(user)
                db.session.commit()
                # flash('Logged in successfully.')
                print('Logged in successfully.')
                return redirect(url_for('secrets', name=user.name))
            else:
                flash('Password incorrect. Please try again.')
                print('Login failed. Password failed.')
        else:
            flash('That email does not exist. Please try again.')
            print('Login failed. Failed to find user in database.')
            time.sleep(2)
    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html", name=request.args.get('name'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    directory = './static/files'
    path = 'cheat_sheet.pdf'
    return send_from_directory(directory, path)


if __name__ == "__main__":
    app.run(debug=True)
