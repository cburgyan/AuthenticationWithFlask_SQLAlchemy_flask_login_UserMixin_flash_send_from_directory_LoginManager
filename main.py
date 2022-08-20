from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# #CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    salt = db.Column(db.String(100))
    hash_method = db.Column(db.String(100))
    name = db.Column(db.String(1000))


# Line below only required once, when creating DB.
db.create_all()


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        generated_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        print(generated_hash)
        generated_hash_list = generated_hash.split('$')

        new_user = User(name=name, email=email, password=generated_hash_list[2], salt=generated_hash_list[1], hash_method=generated_hash_list[0])
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('secrets'))

    return render_template("register.html")


@app.route('/login')
def login():
    return render_template("login.html")


@app.route('/secrets')
def secrets():
    return render_template("secrets.html")


@app.route('/logout')
def logout():
    pass


@app.route('/download')
def download():
    directory = './static/files'
    path = 'cheat_sheet.pdf'
    return send_from_directory(directory, path)


if __name__ == "__main__":
    app.run(debug=True)
