import base64
from email import encoders
from datetime import timedelta, datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase

import weasyprint
from flask import Flask, render_template, flash, session, redirect, send_from_directory
from flask_ckeditor import *
from flask_mysqldb import MySQL
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import sha256_crypt
from sendgrid import To, Bcc, Cc
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from wtforms.fields.html5 import EmailField
import os
import re
import smtplib
import ssl
import uuid
import random
import pdfkit
import email
import email.mime.application
# import sendgrid
# from sendgrid import SendGridAPIClient
# from sendgrid.helpers.mail import Mail
import sendgrid
from sendgrid.helpers.mail import Mail, Attachment, FileContent, FileName, FileType, Disposition, ContentId

# from weasyprint import HTML

app = Flask(__name__)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:novell@123@localhost/mysqlalchemy'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

app.secret_key = 'novell@123'
basedir = os.path.abspath(os.path.dirname(__file__))

# engine = create_engine('mysql://root:novell@123@localhost/mysqlalchemy')

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'novell@123'
app.config['MYSQL_DB'] = 'mysqlalchemy'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# init MYSQL
mysql = MySQL(app)

##################### FILE UPLOAD SCRIPT ######################################
ckeditor = CKEditor(app)

app.config['CKEDITOR_SERVE_LOCAL'] = False
app.config['CKEDITOR_HEIGHT'] = 400
app.config['CKEDITOR_FILE_UPLOADER'] = 'upload'
app.config['UPLOADED_PATH'] = os.path.join(basedir, 'upload')
app.config['UPLOADED_PATH_HTML'] = os.path.join(basedir, 'upload/html')
app.config['UPLOADED_PATH_PDF'] = os.path.join(basedir, 'upload/pdf')
global_app_key = os.environ.get('SENDGRID_API_KEY')


@app.route('/files/<filename>')
def uploaded_files(filename):
    path = app.config['UPLOADED_PATH']
    return send_from_directory(path, filename)


@app.route('/upload', methods=['POST'])
def upload():
    f = request.files.get('upload')
    extension = f.filename.split('.')[1].lower()
    if extension not in ['jpg', 'gif', 'png', 'jpeg']:
        return upload_fail(message='Image only!')
    unique_filename = str(uuid.uuid4())
    f.filename = "flaskapp" + unique_filename[0:8] + '.' + extension
    f.save(os.path.join(app.config['UPLOADED_PATH'], f.filename))
    url = url_for('uploaded_files', filename=f.filename)
    return upload_success(url=url)


##################################################################################


class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(20), nullable=False, default='N/A')
    body = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.now)
    date_updated = db.Column(db.DateTime,
                             nullable=False, default=datetime.now, onupdate=datetime.now)

    def __repr__(self):
        return 'BlogPost ' + str(self.id)


class Articles(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(20), nullable=False, default='N/A')
    body = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.now)
    date_updated = db.Column(db.DateTime,
                             nullable=False, default=datetime.now, onupdate=datetime.now)

    def __repr__(self):
        return 'Articles ' + str(self.id)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    register_date = db.Column(db.DateTime, nullable=False, default=datetime.now)
    hashCode = db.Column(db.String(200))

    def __repr__(self):
        return 'Users ' + str(self.id)


class Urls(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url_name = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return 'Urls ' + str(self.id)


class Tasks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    task = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(100), nullable=False)
    comments = db.Column(db.Text)

    def __repr__(self):
        return 'Urls ' + str(self.id)


# Home Page
@app.route('/', methods=['POST', 'GET'])
def home():
    return render_template('home.html')


@app.route('/loading')
def loading():
    return render_template('loading.html')


# About Page
@app.route('/about')
def about():
    return render_template('about.html')


# Articles page
@app.route('/articles')
def articles():
    # Get articles
    result = db.session.query(Articles).count()
    articles = Articles.query.all()
    if result > 0:
        return render_template('articles.html', articles=articles)
    else:
        msg = "No Articles Found"
        return render_template('articles.html', msg=msg)


@app.route('/download/<path:filename>', methods=['GET', 'POST'])
def download_pdf(filename):
    uploads = os.path.join(current_app.root_path, app.config['UPLOADED_PATH_PDF'])
    return send_from_directory(directory=uploads, filename=filename, as_attachment=True)


# Individual Article page
@app.route('/article/<string:id>/')
def article(id):
    # Get article
    article = Articles.query.get(id)
    return render_template('article.html', article=article)


# Team Updates page
@app.route('/tupdates')
def tupdates():
    # Get articles
    result = db.session.query(BlogPost).count()
    tupdates = BlogPost.query.all()
    if result > 0:
        return render_template('tupdates.html', tupdates=tupdates)
    else:
        msg = "No Updates Found"
        return render_template('tupdates.html', msg=msg)


# Individual update page
@app.route('/tupdate/<string:id>/')
def tupdate(id):
    # Get tupdate
    tupdate = BlogPost.query.get_or_404(id)
    return render_template('tupdate.html', tupdate=tupdate)


# Registration Form Class
class RegisterForm(Form):
    name = StringField('Name', [validators.length(min=1, max=50), validators.DataRequired()])
    username = StringField('Username', [validators.length(min=4, max=25), validators.DataRequired(), validators.Regexp
    ('^\w+$', message="Username must contain only letters numbers or underscore")])
    email = EmailField('Email', [validators.length(min=4, max=50), validators.DataRequired(), validators.Email()])
    password = PasswordField('Password', [validators.data_required(),
                                          validators.EqualTo('confirm', message='Passwords do not match')])
    confirm = PasswordField('Confirm Password')


# Register
# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     form = RegisterForm(request.form)
#     if request.method == 'POST' and form.validate():
#         name = form.name.data
#         email = form.email.data
#         username = form.username.data
#         password = sha256_crypt.encrypt(str(form.password.data))
#
#         # Create a Cursor
#         account = Users.query.filter_by(username=username).first()
#         # If account exists show error and validation checks
#         if account:
#             error = 'Account already exists!'
#             return render_template('register.html', form=form, error=error)
#         else:
#             user = Users(name=name, email=email, username=username, password=password)
#             db.session.add(user)
#             db.session.commit()
#             flash('You are now registered and can log in', 'success')
#             return redirect(url_for('home'))
#     return render_template('register.html', form=form)


# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        email = request.form['email']
        password = sha256_crypt.encrypt(str(request.form['password']))
        # Execute
        account = Users.query.filter_by(username=username).first()
        # If account exists show error and validation checks
        if account:
            error = 'Account already exists!'
            return render_template('register.html', error=error)
        else:
            user = Users(name=name, email=email, username=username, password=password)
            db.session.add(user)
            # Commit DB
            db.session.commit()
            flash('You are now registered and can log in..', 'success')
            return redirect('/')
    else:
        return render_template('register.html')


# Register
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        email = request.form['email']
        password = sha256_crypt.encrypt(str(request.form['password']))
        # Execute
        account = Users.query.filter_by(username=username).first()
        # If account exists show error and validation checks
        if account:
            error = 'Account already exists!'
            return render_template('signup.html', error=error)
        else:
            user = Users(name=name, email=email, username=username, password=password)
            db.session.add(user)
            # Commit DB
            db.session.commit()
            flash('You are now registered and can log in..', 'success')

            return redirect('/')
    else:
        return render_template('signup.html')


@app.route('/preset', methods=['GET', 'POST'])
def preset():
    if request.method == 'POST':
        email = request.form['email']
        # password = sha256_crypt.encrypt(str(request.form['password']))
        # Execute
        account_email = Users.query.filter_by(email=email).first()
        # If account exists show error and validation checks
        if account_email:
            def get_random_string(length=24,
                                  allowed_chars='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'):
                return ''.join(random.choice(allowed_chars) for i in range(length))

            hashCode = get_random_string()
            account_email.hashCode = hashCode
            db.session.commit()

            username = 'apikey'
            sender_email = "flask-app-noreply@nam-qa-mf.com"
            password = global_app_key
            receiver_email = account_email.email

            message = MIMEMultipart("alternative")
            message["Subject"] = 'Password reset mail'
            message["From"] = sender_email
            message["To"] = account_email.email
            filename = basedir + '/templates/pwdresetemail.html'
            with open(filename, 'rb') as f:
                data = f.read().decode('utf-8')
                f.close()

            data = re.sub(r'(Hello )', r'\1' + account_email.name, data)
            # data = re.sub(r'(href=")', r'\1http://localhost:5000/pwdreset/'+account_email.hashCode, data)
            data = re.sub(r'(href=")',
                          r'\1http://nam-users.southeastasia.cloudapp.azure.com/pwdreset/' + account_email.hashCode,
                          data)
            app.logger.info(data)
            # my_str_as_bytes = str.encode(data)
            # body = "Hello,\nWe've received a request to reset your password. If you want to reset your password, " \
            #        "click the link below and enter your " \
            #        "new password\n http://localhost:5000/pwdreset/" + account_email.hashCode

            part1 = MIMEText(data, 'html')
            message.attach(part1)
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL("smtp.sendgrid.net", 465, context=context) as server:
                server.login(username, password)
                server.sendmail(
                    sender_email, receiver_email, message.as_string()
                )
            flash("Your new password reset link has been sent to your primary email address", 'success')
            return redirect(url_for('home'))
        else:
            error = 'No account exists in our database, Please do register!'
            return render_template('signup.html', error=error)

    else:
        return render_template('preset.html')


@app.route("/pwdreset/<string:hashCode>", methods=["GET", "POST"])
def hashcode(hashCode):
    check = Users.query.filter_by(hashCode=hashCode).first()
    if check:
        if request.method == 'POST':
            newpwd = request.form['newpwd']
            confpwd = request.form['confpwd']
            if newpwd == confpwd:
                check.password = sha256_crypt.encrypt(newpwd)
                check.hashCode = None
                db.session.commit()
                flash('Your password has been reset successfully!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Password mismatched!', 'danger')
                return render_template('change_pwd.html', check=check)
        else:
            return render_template('change_pwd.html', check=check)
    else:
        flash('Link expired or not exist!', 'danger')
        return redirect(url_for('home'))


# User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # GET Form Fields
        username = request.form['username']
        password_candidate = request.form['password']

        # Get user by username
        result = Users.query.filter_by(username=username).first()

        if result is not None:
            password = result.password
            name = result.name
            email = result.email
            rdate = result.register_date
            # Compare passwords
            if sha256_crypt.verify(password_candidate, password):
                # PASSED
                session['logged_in'] = True
                session['username'] = username
                session['name'] = name
                session['email'] = email
                session['rdate'] = rdate
                flash("You are now logged in..", 'success')
                return redirect(url_for('home'))
            else:
                error = 'Incorrect username/password!'
                return render_template('login.html', error=error)
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('login.html')


# User Login
@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        # GET Form Fields
        username = request.form['username']
        password_candidate = request.form['password']

        # Get user by username
        result = Users.query.filter_by(username=username).first()

        if result is not None:
            password = result.password
            name = result.name
            email = result.email
            # Compare passwords
            if sha256_crypt.verify(password_candidate, password):
                # PASSED
                session['logged_in'] = True
                session['username'] = username
                session['name'] = name
                session['email'] = email
                flash("You are now logged in..", 'success')
                return redirect(url_for('home'))
            else:
                error = 'Incorrect username/password!'
                return render_template('signin.html', error=error)
        else:
            error = 'Username not found'
            return render_template('signin.html', error=error)

    return render_template('signin.html')


# role based control
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login!', 'danger')
            return redirect(url_for('login'))

    return wrap


def is_logged_in_admin_user(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'admin' == session['username']:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login with admin user!', 'danger')
            app.logger.info(f.__name__)
            return redirect(url_for('user_details'))

    return wrap


def is_logged_in_admin_url(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'admin' == session['username']:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login with admin user', 'danger')
            app.logger.info(f.__name__)
            return redirect(url_for('url_links'))

    return wrap


# Dashboard page
@app.route('/dashboard')
@is_logged_in
def dashboard():
    # Get articles
    result = db.session.query(Articles).count()
    articles = Articles.query.all()

    # Get Updates
    result1 = db.session.query(BlogPost).count()
    tupdates = BlogPost.query.all()

    if result > 0 and result1 > 0:
        return render_template('dashboard.html', tupdates=tupdates, articles=articles)
    elif result == 0 and result1 > 0:
        msg = "No Articles Found"
        return render_template('dashboard.html', tupdates=tupdates, msg=msg)
    elif result > 0 and result1 == 0:
        msg = "No Updates Found"
        return render_template('dashboard.html', articles=articles, msg=msg)
    else:
        msg = "No Updates/Articles Found"
        return render_template('dashboard.html', msg=msg)


# Log out page
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('home'))


# Articles Form Class
class ArticlesForm(Form):
    title = StringField('Title', [validators.length(min=1, max=200)])
    body = TextAreaField('Body', [validators.length(min=30)])


@app.route('/add_article', methods=['GET', 'POST'])
@is_logged_in
def add_article():
    form = ArticlesForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        body = form.body.data
        article_validation = Articles.query.filter_by(title=title).first()
        # If account exists show error and validation checks
        if article_validation:
            error = 'Given title article already exists!'
            return render_template('add_article.html', form=form, error=error)
        else:
            # Execute
            article_data = Articles(title=title, body=body, author=session['username'])
            db.session.add(article_data)
            # Commit DB
            db.session.commit()
            html_creation(article_validation.id)
            # pdf_creation(title)
            flash("Article created", 'success')
            return redirect(url_for('dashboard'))
    return render_template('add_article.html', form=form)


@app.route('/edit_article/<string:page>/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_article(page, id):
    # Get article by id
    article_edit = Articles.query.get_or_404(id)
    # Get form
    form = ArticlesForm(request.form)
    # Populate the article form fields
    form.title.data = article_edit.title
    form.body.data = article_edit.body
    if request.method == 'POST' and form.validate():
        article_edit.title = request.form['title']
        article_edit.body = request.form['body']
        # Commit DB
        article_validation = Articles.query.filter_by(title=article_edit.title).first()
        # If account exists show error and validation checks
        # app.logger.info(type(article_validation.id))
        # app.logger.info(type(id))
        # if article_validation.id != id:
        #     app.logger.info("True")
        # else:
        #     app.logger.info("False")
        if article_validation and str(article_validation.id) != id:
            error = 'Given title article already exists!'
            return render_template('edit_article.html', form=form, error=error)
        else:
            db.session.commit()
            html_creation(id)
            # pdf_creation(article_edit.title)
            flash("Article updated", 'success')
            if page == 'dashboard':
                return redirect(url_for('dashboard'))
            else:
                return redirect('/edit_article/' + page + '/' + id)

    return render_template('edit_article.html', form=form)


@app.route('/delete_article/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def delete_article(id):
    # Execute
    article_delete = Articles.query.get_or_404(id)
    db.session.delete(article_delete)
    # Commit DB
    db.session.commit()
    flash("Article deleted!", 'success')
    return redirect(url_for('dashboard'))


# Update Form Class
class TeamUpdateForm(Form):
    name = StringField('Name', [validators.length(min=1, max=200)])
    body = TextAreaField('Body', [validators.length(min=30)])


@app.route('/add_update', methods=['GET', 'POST'])
@is_logged_in
def add_update():
    form = TeamUpdateForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        body = form.body.data
        # Execute
        update = BlogPost(name=name, body=body, author=session['username'])
        db.session.add(update)
        # Commit DB
        db.session.commit()
        flash("User updates created/added! ", 'success')
        return redirect(url_for('dashboard'))

    return render_template('add_update.html', form=form)


@app.route('/edit_update/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_update(id):
    # Get article by id
    t_update_edit = BlogPost.query.get_or_404(id)
    # Get form
    form = TeamUpdateForm(request.form)
    # Populate the article form fields
    form.name.data = t_update_edit.name
    form.body.data = t_update_edit.body
    if request.method == 'POST' and form.validate():
        t_update_edit.name = request.form['name']
        t_update_edit.body = request.form['body']
        # Commit DB
        db.session.commit()
        flash("Updated successfully!", 'success')
        return redirect(url_for('dashboard'))

    return render_template('edit_update.html', form=form)


@app.route('/delete_update/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def delete_update(id):
    # Execute
    update_delete = BlogPost.query.get_or_404(id)
    db.session.delete(update_delete)
    # Commit DB
    db.session.commit()
    flash("Updates deleted!", 'success')
    return redirect(url_for('dashboard'))


@app.route('/contactus')
def contactus():
    return render_template('contact_us.html')


@app.route('/send_mail', methods=['POST'])
@is_logged_in
def send_mail():
    me = "nam-qa-update@microfocus.com"
    you = "mohamediburahimsha.s@microfocus.com"
    #
    team_updates = BlogPost.query.all()
    app.logger.info(team_updates)
    message = MIMEMultipart('alternative')
    message['Subject'] = "Weekly Staff Updates"
    message['From'] = me
    message['To'] = you
    html = """\
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Updates Mail</title>
    </head>
    <body>
          <h1>Weekly Team Updates</h1>
          <hr>"""
    for d in team_updates:
        name = d.name
        body = d.body
        html = html + "<h2>"
        html = html + name + "</h2>"
        html = html + "<div>"
        html = html + body + "</div>"
        html = html + "<hr>"

    html = html + """</body>
    </html>
    """
    # Record the MIME types of both parts - text/plain and text/html.
    # part1 = MIMEText(text, 'plain')
    part2 = MIMEText(html, 'html')

    # Attach parts into message container.
    # According to RFC 2046, the last part of a multipart message, in this case
    # the HTML message, is best and preferred.
    # msg.attach(part1)
    message.attach(part2)

    # Send the message via local SMTP server.
    s = smtplib.SMTP('smtp.microfocus.com:25')
    # sendmail function takes 3 arguments: sender's address, recipient's address
    # and message to send - here it is sent as one string.
    s.sendmail(me, you, message.as_string())
    s.quit()
    flash("Message sent successfully!", 'success')
    return redirect(url_for('dashboard'))


@app.route('/send_mail_dashboard', methods=['POST'])
@is_logged_in
def send_mail_dashboard():
    username = 'apikey'
    sender_email = "flask-app-noreply@nam-qa-mf.com"
    receiver_email = session['email']
    # password = os.environ.get('SENDGRID_API_KEY')
    password = global_app_key
    #
    team_updates = None
    user01 = None
    if session['username'] == 'admin':
        team_updates = BlogPost.query.all()
    else:
        user01 = BlogPost.query.filter_by(author=session['username']).first()
    app.logger.info(team_updates)
    app.logger.info(user01)
    message = MIMEMultipart("alternative")
    message["Subject"] = "Weekly Team Updates"
    message["From"] = sender_email
    message["To"] = receiver_email
    html = """\
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Updates Mail</title>
    </head>
    <body>
          <h1>Weekly Team Updates</h1>
          <hr>"""
    if session['username'] == 'admin':
        if team_updates is not None:
            for d in team_updates:
                name = d.name
                body = d.body
                html = html + "<h2>"
                html = html + name + "</h2>"
                html = html + "<div>"
                html = html + body + "</div>"
                html = html + "<hr>"
        else:
            flash("Sorry ! No updates available for the user!", 'danger')
            return redirect(url_for('dashboard'))
    else:
        if user01 is not None:
            name = user01.name
            body = user01.body
            html = html + "<h2>"
            html = html + name + "</h2>"
            html = html + "<div>"
            html = html + body + "</div>"
            html = html + "<hr>"
        else:
            flash("Sorry ! No updates available for the user!", 'danger')
            return redirect(url_for('dashboard'))

    html = html + """</body>
    </html>
    """
    # Record the MIME types of both parts - text/plain and text/html.
    # part1 = MIMEText(text, 'plain')
    part2 = MIMEText(html, 'html')

    # Attach parts into message container.
    # According to RFC 2046, the last part of a multipart message, in this case
    # the HTML message, is best and preferred.
    # msg.attach(part1)
    message.attach(part2)

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.sendgrid.net", 465, context=context) as server:
        server.login(username, password)
        server.sendmail(
            sender_email, receiver_email, message.as_string()
        )
    flash("Mail sent successfully!", 'success')
    return redirect(url_for('dashboard'))


# @app.route('/send_article', methods=['GET', 'POST'])
# @is_logged_in
# def send_article():
#     me = "nam-qa-update@microfocus.com"
#     you = "mohamediburahimsha.s@microfocus.com"
#     #
#     d = Articles.query.get_or_404(1)
#     app.logger.info(d)
#     message = MIMEMultipart('alternative')
#     message['Subject'] = "Weekly Staff Updates"
#     message['From'] = me
#     message['To'] = you
#     html = """\
#     <!DOCTYPE html>
#     <html lang="en">
#     <head>
#         <meta charset="UTF-8">
#         <title>Articles</title>
#     </head>
#     <body>
#           <h1></h1>"""
#     # for d in article_data:
#     title = d.title
#     author = d.author
#     date = d.date_posted.strftime("%m/%d/%Y %H:%M:%S")
#     body = d.body
#     body = re.sub(r'(<img alt="" src=")', r'\1http://localhost:5000', body)
#     body = re.sub(r'(<p)', r'\1 style="font-size: 15px;"', body)
#     # app.logger.info(body)
#     html = html + "<h2>"
#     html = html + title + "</h2> <small>Written by " + author + " on " + date + "</small>"
#     html = html + "<hr>"
#     html = html + "<div>"
#     html = html + body + "</div>"
#     html = html + "<hr>"
#     html = html + """</body>
#     </html>
#     """
#     html_file = open("upload/" + title + ".html", "w")
#     html_file.write(html)
#     html_file.close()
#     # Record the MIME types of both parts - text/plain and text/html.
#     # part1 = MIMEText(text, 'plain')
#     config = pdfkit.configuration(wkhtmltopdf="C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe")
#     part2 = MIMEText(html, 'html')
#     pdfkit.from_file('upload/' + title + '.html', 'upload/' + title + '.pdf', configuration=config)
#     # pdf = pdfkit.from_file('article.html', False)
#     filename = 'upload/' + title + '.pdf'
#     fo = open(filename, 'rb')
#     attach = email.mime.application.MIMEApplication(fo.read(), _subtype="pdf")
#     fo.close()
#     attach.add_header('Content-Disposition', 'attachment', filename=filename)
#
#     app.logger.info(html)
#
#     mail_body = """\
#     <!DOCTYPE html>
#     <html lang="en">
#     <head>
#         <meta charset="UTF-8">
#         <title>Articles</title>
#     </head>
#     <body>
#           <h3>Hello Reader</h3>
#           <p style="font-size: 15px;"> Thanks for downloading this article, your article has been attached in the mail</p>
#           <p style="font-size: 15px;"> Please share your valuable feedback to us ! </p>
#           <p style="font-size: 15px;"> Happy Learning! </p>
#           <p style="font-size: 15px;"> Thanks | Flask app Developers</p>
#           """
#     part_subject = MIMEText(mail_body, 'html')
#     # Attach parts into message container.
#     # According to RFC 2046, the last part of a multipart message, in this case
#     # the HTML message, is best and preferred.
#     # msg.attach(part1)
#     message.attach(attach)
#     message.attach(part_subject)
#
#     # Send the message via local SMTP server.
#     s = smtplib.SMTP('smtp.microfocus.com:25')
#     # sendmail function takes 3 arguments: sender's address, recipient's address
#     # and message to send - here it is sent as one string.
#     s.sendmail(me, you, message.as_string())
#     s.quit()
#     flash("Message sent successfully!", 'success')
#     return redirect(url_for('articles'))


@app.route('/send_article', methods=['GET', 'POST'])
@is_logged_in
def send_article():
    # me = "nam-qa-update@microfocus.com"
    # you = "mohamediburahimsha.s@microfocus.com"
    # #
    d = Articles.query.get_or_404(1)
    app.logger.info(d)
    # message = MIMEMultipart('alternative')
    # message['Subject'] = "Weekly Staff Updates"
    # message['From'] = me
    # message['To'] = you
    html = """\
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Articles</title>
    </head>
    <body>
          <h1></h1>"""
    # for d in article_data:
    title = d.title
    author = d.author
    date = d.date_posted.strftime("%m/%d/%Y %H:%M:%S")
    body = d.body
    # body = re.sub(r'(<img alt="" src=")', r'\1http://localhost:5000', body)
    body = re.sub(r'(<img alt="" src=")', r'\1http://nam-users.southeastasia.cloudapp.azure.com', body)
    body = re.sub(r'(<p)', r'\1 style="font-size: 15px;"', body)
    # app.logger.info(body)
    html = html + "<h2>"
    html = html + title + "</h2> <small>Written by " + author + " on " + date + "</small>"
    html = html + "<hr>"
    html = html + "<div>"
    html = html + body + "</div>"
    html = html + "<hr>"
    html = html + """</body>
    </html>
    """
    html_file = open(basedir + "/upload/" + title + ".html", "w")
    html_file.write(html)
    html_file.close()
    # Record the MIME types of both parts - text/plain and text/html.
    # part1 = MIMEText(text, 'plain')
    # config = pdfkit.configuration(wkhtmltopdf="C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe")
    # config = pdfkit.configuration(wkhtmltopdf="/usr/local/bin/wkhtmltopdf")
    part2 = MIMEText(html, 'html')
    # pdfkit.from_file(basedir+'/upload/' + title + '.html', basedir+'/upload/' + title + '.pdf', configuration=config)
    # app.logger.info(basedir + '/upload/' + title + '.pdf')
    # pdfkit.from_file(basedir + '/upload/' + title + '.html', basedir + '/upload/' + title + '.pdf')
    # pdf = pdfkit.from_file('article.html', False)

    # filename = basedir+'/upload/' + title + '.pdf'
    # with open(filename, 'rb') as f:
    #    data = f.read()
    #    f.close()
    # encoded = base64.b64encode(data).decode()
    # attachment = Attachment()
    # attachment.file_content = FileContent(encoded)
    # attachment.file_type = FileType('application/pdf')
    # attachment.file_name = FileName(title + '.pdf')
    # attachment.disposition = Disposition('attachment')
    # attachment.content_id = ContentId('Example Content ID')
    # message.attachment = attachment
    # app.logger.info(html)
    mail_body = """\
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Articles</title>
    </head>
    <body>
          <h3>Hello """ + session['name'] + """,</h3>
          <p style="font-size: 15px;"> Thanks for downloading this article, your article has been attached in the mail</p>
          <p style="font-size: 15px;"> Please share your valuable feedback to us ! </p>
          <p style="font-size: 15px;"> Happy Learning! </p>
          <p style="font-size: 15px;"> Thanks | Flask app Developers</p>
          """
    # part_subject = MIMEText(mail_body, 'html')//
    # Attach parts into message container.
    # According to RFC 2046, the last part of a multipart message, in this case
    # the HTML message, is best and preferred.
    # msg.attach(part1)
    # message.attach(attach)//
    # message.attach(part_subject)//

    # Send the message via local SMTP server.
    # s = smtplib.SMTP('smtp.microfocus.com:25')//
    # sendmail function takes 3 arguments: sender's address, recipient's address
    # and message to send - here it is sent as one string.
    # s.sendmail(me, you, message.as_string())//
    # s.quit()//
    message = Mail(
        from_email='flaskapp@nam-qa-mf.com',
        to_emails=To(session['email']),
        subject='Article from flaskapp - ' + title + '.pdf',
        html_content='<strong>and easy to do anywhere, even with Python</strong>')
    # message.attachment = attachment
    # message.add_content('text/html', mail_body)
    try:
        sg = sendgrid.SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
        response = sg.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print(str(e))
    flash("Message sent successfully!", 'success')
    return redirect(url_for('articles'))


def pdf_creation(title):
    pdf = weasyprint.HTML(basedir + '/upload/html/' + title + '.html').write_pdf()
    open(basedir + "/upload/pdf/" + title + ".pdf", 'wb').write(pdf)

# def pdf_creation(title):
#     config = pdfkit.configuration(wkhtmltopdf="C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe")
#     pdfkit.from_file(basedir + '/upload/html/' + title + '.html', basedir + '/upload/pdf/' + title + '.pdf',
#                      configuration=config)



def html_creation(art_id):
    d = Articles.query.get_or_404(art_id)
    title = d.title
    author = d.author
    date = d.date_posted.strftime("%m/%d/%Y %H:%M:%S")
    body = d.body
    app.logger.info(body)
    html = """\
           <!DOCTYPE html>
           <html lang="en">
           <head>
               <meta charset="UTF-8">
               <title>Articles</title>
           </head>
           <body>
                 <h1></h1>"""
    # body = re.sub(r'(<img alt="" src=")', r'\1http://localhost:5000', body)
    body = re.sub(r'(<img alt="" src=")', r'\1http://nam-users.southeastasia.cloudapp.azure.com', body)
    body = re.sub(r'(<p)', r'\1 style="font-size: 15px;"', body)

    html = html + "<h2>"
    html = html + title + "</h2> <small>Written by " + author + " on " + date + "</small>"
    html = html + "<hr>"
    html = html + "<div>"
    html = html + body + "</div>"
    html = html + "<hr>"
    html = html + """</body>
           </html>
           """
    html_file = open(basedir + "/upload/html/" + title + ".html", "w")
    html_file.write(html)
    html_file.close()


@app.route('/send_article_new/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def send_article_new(id):
    username = 'apikey'
    sender_email = "flask-app-noreply@nam-qa-mf.com"
    receiver_email = session['email']
    # password = os.environ.get('SENDGRID_API_KEY')
    password = global_app_key

    d = Articles.query.get_or_404(id)
    title = d.title
    author = d.author
    date = d.date_posted.strftime("%m/%d/%Y %H:%M:%S")
    body = d.body
    app.logger.info(d)

    message = MIMEMultipart("alternative")
    message["Subject"] = title
    message["From"] = sender_email
    message["To"] = receiver_email
    html = """\
       <!DOCTYPE html>
       <html lang="en">
       <head>
           <meta charset="UTF-8">
           <title>Articles</title>
       </head>
       <body>
             <h1></h1>"""
    # body = re.sub(r'(<img alt="" src=")', r'\1http://localhost:5000', body)
    body = re.sub(r'(<img alt="" src=")', r'\1http://nam-users.southeastasia.cloudapp.azure.com', body)
    body = re.sub(r'(<p)', r'\1 style="font-size: 15px;"', body)

    html = html + "<h2>"
    html = html + title + "</h2> <small>Written by " + author + " on " + date + "</small>"
    html = html + "<hr>"
    html = html + "<div>"
    html = html + body + "</div>"
    html = html + "<hr>"
    html = html + """</body>
       </html>
       """
    mail_body = """\
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Articles</title>
    </head>
    <body>
          <h3>Hello """ + session['name'] + """,</h3>
          <p style="font-size: 15px;"> Thanks for downloading this article, your article has been attached in the mail</p>
          <p style="font-size: 15px;"> Please share your valuable feedback to us ! </p>
          <p style="font-size: 15px;"> Happy Learning! </p>
          <p style="font-size: 15px;"> Thanks | Flask app Developers</p>
          """

    # html_file = open(basedir + "/upload/" + title + ".html", "w")
    # html_file.write(html)
    # html_file.close()
    # part1 = MIMEText(mail_body, "html")
    part2 = MIMEText(html, "html")

    # Add HTML/plain-text parts to MIMEMultipart message
    # The email client will try to render the last part first
    message.attach(part2)
    # message.attach(part2)
    # HTML(basedir+'/upload/' + title + '.html').write_pdf(basedir+'/upload/' + title + '.pdf')
    # pdf = HTML(basedir+'/upload/' + title + '.html').write_pdf()
    # open(basedir + "/upload/" + title + ".pdf", 'wb').write(pdf)
    # config = pdfkit.configuration(wkhtmltopdf='/usr/local/bin/wkhtmltopdf')
    # pdfkit.from_file(basedir+'/upload/' + title + '.html', basedir+'/upload/' + title + '.pdf', configuration=config)

    # filename = basedir+'/upload/' + title + '.pdf'
    # attachment = open(filename, "rb")
    #
    # part = MIMEBase('application', 'octet-stream')
    # part.set_payload(attachment.read())
    # encoders.encode_base64(part)
    # part.add_header('Content-Disposition', "attachment; filename= %s" % filename)
    #
    # message.attach(part)

    # Create secure connection with server and send email
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.sendgrid.net", 465, context=context) as server:
        server.login(username, password)
        server.sendmail(
            sender_email, receiver_email, message.as_string()
        )
    flash("Mail sent successfully!", 'success')
    return redirect(url_for('articles'))


@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=15)


@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500


# User Details page
@app.route('/user_details')
@is_logged_in
# @is_logged_in_admin_user
def user_details():
    # Get articles
    result = db.session.query(Users).count()
    users = Users.query.all()

    if result > 0:
        return render_template('user_details.html', users=users)
    else:
        msg = "No users Found"
        return render_template('user_details.html', msg=msg)


@app.route('/delete_user/<string:id>', methods=['GET', 'POST'])
@is_logged_in
# @is_logged_in_admin_user
def delete_user(id):
    # Execute
    user_delete = Users.query.get_or_404(id)
    db.session.delete(user_delete)
    # Commit DB
    db.session.commit()
    flash("User deleted successfully!", 'success')
    return redirect(url_for('user_details'))


@app.route('/url_links')
def url_links():
    # Get articles
    result = db.session.query(Urls).count()
    urls = Urls.query.all()

    if result > 0:
        return render_template('imp_links.html', urls=urls)
    else:
        msg = "No links Found"
        return render_template('imp_links.html', msg=msg)


# URL Form Class
class URLUpdateForm(Form):
    url_name = StringField('URL Name', [validators.length(min=1, max=200)])
    url = StringField('URL', [validators.length(min=5)])


@app.route('/add_url', methods=['GET', 'POST'])
def add_url():
    form = URLUpdateForm(request.form)
    if request.method == 'POST' and form.validate():
        url_name = form.url_name.data
        url = form.url.data
        # Execute
        urls = Urls(url_name=url_name, url=url)
        db.session.add(urls)
        # Commit DB
        db.session.commit()
        flash("Url added!", 'success')
        return redirect(url_for('url_links'))
    return render_template('add_url.html', form=form)


@app.route('/edit_url/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_url(id):
    # Get article by id
    url_edit = Urls.query.get_or_404(id)
    # Get form
    form = URLUpdateForm(request.form)
    # Populate the article form fields
    form.url_name.data = url_edit.url_name
    form.url.data = url_edit.url
    if request.method == 'POST' and form.validate():
        url_edit.url_name = request.form['url_name']
        url_edit.url = request.form['url']
        # Commit DB
        db.session.commit()
        flash("Updated successfully!", 'success')
        return redirect(url_for('url_links'))
    return render_template('edit_url.html', form=form)


@app.route('/delete_url/<string:id>', methods=['GET', 'POST'])
@is_logged_in
@is_logged_in_admin_url
def delete_url(id):
    url_delete = Urls.query.get_or_404(id)
    db.session.delete(url_delete)
    # Commit DB
    db.session.commit()
    flash("Url deleted successfully!", 'success')
    return redirect(url_for('url_links'))


@app.route('/add_task', methods=['GET', 'POST'])
def add_task():
    if request.method == 'POST':
        task = request.form['task']
        name = request.form['name']
        status = request.form['status']
        # Execute
        tasks = Tasks(task=task, name=name, status=status)
        db.session.add(tasks)
        # Commit DB
        db.session.commit()
        flash("User task added!", 'success')
        return redirect('/add_task')
    else:
        all_tasks = Tasks.query.all()
        all_users = Users.query.all()
        return render_template('dynamic_table.html', tasks=all_tasks, users=all_users)


@app.route('/edit_task/<string:task_id>', methods=['GET', 'POST'])
@is_logged_in
def edit_task(task_id):
    task_edit = Tasks.query.get_or_404(task_id)
    all_users = Users.query.all()
    if request.method == 'POST':
        task_edit.task = request.form['task']
        task_edit.name = request.form['name']
        task_edit.status = request.form['status']
        task_edit.comments = request.form['comments']
        db.session.commit()
        flash("User task edited!", 'success')
        return redirect('/add_user_task')
    else:
        return render_template('edit_task.html', tasks=task_edit, users=all_users)


@app.route('/delete_task/<string:task_id>', methods=['GET', 'POST'])
@is_logged_in
def delete_task(task_id):
    task_delete = Tasks.query.get_or_404(task_id)
    db.session.delete(task_delete)
    # Commit DB
    db.session.commit()
    flash("Task deleted successfully!", 'success')
    return redirect('/add_user_task')


@app.route('/add_user_task', methods=['GET', 'POST'])
@is_logged_in
def add_user_task():
    cur = mysql.connection.cursor()
    cur.execute("SELECT name, COUNT( name ) x FROM tasks GROUP BY name HAVING x >0")
    results = cur.fetchall()
    if request.method == 'POST':
        task = request.form['task']
        name = request.form['name']
        status = request.form['status']
        # Execute
        tasks = Tasks(task=task, name=name, status=status)
        db.session.add(tasks)
        # Commit DB
        db.session.commit()
        flash("User task added!", 'success')
        return redirect('/add_user_task')
    else:
        all_tasks = Tasks.query.all()
        all_users = Users.query.all()
        return render_template('user_task_list.html', tasks=all_tasks, users=all_users, total_tasks=results)


# Profile_Page
@app.route('/profile', methods=['GET', 'POST'])
@is_logged_in
def profile():
    check = Users.query.filter_by(username=session['username']).first()
    if request.method == 'POST':
        check.name = request.form['name']
        check.username = request.form['username']
        check.email = request.form['email']
        db.session.commit()
        session['name'] = check.name
        session['username'] = check.username
        flash("Profile Updated!", 'success')
        check = Users.query.filter_by(username=session['username']).first()
        return render_template('profile.html', check=check)
    return render_template('profile.html', check=check)


# Change_Password
@app.route('/old_pwd_change', methods=['GET', 'POST'])
@is_logged_in
def old_pwd_change():
    check = Users.query.filter_by(username=session['username']).first()
    if request.method == 'POST':
        oldpwd = request.form['oldpwd']
        newpwd = request.form['newpwd']
        confpwd = request.form['confpwd']
        if sha256_crypt.verify(oldpwd, check.password):
            if newpwd == confpwd:
                check.password = sha256_crypt.encrypt(newpwd)
                db.session.commit()
                flash('Your password has been changed successfully!', 'success')
                return redirect(url_for('old_pwd_change'))
            else:
                flash('Password mismatched!', 'danger')
                return render_template('change_pwd1.html')
        else:
            flash('Incorrect old password !', 'danger')
            return render_template('change_pwd1.html')
    else:
        return render_template('change_pwd1.html')


if __name__ == '__main__':
    app.run(debug=True)
