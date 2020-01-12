from flask import Flask, render_template, flash, url_for, session, logging, request, redirect
from flask_sqlalchemy import SQLAlchemy
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from wtforms.fields.html5 import EmailField
from passlib.hash import sha256_crypt
from functools import wraps
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import timedelta, datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

app.secret_key = 'novell@123'


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

    def __repr__(self):
        return 'Articles ' + str(self.id)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    register_date = db.Column(db.DateTime, nullable=False, default=datetime.now)

    def __repr__(self):
        return 'Users ' + str(self.id)


class Urls(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url_name = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return 'Urls ' + str(self.id)


# Home Page
@app.route('/')
def home():
    return render_template('home.html')


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
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # Create a Cursor
        account = Users.query.filter_by(username=username).first()
        # If account exists show error and validation checks
        if account:
            error = 'Account already exists!'
            return render_template('register.html', form=form, error=error)
        else:
            user = Users(name=name, email=email, username=username, password=password)
            db.session.add(user)
            db.session.commit()
            flash('You are now registered and can log in', 'success')
            return redirect(url_for('home'))
    return render_template('register.html', form=form)


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

            # Compare passwords
            if sha256_crypt.verify(password_candidate, password):
                # PASSED
                session['logged_in'] = True
                session['username'] = username
                session['name'] = name
                flash("You are now logged in", 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Incorrect username/password!'
                return render_template('login.html', error=error)
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('login.html')


# role based control
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))

    return wrap


def is_logged_in_admin_user(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'admin' == session['username']:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login with admin user', 'danger')
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
    return redirect(url_for('login'))


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

        # Execute
        article_data = Articles(title=title, body=body, author=session['username'])
        db.session.add(article_data)
        # Commit DB
        db.session.commit()

        flash("Article Created", 'success')
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
        db.session.commit()
        flash("Article Updated", 'success')
        if page == 'dashboard':
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('articles'))

    return render_template('edit_article.html', form=form)


@app.route('/delete_article/<string:id>', methods=['POST'])
@is_logged_in
def delete_article(id):
    # Execute
    article_delete = Articles.query.get_or_404(id)
    db.session.delete(article_delete)
    # Commit DB
    db.session.commit()
    flash("Article Deleted", 'success')
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
        flash("User updates created/added", 'success')
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
        flash("Updated successfully", 'success')
        return redirect(url_for('dashboard'))

    return render_template('edit_update.html', form=form)


@app.route('/delete_update/<string:id>', methods=['POST'])
@is_logged_in
def delete_update(id):
    # Execute
    update_delete = BlogPost.query.get_or_404(id)
    db.session.delete(update_delete)
    # Commit DB
    db.session.commit()
    flash("Updates Deleted", 'success')
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
    flash("Message sent Successfully", 'success')
    return redirect(url_for('dashboard'))


@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=5)


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


@app.route('/delete_user/<string:id>', methods=['POST'])
@is_logged_in
# @is_logged_in_admin_user
def delete_user(id):
    # Execute
    user_delete = Users.query.get_or_404(id)
    db.session.delete(user_delete)
    # Commit DB
    db.session.commit()
    flash("User Deleted Successfully!", 'success')
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
        flash("URL added", 'success')
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
        flash("Updated successfully", 'success')
        return redirect(url_for('url_links'))
    return render_template('edit_url.html', form=form)


@app.route('/delete_url/<string:id>', methods=['POST'])
@is_logged_in
@is_logged_in_admin_url
def delete_url(id):
    url_delete = Urls.query.get_or_404(id)
    db.session.delete(url_delete)
    # Commit DB
    db.session.commit()
    flash("URL Deleted Successfully!", 'success')
    return redirect(url_for('url_links'))


if __name__ == '__main__':
    app.run(debug=True)
