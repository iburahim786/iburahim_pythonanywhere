from flask import Flask, render_template, flash, url_for, session, logging, request, redirect
# from data import Articles
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os, sys

app = Flask(__name__)

# Articles = Articles()

# Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'novell@123'
app.config['MYSQL_DB'] = 'myflaskapp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# init MYSQL
mysql = MySQL(app)

sys.path.append('C:/Users/mis/PycharmProjects/NewApp')


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
    # Create cursor
    cur = mysql.connection.cursor()

    # Get articles
    result = cur.execute("SELECT * FROM articles")

    articles = cur.fetchall()

    if result > 0:
        return render_template('articles.html', articles=articles)
    else:
        msg = "No Articles Found"
        return render_template('articles.html', msg=msg)
    # Cursor Close
    cur.close()


# Individual Article page
@app.route('/article/<string:id>/')
def article(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Get article
    result = cur.execute("SELECT * FROM articles WHERE id = %s", [id])

    article = cur.fetchone()

    return render_template('article.html', article=article)


# Team Updates page
@app.route('/tupdates')
def tupdates():
    # Create cursor
    cur = mysql.connection.cursor()

    # Get articles
    result = cur.execute("SELECT * FROM tupdates")

    tupdates = cur.fetchall()

    if result > 0:
        return render_template('tupdates.html', tupdates=tupdates)
    else:
        msg = "No Updates Found"
        return render_template('tupdates.html', msg=msg)
    # Cursor Close
    cur.close()


# Individual update page
@app.route('/tupdate/<string:id>/')
def tupdate(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Get article
    result = cur.execute("SELECT * FROM tupdates WHERE id = %s", [id])

    tupdate = cur.fetchone()

    return render_template('tupdate.html', tupdate=tupdate)


# Registration Form Class
class RegisterForm(Form):
    name = StringField('Name', [validators.length(min=1, max=50)])
    username = StringField('Username', [validators.length(min=4, max=25)])
    email = StringField('Email', [validators.length(min=6, max=50)])
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
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)",
                    (name, email, username, password))
        # Commit to DB
        mysql.connection.commit()
        # Close Connection
        cur.close()
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

        # Create Cursor
        cur = mysql.connection.cursor()

        # Get user by username
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['password']
            name = data['name']

            # Compare passwords
            if sha256_crypt.verify(password_candidate, password):
                # PASSED
                session['logged_in'] = True
                session['username'] = username
                session['name'] = name

                flash("You are now logged in", 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)
            # Close connection
            cur.close()

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


# Article Dashboard page
@app.route('/dashboard')
@is_logged_in
def dashboard():
    # Create cursor
    cur = mysql.connection.cursor()
    cur1 = mysql.connection.cursor()

    # Get articles
    result = cur.execute("SELECT * FROM articles")
    articles = cur.fetchall()

    result1 = cur1.execute("SELECT * FROM tupdates")
    tupdates = cur1.fetchall()

    if result > 0 and result1 > 0:
        return render_template('dashboard.html', tupdates=tupdates, articles=articles)
    elif result == 0 and result1 > 0:
        msg = "No Articles Found"
        return render_template('dashboard.html', tupdates=tupdates, msg=msg)
    elif result > 0 and result1 <= 0:
        msg = "No Updates Found"
        return render_template('dashboard.html', articles=articles, msg=msg)
    else:
        msg = "No Updates/Articles Found"
        return render_template('dashboard.html', msg=msg)

    # Cursor Close
    cur1.close()
    cur.close()
    cur1.close()


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

        # Create Cursor
        cur = mysql.connection.cursor()
        # Execute
        cur.execute("INSERT INTO articles(title, body, author) VALUES(%s, %s, %s)", (title, body, session['username']))
        # Commit DB
        cur.connection.commit()
        # Close Connection
        cur.close()

        flash("Article Created", 'success')

        return redirect(url_for('dashboard'))
    return render_template('add_article.html', form=form)


@app.route('/edit_article/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_article(id):
    # Create Cursor
    cur = mysql.connection.cursor()
    # Get article by id
    result = cur.execute("SELECT * FROM articles WHERE id = %s", [id])
    article = cur.fetchone()
    # Get form
    form = ArticlesForm(request.form)
    # Populate the article form fields
    form.title.data = article['title']
    form.body.data = article['body']
    if request.method == 'POST' and form.validate():
        title = request.form['title']
        body = request.form['body']
        # Create Cursor
        cur = mysql.connection.cursor()
        # Execute
        cur.execute("UPDATE articles SET title=%s, body=%s WHERE id=%s", (title, body, id))
        # Commit DB
        cur.connection.commit()
        # Close Connection
        cur.close()

        flash("Article Updated", 'success')

        return redirect(url_for('dashboard'))
    return render_template('edit_article.html', form=form)


@app.route('/delete_article/<string:id>', methods=['POST'])
@is_logged_in
def delete_article(id):
    # Create Cursor
    cur = mysql.connection.cursor()

    # Execute
    cur.execute("DELETE FROM articles WHERE id=%s", [id])

    # Commit DB
    cur.connection.commit()

    # Close Connection
    cur.close()

    flash("Article Deleted", 'success')

    return redirect(url_for('dashboard'))


#########################################################################################################


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

        # Create Cursor
        cur = mysql.connection.cursor()
        # Execute
        cur.execute("INSERT INTO tupdates(name, body, author) VALUES(%s, %s, %s)", (name, body, session['username']))
        # Commit DB
        cur.connection.commit()
        # Close Connection
        cur.close()

        flash("User updates created/added", 'success')

        return redirect(url_for('dashboard'))
    return render_template('add_update.html', form=form)


@app.route('/edit_update/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_update(id):
    # Create Cursor
    cur = mysql.connection.cursor()
    # Get article by id
    result = cur.execute("SELECT * FROM tupdates WHERE id = %s", [id])
    tupdate = cur.fetchone()
    # Get form
    form = TeamUpdateForm(request.form)
    # Populate the article form fields
    form.name.data = tupdate['name']
    form.body.data = tupdate['body']
    if request.method == 'POST' and form.validate():
        name = request.form['name']
        body = request.form['body']
        # Create Cursor
        cur = mysql.connection.cursor()
        # Execute
        cur.execute("UPDATE tupdates SET name=%s, body=%s WHERE id=%s", (name, body, id))
        # Commit DB
        cur.connection.commit()
        # Close Connection
        cur.close()

        flash("Updated successfully", 'success')

        return redirect(url_for('dashboard'))
    return render_template('edit_update.html', form=form)


@app.route('/delete_update/<string:id>', methods=['POST'])
@is_logged_in
def delete_update(id):
    # Create Cursor
    cur = mysql.connection.cursor()

    # Execute
    cur.execute("DELETE FROM tupdates WHERE id=%s", [id])

    # Commit DB
    cur.connection.commit()

    # Close Connection
    cur.close()

    flash("Updates Deleted", 'success')

    return redirect(url_for('dashboard'))


@app.route('/contactus')
def contactus():
    return render_template('contact_us.html')


@app.route('/mail')
def mail_content():
    cur = mysql.connection.cursor()
    html_page = ""
    # Get updates
    result = cur.execute("SELECT * FROM articles")

    team_updates = cur.fetchall()

    return render_template('mail_content.html', team_updates=team_updates)


@app.route('/send_mail', methods=['POST'])
@is_logged_in
def send_mail(to):
    me = "nam-qa-update@microfocus.com"
    you = "mohamediburahimsha.s@microfocus.com"
    # Create cursor
    cur = mysql.connection.cursor()
    #
    # # Get updates
    result = cur.execute("SELECT * FROM tupdates")
    #
    team_updates = cur.fetchall()
    app.logger.info(team_updates)

    #
    # template = get_template('templates/mail_content.html')
    #
    # html = template.render({'team_updates': team_updates})

    # Create message container - the correct MIME type is multipart/alternative.
    message = MIMEMultipart('alternative')
    message['Subject'] = "Link"
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
        name = d['name']
        body = d['body']
    # for d in team_updates:
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
    msg = "Message sent Successfully"
    return render_template('dashboard.html', msg=msg)


if __name__ == '__main__':
    app.secret_key = 'novell@123'
    os.environ['DJANGO_SETTINGS_MODULE'] = 'mysite.settings'
    app.run(debug=True)
