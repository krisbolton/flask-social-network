"""
A flask web app for a security course by Kris Bolton (https://breakthis.app).
App adapted from tutorials by Flask, Teamtreehouse and Python API Development Fundamentals (Packt)

"""

from http import HTTPStatus
from flask import (Flask, g, render_template, flash, redirect,
                   url_for, abort)
from flask_bcrypt import check_password_hash
from flask_login import (LoginManager, login_user, logout_user,
                         login_required, current_user)

from models import DATABASE, init_db, AnonymousUser, User, Post, Relationship
from forms import PostForm, RegisterForm, LoginForm


DEBUG = True
PORT = 8000
HOST = '127.0.0.1'

app = Flask(__name__)
app.secret_key = '.1@_o2Ew.,M#?[g|'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.anonymous_user = AnonymousUser


@login_manager.user_loader
def load_user(user_id):
    """Flask_login user_loader. Reloads user object from user ID stored in session.

    :param user_id:
    :return: User.id or None
    """
    try:
        return User.get(User.id == user_id)
    except User.DoesNotExist:
        return None


@app.before_request
def before_request():
    """Registers function to run before a request."""
    g.db = DATABASE
    g.db.connect()
    g.user = current_user


@app.after_request
def after_request(response):
    """Registers function to run after a request."""
    g.db.close()
    return response


@app.route('/register', methods=('GET', 'POST'))
def register():
    """User registration function.

    :return: render_template()
    """
    form = RegisterForm()
    if form.validate_on_submit():
        flash("Registration successful", "success")
        User.create_user(
            username=form.username.data,
            email=form.email.data,
            password=form.password.data
        )
        return redirect(url_for('index'))
    return render_template('register.html', form=form)


@app.route('/login', methods=('GET', 'POST'))
def login():
    """User login function.

    :return: render_template()
    """
    form = LoginForm()
    if form.validate_on_submit():
        try:
            user = User.get(User.email == form.email.data)
        except User.DoesNotExist:
            flash("Email or password don't match", "error")
        else:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                flash("Login successful", "success")
                return redirect(url_for('index'))

        flash("Email or password don't match", "error")
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    """User logout function. Login required.

    :return: redirect()
    """
    logout_user()
    flash("Logout successful", "success")
    return redirect(url_for('index'))


@app.route('/new_post', methods=('GET', 'POST'))
@login_required
def post():
    """User post function. Login required.

    :return: render_template.
    """
    form = PostForm()
    if form.validate_on_submit():
        Post.create(user=g.user.id,
                    content=form.content.data.strip())
        flash("Message posted", "success")
        return redirect(url_for('index'))
    return render_template('post.html', form=form)


@app.route('/')
def index():
    """Render feed on index.html.

    :return: render_template()
    """
    feed = Post.select().limit(100)
    return render_template('feed.html', feed=feed)


@app.route('/feed')
@app.route('/feed/<username>')
def feed(username=None):
    """User post feed.

    :param username:
    :return: render_template()
    """
    template = 'feed.html'
    if current_user.username == 'Guest':
        return render_template('unauthorized.html'), HTTPStatus.UNAUTHORIZED
    elif username and username != current_user.username:
        try:
            user = User.select().where(
                User.username ** username).get()
        except User.DoesNotExist:
            return render_template('user-nonexistent.html'), HTTPStatus.NOT_FOUND
    else:
        feed = current_user.get_feed().limit(100)
        user = current_user
    if username:
        feed = current_user.get_feed().limit(100)
        template = 'user_feed.html'
    return render_template(template, feed=feed, user=user)


@app.route('/post/<int:post_id>')
def view_post(post_id):
    """View individual user post.

    :param post_id:
    :return: render_template()
    """
    posts = Post.select().where(Post.id == post_id)
    if posts.count() == 0:
        abort(404)
    return render_template('feed.html', feed=posts)


@app.route('/follow/<username>')
@login_required
def follow(username):
    """Follow user function. Login required.

    :param username:
    :return: redirect()
    """
    try:
        to_user = User.get(User.username ** username)
    except User.DoesNotExist:
        abort(404)
    else:
        try:
            Relationship.create(
                from_user=g.user._get_current_object(),
                to_user=to_user
            )
        except Relationship.IntegrityError:
            to_user = User.get(User.username ** username)
        else:
            flash("Following {}".format(to_user.username), "success")
    return redirect(url_for('feed', username=to_user.username))


@app.route('/unfollow/<username>')
@login_required
def unfollow(username):
    """User unfollow function. Login required.

    :param username:
    :return: redirect()
    """
    try:
        to_user = User.get(User.username ** username)
    except User.DoesNotExist:
        abort(404)
    else:
        try:
            Relationship.get(
                from_user=g.user._get_current_object(),
                to_user=to_user
            ).delete_instance()
        except Relationship.IntegrityError:
            pass
        else:
            flash("Unfollowed {}".format(to_user.username), "success")
    return redirect(url_for('feed', username=to_user.username))


@app.errorhandler(404)
def not_found(error):
    """404 Error

    :param error:
    :return: render_template()
    """
    return render_template('404.html'), 404


if __name__ == '__main__':
    init_db()
    try:
        User.create_user(
            username='ZeroCool',
            email='zerocool@hackers.com',
            password='Zer0',
            admin=False
        )
    except ValueError:
        pass
    app.run(debug=DEBUG, host=HOST, port=PORT)
