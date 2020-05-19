from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import (DataRequired, Regexp, ValidationError, Email,
                                Length, EqualTo)

from models import User


def name_exists(form, field):
    if User.select().where(User.username == field.data).exists():
        raise ValidationError('Username already in use.')


def email_exists(form, field):
    if User.select().where(User.email == field.data).exists():
        raise ValidationError('Email already in use.')


class RegisterForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[
            DataRequired(),
            Regexp(
                r'^[a-zA-Z0-9]+$',
                message=("Username's can contain letters and "
                         "numbers only.")
            ),
            name_exists
        ])
    email = StringField(
        'Email',
        validators=[
            DataRequired(),
            Email(),
            email_exists
        ])
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(),
            Length(min=2),
            EqualTo('password2', message='Password does not match.')
        ])
    password2 = PasswordField(
        'Confirm Password',
        validators=[DataRequired()]
    )


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])


class PostForm(FlaskForm):
    content = TextAreaField("What's up?", validators=[DataRequired()])
