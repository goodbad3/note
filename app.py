from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os
import sys
import click
from flask_wtf import FlaskForm
from wtforms import SubmitField, TextAreaField,StringField,BooleanField,PasswordField
from wtforms.validators import DataRequired, Length
from flask import redirect, url_for, abort, render_template, flash,request
import pymysql
from flask_ckeditor import CKEditor
from flask_ckeditor import CKEditorField
from datetime import datetime
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from faker import Faker
from flask_wtf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager
from flask_login import UserMixin
from flask_login import login_user, logout_user, login_required, current_user
from urllib.parse import urlparse, urljoin
app = Flask(__name__)
WIN = sys.platform.startswith('win')
if WIN:
    prefix = 'sqlite:///'
else:
    prefix = 'sqlite:////'
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'secret string')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', prefix + os.path.join(app.root_path, 'data.db'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['CKEDITOR_SERVE_LOCAL'] = True
app.config['NOTE_POST_PER_PAGE'] = 10
db = SQLAlchemy(app)
ckeditor = CKEditor(app)
bootstrap = Bootstrap(app)
moment = Moment(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    title = db.Column(db.String(20))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def __repr__(self):
        return '<Note %r>' % self.body    

@app.cli.command()
@click.option('--drop', is_flag=True, help='Create after drop.')
def initdb(drop):
    if drop:
        db.drop_all()
    db.create_all()
    click.echo('Initialized database.')

@app.cli.command()
@click.option('--count', default=20, help='Quantity of messages, default is 20.')
def forge(count):
    db.drop_all()
    db.create_all()
    fake = Faker('zh_CN')
    click.echo('Working...')
    for i in range(count):
        note = Note(
            title=fake.name(),
            body=fake.sentence(),
            timestamp=fake.date_time_this_year()
        )
        db.session.add(note)

    db.session.commit()
    click.echo('Created %d fake notes.' % count)    
class NewNoteForm(FlaskForm):
    title = StringField('Name', validators=[DataRequired(), Length(1, 20)])
    body = CKEditorField('Body', validators=[DataRequired()])
    submit = SubmitField('Save')
@app.route('/new', methods=['GET', 'POST'])
def new_note():
    form = NewNoteForm()
    if form.validate_on_submit():
        title = form.title.data
        body = form.body.data
        note = Note(body=body,title=title)
        db.session.add(note)
        db.session.commit()
        flash('Your note is saved.')
        return redirect(url_for('index'))
    return render_template('new_note.html', form=form)
@app.route('/')
def index():
    form = DeleteNoteForm()
    page = request.args.get('page', 1, type=int)
    per_page = app.config['NOTE_POST_PER_PAGE']
    pagination = Note.query.order_by(Note.timestamp.desc()).paginate(page, per_page=per_page)
    notes = pagination.items
    return render_template('index.html', notes=notes, form=form,pagination=pagination)

class EditNoteForm(NewNoteForm):
    submit = SubmitField('Update')
@app.route('/edit/<int:note_id>', methods=['GET', 'POST'])
@login_required
def edit_note(note_id):
    form = EditNoteForm()
    note = Note.query.get(note_id)
    if form.validate_on_submit():
        note.title = form.title.data
        note.body = form.body.data
        db.session.commit()
        flash('Your note is updated.')
        return redirect(url_for('index'))
    form.title.data = note.title
    form.body.data = note.body 
    return render_template('edit_note.html', form=form)
class DeleteNoteForm(FlaskForm):
    submit = SubmitField('Delete')
@app.route('/delete/<int:note_id>', methods=['POST'])
@login_required
def delete_note(note_id):
    form = DeleteNoteForm()
    if form.validate_on_submit():
        note = Note.query.get(note_id)
        db.session.delete(note)
        db.session.commit()
        flash('Your note is deleted.')
    else:
        abort(400)
    return redirect(url_for('index'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

class Admin(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20))
    password_hash = db.Column(db.String(128))
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def validate_password(self, password):
        return check_password_hash(self.password_hash, password)
    

@app.cli.command()
@click.option('--username', prompt=True, help='The username used to login.')
@click.option('--password', prompt=True, hide_input=True,
                  confirmation_prompt=True, help='The password used to login.')
def initadmin(username, password):
        admin = Admin.query.first()
        if admin is not None:
            click.echo('The administrator already exists, updating...')
            admin.username = username
            admin.set_password(password)
        else:
            click.echo('Creating the temporary administrator account...')
            admin = Admin(
                username=username)
            admin.set_password(password)
            db.session.add(admin)
        db.session.commit()
        click.echo('Done.')

@login_manager.user_loader
def load_user(user_id):
    user = Admin.query.get(int(user_id))
    return user

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        remember = form.remember.data
        admin = Admin.query.first()
        if admin:
            if username == admin.username and admin.validate_password(password):
                login_user(admin, remember)
                flash('Welcome back.', 'info')
                return redirect_back()
            flash('Invalid username or password.')
        else:
            flash('No account.', 'warning')
    return render_template('login.html', form=form)                                      	
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(1, 20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(1, 128)])
    remember = BooleanField('Remember me')
    submit = SubmitField('Log in')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout success.')
    return redirect_back()
login_manager.login_view = 'login'
login_manager.login_message = '请登录'
login_manager.login_message_category = 'warning'
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc
def redirect_back(default='index', **kwargs):
    for target in request.args.get('next'), request.referrer:
        if not target:
            continue
        if is_safe_url(target):
            return redirect(target)
    return redirect(url_for(default, **kwargs))
@app.context_processor
def make_template_context():
        admin = Admin.query.first()
        return dict(admin=admin)




