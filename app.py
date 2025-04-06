from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from forms import RegisterForm, LoginForm, ForgotPasswordForm
from models import db, User
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)

# Configuración segura
app.config['SECRET_KEY'] = 'clave_super_segura'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicializar extensiones
db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.session_protection = "strong"
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://"
)
limiter.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        try:
            existing_user = User.query.filter_by(email=form.email.data).first()
            if existing_user:
                flash('Este correo electrónico ya está registrado. ¿Olvidaste tu contraseña?', 'danger')
                return redirect(url_for('forgot_password'))
            
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            new_user = User(
                username=form.username.data,
                email=form.email.data,
                password=hashed_password
            )
            
            db.session.add(new_user)
            db.session.commit()
            flash('Registro exitoso. Ahora puedes iniciar sesión.', 'success')
            return redirect(url_for('login'))
        
        except IntegrityError:
            db.session.rollback()
            flash('Error al registrar el usuario. El correo electrónico ya existe.', 'danger')
            return redirect(url_for('register'))
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Credenciales incorrectas. ¿Olvidaste tu contraseña?', 'danger')
    return render_template('login.html', form=form)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            try:
                db.session.delete(user)
                db.session.commit()
                flash('Cuenta eliminada. Puedes registrarte nuevamente.', 'info')
                return redirect(url_for('register'))
            except Exception as e:
                db.session.rollback()
                flash('Error al eliminar la cuenta. Inténtalo nuevamente.', 'danger')
        else:
            flash('No existe una cuenta con este correo electrónico.', 'danger')
    return render_template('forgot_password.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión.', 'info')
    return redirect(url_for('login'))

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, port=5001)
