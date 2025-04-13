from dotenv import load_dotenv
import os
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from forms import RegisterForm, LoginForm, ForgotPasswordForm, VerifyForm
from models import db, User
from sqlalchemy.exc import IntegrityError
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
from datetime import timedelta
import pyotp
import qrcode
import io
import base64
import requests  # Para hacer solicitudes HTTP a la API de reCAPTCHA

load_dotenv()

app = Flask(__name__)

# Configuración segura
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuración JWT
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Token expira en 1 hora

# Configuración reCAPTCHA
app.config['RECAPTCHA_SITE_KEY'] = os.environ.get('RECAPTCHA_SITE_KEY')
app.config['RECAPTCHA_SECRET_KEY'] = os.environ.get('RECAPTCHA_SECRET_KEY')
app.config['RECAPTCHA_VERIFY_URL'] = "https://www.google.com/recaptcha/api/siteverify"
app.config['RECAPTCHA_THRESHOLD'] = 0.5  # Umbral para considerar una acción como válida
app.config['RECAPTCHA_ENABLED'] = os.environ.get('RECAPTCHA_ENABLED', 'true').lower() == 'true'

# Inicializar extensiones
db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.session_protection = "strong"
jwt = JWTManager(app)
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://"
)
limiter.init_app(app)

# Función mejorada para verificar reCAPTCHA
def verify_recaptcha(token, action):
    # Si reCAPTCHA está desactivado, siempre devolvemos True
    if not app.config['RECAPTCHA_ENABLED']:
        app.logger.info("reCAPTCHA desactivado: omitiendo verificación")
        return True
    
    # En modo debug, podemos usar un bypass adicional
    if app.debug and os.environ.get('BYPASS_RECAPTCHA', 'false').lower() == 'true':
        app.logger.info("Modo de desarrollo: omitiendo verificación de reCAPTCHA")
        return True
    
    if not token:
        app.logger.warning("No se recibió token de reCAPTCHA")
        return False
    
    data = {
        'secret': app.config['RECAPTCHA_SECRET_KEY'],
        'response': token
    }
    
    try:
        response = requests.post(app.config['RECAPTCHA_VERIFY_URL'], data=data)
        result = response.json()
        app.logger.info(f"Respuesta de reCAPTCHA: {result}")
        
        # Comprueba primero el éxito básico
        if not result.get('success'):
            app.logger.warning("La verificación de reCAPTCHA no fue exitosa")
            return False
        
        # Verificar la acción solo si está presente en el resultado
        if 'action' in result and result.get('action') != action:
            app.logger.warning(f"Acción incorrecta: {result.get('action')} vs {action}")
            return False
        
        # Verificar el score
        if result.get('score', 0) < app.config['RECAPTCHA_THRESHOLD']:
            app.logger.warning(f"Score demasiado bajo: {result.get('score')}")
            return False
        
        return True
    
    except Exception as e:
        app.logger.error(f"Error al verificar reCAPTCHA: {e}")
        # En caso de error, permitimos el paso si estamos en modo debug
        return app.debug

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
        # Verificar reCAPTCHA
        recaptcha_token = request.form.get('g-recaptcha-response')
        if not verify_recaptcha(recaptcha_token, 'register'):
            flash('Falló la verificación de seguridad. Por favor, inténtalo de nuevo.', 'danger')
            return render_template('register.html', form=form, recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'])
        
        try:
            existing_user = User.query.filter_by(email=form.email.data).first()
            if existing_user:
                flash('Este correo electrónico ya está registrado. ¿Olvidaste tu contraseña?', 'danger')
                return redirect(url_for('forgot_password'))
            
            # Generar secreto para 2FA
            totp_secret = pyotp.random_base32()
            
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            new_user = User(
                username=form.username.data,
                email=form.email.data,
                password=hashed_password,
                totp_secret=totp_secret,
                is_2fa_enabled=False  # Inicialmente desactivado hasta que el usuario lo configure
            )
            
            db.session.add(new_user)
            db.session.commit()
            flash('Registro exitoso. Ahora puedes iniciar sesión.', 'success')
            return redirect(url_for('login'))
        
        except IntegrityError:
            db.session.rollback()
            flash('Error al registrar el usuario. El correo electrónico ya existe.', 'danger')
            return redirect(url_for('register'))
    
    return render_template('register.html', form=form, recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'])

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        try:
            # Verificar reCAPTCHA con manejo de errores mejorado
            recaptcha_token = request.form.get('g-recaptcha-response')
            app.logger.info(f"Token recibido: {recaptcha_token[:20]}..." if recaptcha_token else "No se recibió token")
            
            if not verify_recaptcha(recaptcha_token, 'login'):
                flash('Falló la verificación de seguridad. Por favor, inténtalo de nuevo.', 'danger')
                return render_template('login.html', form=form, recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'])
            
            user = User.query.filter_by(email=form.email.data).first()
            app.logger.info(f"Usuario encontrado: {user is not None}")
            
            if user and bcrypt.check_password_hash(user.password, form.password.data):
                app.logger.info("Contraseña válida")
                # Si el usuario tiene 2FA habilitado, redirige a la verificación
                if user.is_2fa_enabled:
                    app.logger.info("2FA está habilitado, redirigiendo a verificación")
                    session['user_id_for_2fa'] = user.id
                    return redirect(url_for('verify_2fa'))
                
                # Si no tiene 2FA, procede con el login normal
                app.logger.info("Iniciando sesión del usuario")
                login_user(user)
                
                # Generar el token JWT
                access_token = create_access_token(identity=user.id)
                session['jwt_token'] = access_token
                
                flash('Inicio de sesión exitoso', 'success')
                return redirect(url_for('dashboard'))
            else:
                app.logger.warning("Credenciales inválidas")
                flash('Credenciales incorrectas. ¿Olvidaste tu contraseña?', 'danger')
        except Exception as e:
            app.logger.error(f"Error durante el login: {e}")
            flash('Ocurrió un error durante el inicio de sesión. Por favor, inténtalo de nuevo.', 'danger')
    
    return render_template('login.html', form=form, recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'])

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'user_id_for_2fa' not in session:
        return redirect(url_for('login'))
    
    form = VerifyForm()
    
    if form.validate_on_submit():
        # Verificar reCAPTCHA
        recaptcha_token = request.form.get('g-recaptcha-response')
        if not verify_recaptcha(recaptcha_token, 'verify_2fa'):
            flash('Falló la verificación de seguridad. Por favor, inténtalo de nuevo.', 'danger')
            return render_template('verify_2fa.html', form=form, recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'])
        
        user = User.query.get(session['user_id_for_2fa'])
        
        if not user:
            flash('Usuario no encontrado', 'danger')
            return redirect(url_for('login'))
        
        totp = pyotp.TOTP(user.totp_secret)
        
        # Verificar el código TOTP
        if totp.verify(form.code.data):
            login_user(user)
            
            # Generar el token JWT
            access_token = create_access_token(identity=user.id)
            session['jwt_token'] = access_token
            
            # Limpiar la sesión
            session.pop('user_id_for_2fa', None)
            
            flash('Verificación correcta', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Código incorrecto', 'danger')
    
    return render_template('verify_2fa.html', form=form, recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'])

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        # Verificar reCAPTCHA
        recaptcha_token = request.form.get('g-recaptcha-response')
        if not verify_recaptcha(recaptcha_token, 'forgot_password'):
            flash('Falló la verificación de seguridad. Por favor, inténtalo de nuevo.', 'danger')
            return render_template('forgot_password.html', form=form, recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'])
        
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
    return render_template('forgot_password.html', form=form, recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'])

@app.route('/setup_2fa')
@login_required
def setup_2fa():
    if current_user.is_2fa_enabled:
        flash('Ya tienes la autenticación de dos factores habilitada', 'info')
        return redirect(url_for('dashboard'))
    
    # Generar URI para QR code
    totp = pyotp.TOTP(current_user.totp_secret)
    uri = totp.provisioning_uri(name=current_user.email, issuer_name="TuAplicacion")
    
    # Generar QR code
    img = qrcode.make(uri)
    buffered = io.BytesIO()
    img.save(buffered)
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    # Mostrar el código de recuperación
    return render_template(
        'setup_2fa.html', 
        qr_code=img_str, 
        secret=current_user.totp_secret,
        recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY']
    )

@app.route('/enable_2fa', methods=['POST'])
@login_required
def enable_2fa():
    # Verificar reCAPTCHA
    recaptcha_token = request.form.get('g-recaptcha-response')
    if not verify_recaptcha(recaptcha_token, 'enable_2fa'):
        flash('Falló la verificación de seguridad. Por favor, inténtalo de nuevo.', 'danger')
        return redirect(url_for('setup_2fa'))
    
    code = request.form.get('code')
    
    totp = pyotp.TOTP(current_user.totp_secret)
    
    # Verificar el código TOTP
    if totp.verify(code):
        current_user.is_2fa_enabled = True
        db.session.commit()
        flash('Autenticación de dos factores habilitada correctamente', 'success')
    else:
        flash('Código incorrecto', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/disable_2fa', methods=['POST'])
@login_required
def disable_2fa():
    # Verificar reCAPTCHA
    recaptcha_token = request.form.get('g-recaptcha-response')
    if not verify_recaptcha(recaptcha_token, 'disable_2fa'):
        flash('Falló la verificación de seguridad. Por favor, inténtalo de nuevo.', 'danger')
        return redirect(url_for('dashboard'))
    
    current_user.is_2fa_enabled = False
    db.session.commit()
    flash('Autenticación de dos factores deshabilitada', 'info')
    return redirect(url_for('dashboard'))

# Nueva ruta para API de login que devuelve JWT
@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def api_login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400
    
    # Verificar reCAPTCHA
    recaptcha_token = request.json.get('recaptcha_token')
    if not verify_recaptcha(recaptcha_token, 'api_login'):
        return jsonify({"msg": "Falló la verificación de seguridad"}), 400
    
    email = request.json.get('email', None)
    password = request.json.get('password', None)
    
    if not email or not password:
        return jsonify({"msg": "Missing email or password"}), 400
    
    user = User.query.filter_by(email=email).first()
    if user and bcrypt.check_password_hash(user.password, password):
        # Si el usuario tiene 2FA habilitado, requerir código
        if user.is_2fa_enabled:
            totp_code = request.json.get('totp_code', None)
            
            if not totp_code:
                return jsonify({"msg": "Se requiere código 2FA", "requires_2fa": True}), 400
            
            totp = pyotp.TOTP(user.totp_secret)
            if not totp.verify(totp_code):
                return jsonify({"msg": "Código 2FA incorrecto"}), 401
        
        # Si no tiene 2FA o ya pasó la verificación, proceder con JWT
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token), 200
    
    return jsonify({"msg": "Credenciales incorrectas"}), 401

@app.route('/api/verify_2fa', methods=['POST'])
def api_verify_2fa():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400
    
    # Verificar reCAPTCHA
    recaptcha_token = request.json.get('recaptcha_token')
    if not verify_recaptcha(recaptcha_token, 'api_verify_2fa'):
        return jsonify({"msg": "Falló la verificación de seguridad"}), 400
    
    email = request.json.get('email', None)
    totp_code = request.json.get('totp_code', None)
    
    if not email or not totp_code:
        return jsonify({"msg": "Missing email or TOTP code"}), 400
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"msg": "Usuario no encontrado"}), 404
    
    totp = pyotp.TOTP(user.totp_secret)
    if totp.verify(totp_code):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token), 200
    
    return jsonify({"msg": "Código 2FA incorrecto"}), 401

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username, is_2fa_enabled=current_user.is_2fa_enabled)

# Nueva ruta protegida con JWT
@app.route('/api/protected')
@jwt_required()
def protected():
    # Acceder al identity del token JWT
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({"msg": "Usuario no encontrado"}), 404
    
    return jsonify(
        id=user.id,
        username=user.username,
        email=user.email,
        is_2fa_enabled=user.is_2fa_enabled
    ), 200

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión.', 'info')
    return redirect(url_for('login'))

# Manejador de errores para JWT
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({
        'status': 401,
        'sub_status': 42,
        'msg': 'El token ha expirado'
    }), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({
        'status': 401,
        'sub_status': 43,
        'msg': 'Token inválido'
    }), 401

# Configurar logging para desarrollo
if app.debug:
    import logging
    logging.basicConfig(level=logging.INFO)
    app.logger.setLevel(logging.INFO)

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=False, port=5001)