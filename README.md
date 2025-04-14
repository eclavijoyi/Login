# 🔐 Flask Auth App con 2FA y reCAPTCHA

Este proyecto es una aplicación web desarrollada con **Flask** que implementa autenticación de usuarios con:

- Inicio de sesión y registro
- Autenticación de dos factores (2FA) con TOTP (Google Authenticator)
- Protección con Google reCAPTCHA v3
- Gestión de sesiones con JWT y Flask-Login
- Protección contra abuso con Flask-Limiter
- API REST para login y autenticación
- Base de datos con SQLAlchemy (SQLite por defecto)

---

## 🚀 Tecnologías utilizadas

- Python 3.x
- Flask
- SQLAlchemy
- Flask-Login
- Flask-Bcrypt
- Flask-JWT-Extended
- Flask-WTF
- Flask-Limiter
- pyotp
- Google reCAPTCHA v3
- SQLite

---

## 📦 Instalación

```bash
git clone https://github.com/eclavijoyi/Login.git
cd Login
python3 -m venv venv
pip install -r requirements.txt
```

```Docker
Recuerda tener el servidor de Traefik en su vps instalado
git clone https://github.com/eclavijoyi/Login.git
cd Login
docker-compose up -d
```

---

## 🔑 Variables de entorno

Crea un archivo `.env` en la raíz del proyecto con el siguiente contenido:

```env
SECRET_KEY=tu_clave_secreta_flask
JWT_SECRET_KEY=tu_clave_secreta_jwt
RECAPTCHA_SITE_KEY=tu_clave_recaptcha_sitio
RECAPTCHA_SECRET_KEY=tu_clave_recaptcha_servidor
RECAPTCHA_ENABLED=true
BYPASS_RECAPTCHA=false
DOMAIN_NAME=tudominio.com
IMAGE_NAME=nombre_de_tu_imagen_docker
```

---

## 🧪 Ejecutar localmente

```bash
python app.py
```

La aplicación estará disponible en [http://localhost:5001](http://localhost:5001)

---

## 🔐 Funcionalidades principales

- [x] Registro de usuarios con validación reCAPTCHA
- [x] Inicio de sesión protegido por reCAPTCHA
- [x] Habilitación y deshabilitación de 2FA con escaneo de código QR
- [x] Ruta protegida por JWT (`/api/protected`)
- [x] Inicio de sesión vía API (`/api/login`)
- [x] Límite de intentos de login con Flask-Limiter
- [x] Eliminación de cuenta desde formulario de recuperación

---

## 📄 Estructura del proyecto

```
├── app.py                # Archivo principal de la aplicación Flask
├── forms.py              # Formularios de WTForms
├── models.py             # Modelos SQLAlchemy
├── templates/            # Plantillas HTML
├── static/               # Archivos estáticos (CSS, JS, imágenes)
├── .env                  # Variables de entorno
├── requirements.txt      # Dependencias del proyecto
```

---

## 📬 API Endpoints

| Método | Ruta              | Descripción            |
| ------ | ----------------- | ---------------------- |
| POST   | `/api/login`      | Login por API          |
| POST   | `/api/verify_2fa` | Verificación 2FA       |
| GET    | `/api/protected`  | Ruta protegida con JWT |

---

## 🔐 Seguridad

- Protección con reCAPTCHA en todos los formularios críticos
- 2FA con TOTP compatible con Google Authenticator
- Tokens JWT con expiración automática
- Manejo robusto de sesiones, errores y validaciones

---

## 👨‍💻 Autor

Desarrollado por eclavijoyi.

---

## 🛡️ Licencia

Este proyecto está bajo la licencia MIT. Puedes usarlo, modificarlo y distribuirlo libremente con la debida atribución.
