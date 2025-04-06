from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo

class RegisterForm(FlaskForm):
    username = StringField('Usuario', 
                          validators=[DataRequired(), 
                                      Length(min=4, max=150)])
    email = StringField('Correo Electrónico', 
                       validators=[DataRequired(), 
                                   Email()])
    password = PasswordField('Contraseña', 
                            validators=[DataRequired(), 
                                        Length(min=8)])
    confirm_password = PasswordField('Confirmar Contraseña', 
                                    validators=[DataRequired(), 
                                                EqualTo('password')])
    submit = SubmitField('Registrarse')

class LoginForm(FlaskForm):
    email = StringField('Correo Electrónico', 
                       validators=[DataRequired(), 
                                   Email()])
    password = PasswordField('Contraseña', 
                            validators=[DataRequired()])
    submit = SubmitField('Iniciar Sesión')

class ForgotPasswordForm(FlaskForm):  # Clase añadida correctamente
    email = StringField('Correo Electrónico',  # Nombre del campo actualizado
                      validators=[DataRequired(), 
                                  Email()])
    submit = SubmitField('Eliminar Cuenta y Registrar Nuevamente')