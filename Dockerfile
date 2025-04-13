# Usar una imagen base de Python 3.9
FROM python:3.12.3-slim

# Establecer directorio de trabajo
WORKDIR /app

# Instalar dependencias del sistema para que funcionen bcrypt y otras bibliotecas
RUN apt-get update && apt-get install -y \
    gcc \
    libffi-dev \
    python3-dev \
    build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copiar archivos de requisitos primero para aprovechar la caché de capas de Docker
COPY requirements.txt .

# Instalar las dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el resto del código de la aplicación
COPY . .

# Configurar variables de entorno
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

# Exponer el puerto en el que se ejecutará la aplicación
EXPOSE 5001

# Ejecutar el comando para iniciar la aplicación
CMD ["gunicorn", "--bind", "0.0.0.0:5001", "app:app"]