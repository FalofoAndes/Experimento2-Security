# Usa la imagen oficial de Python como base
FROM python:3.11

# Establece la variable de entorno para evitar que Python escriba archivos .pyc
ENV PYTHONDONTWRITEBYTECODE 1
# Establece la variable de entorno para que el stdout y el stderr se envíen al terminal
ENV PYTHONUNBUFFERED 1

# Establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copia los archivos de requisitos a la imagen
COPY requirements.txt /app/

# Instala las dependencias del proyecto
RUN pip install --no-cache-dir -r requirements.txt

# Copia el resto del código de tu proyecto a la imagen
COPY . /app/

# Exponer el puerto en el que se ejecutará tu aplicación
EXPOSE 8000

# Comando para ejecutar tu aplicación 
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:8000"]
