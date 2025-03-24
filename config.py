import os

DB_USER = "myuser"
DB_PASSWORD = "mypassword"
DB_NAME = "mydb"
DB_HOST = "db"  # This is the service name in docker-compose

SQLALCHEMY_DATABASE_URI = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:5432/{DB_NAME}"
SQLALCHEMY_TRACK_MODIFICATIONS = False
SECRET_KEY = os.urandom(24)  # For Flask sessions
