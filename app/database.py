# database.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from config import load_config

config = load_config()

DATABASE_URL = f"mysql+pymysql://{config['user']}:{config['password']}@{config['host']}/{config['database']}"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
