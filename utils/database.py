# utils/database.py
import os
import psycopg2
import logging
from dotenv import load_dotenv

load_dotenv() # Ensure env vars are loaded for this utility too

logger = logging.getLogger(__name__)

def get_db_connection():
    """Establishes and returns a new database connection."""
    database_url = os.getenv('DATABASE_URL')
    if not database_url:
        logger.critical("DATABASE_URL environment variable not set in utils/database.py. Exiting.")
        raise ValueError("DATABASE_URL environment variable is required for database connection.")
    try:
        conn = psycopg2.connect(database_url)
        logger.debug("Database connection established.")
        return conn
    except Exception as e:
        logger.error(f"Failed to connect to database: {e}", exc_info=True)
        raise
