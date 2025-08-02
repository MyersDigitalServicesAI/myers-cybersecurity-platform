import os
import psycopg2
from psycopg2 import OperationalError
from psycopg2.pool import SimpleConnectionPool
import logging

# --- Module-level logger setup ---
logger = logging.getLogger(__name__)

# --- Global variable to hold the connection pool ---
db_pool = None

def init_db_pool(min_conn: int = 1, max_conn: int = 10):
    """
    Initializes the global database connection pool.
    This function should be called once at the application's startup.

    Args:
        min_conn (int): The minimum number of connections to keep open in the pool.
        max_conn (int): The maximum number of connections allowed in the pool.
    """
    global db_pool
    if db_pool is not None:
        logger.warning("Database pool already initialized. Skipping re-initialization.")
        return
        
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        logger.critical("FATAL: DATABASE_URL environment variable not set. Cannot initialize database pool.")
        raise ValueError("DATABASE_URL environment variable is required.")

    try:
        db_pool = SimpleConnectionPool(min_conn, max_conn, dsn=database_url)
        # Test connection
        conn = db_pool.getconn()
        db_pool.putconn(conn)
        logger.info(f"Database connection pool initialized successfully.")
    except OperationalError as e:
        logger.critical(f"Failed to initialize database pool (OperationalError): {e}. Check DATABASE_URL and database status.", exc_info=True)
        raise
    except Exception as e:
        logger.critical(f"An unexpected error occurred during database pool initialization: {e}", exc_info=True)
        raise

def get_db_connection():
    """
    Retrieves a connection from the database pool. This function is intended
    to be used by the db_connection_manager decorator in SecurityCore.
    """
    global db_pool
    if db_pool is None:
        logger.critical("Database pool is not initialized. Call init_db_pool() first.")
        raise RuntimeError("Database connection pool not initialized.")
    try:
        return db_pool.getconn()
    except Exception as e:
        logger.error(f"Failed to get connection from pool: {e}", exc_info=True)
        raise

def return_db_connection(conn):
    """
    Returns a connection to the database pool.
    """
    global db_pool
    if db_pool is None:
        logger.warning("Database pool is not initialized, cannot return connection.")
        return
    try:
        db_pool.putconn(conn)
    except Exception as e:
        logger.error(f"Error returning connection to pool: {e}", exc_info=True)

def close_db_pool():
    """
    Closes all connections in the database pool.
    Should be called once at application shutdown.
    """
    global db_pool
    if db_pool:
        logger.info("Closing database connection pool.")
        db_pool.closeall()
        db_pool = None # Reset pool to None
        logger.info("Database connection pool closed.")

