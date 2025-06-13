import os
import psycopg2
from psycopg2 import OperationalError
from psycopg2.pool import SimpleConnectionPool
import logging
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Global variable to hold the connection pool
db_pool = None

def init_db_pool(min_conn=1, max_conn=20): # Increased max_conn for potential higher load
    """
    Initializes the global database connection pool.
    Should be called once at application startup.
    """
    global db_pool
    if db_pool is not None:
        logger.warning("Database pool already initialized. Skipping re-initialization.")
        return

    database_url = os.getenv('DATABASE_URL')
    if not database_url:
        logger.critical("DATABASE_URL environment variable not set. Cannot initialize database pool. Exiting.")
        raise ValueError("DATABASE_URL environment variable is required for database connection.")

    try:
        db_pool = SimpleConnectionPool(min_conn, max_conn, database_url)
        logger.info(f"Database connection pool initialized with min={min_conn}, max={max_conn} connections.")
    except OperationalError as e:
        logger.critical(f"Failed to initialize database pool (OperationalError): {e}. Check DATABASE_URL and database status.", exc_info=True)
        raise
    except Exception as e:
        logger.critical(f"An unexpected error occurred during database pool initialization: {e}", exc_info=True)
        raise

def get_db_connection():
    """
    Retrieves a connection from the global database pool.
    Raises a RuntimeError if the pool is not initialized.
    """
    if db_pool is None:
        logger.critical("Database pool not initialized. Call init_db_pool() before attempting to get a connection.")
        raise RuntimeError("Database pool not initialized.")
    try:
        conn = db_pool.getconn()
        # logger.debug("Retrieved connection from pool.") # Uncomment for verbose debugging
        return conn
    except OperationalError as e:
        logger.error(f"Failed to get connection from pool (OperationalError): {e}. Pool might be exhausted or database unresponsive.", exc_info=True)
        raise
    except Exception as e:
        logger.error(f"An unexpected error occurred getting connection from pool: {e}", exc_info=True)
        raise

def return_db_connection(conn):
    """
    Returns a connection to the global database pool.
    It's crucial to call this after you're done with a connection,
    especially in a finally block to ensure it's returned even on errors.
    """
    if db_pool is None:
        logger.warning("Database pool is not initialized, cannot return connection. Connection might be leaked.")
        if conn: # Attempt to close directly if pool is gone, to prevent resource exhaustion
            try:
                conn.close()
                logger.warning("Closed a connection directly because pool was not available.")
            except Exception as e:
                logger.error(f"Error closing direct connection after pool was unavailable: {e}")
        return
    if conn:
        try:
            # Check if the connection is still open before putting it back.
            # This can happen if an error occurred that closed the connection implicitly.
            if not conn.closed:
                db_pool.putconn(conn)
                # logger.debug("Returned connection to pool.") # Uncomment for verbose debugging
            else:
                logger.warning("Attempted to return a closed connection to the pool. It will not be reused.")
        except Exception as e:
            logger.error(f"Error returning connection to pool: {e}", exc_info=True)
