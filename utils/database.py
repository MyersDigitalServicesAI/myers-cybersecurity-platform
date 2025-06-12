import os
from dotenv import load_dotenv # Only needed for local development
from supabase import create_client, Client

# For local development: Load environment variables from .env file
# In production (e.g., on Render), these variables will already be available
load_dotenv()

# Get Supabase credentials from environment variables
supabase_url: str = os.getenv("SUPABASE_URL")
supabase_key: str = os.getenv("SUPABASE_KEY")

# Create the Supabase client
# Ensure that these environment variables are set before this line is executed.
if not supabase_url or not supabase_key:
    raise ValueError("Supabase URL and Key must be set in environment variables.")

supabase: Client = create_client(supabase_url, supabase_key)

# Example usage (you would use this in your application logic):
# from your_module import supabase
#
# # Fetch data
# response = supabase.table("your_table_name").select("*").execute()
# data = response.data
# error = response.error
#
# if error:
#     print(f"Error fetching data: {error}")
# else:
#     print(f"Data: {data}")

# If you need the service role key for admin-level operations (e.g., bypassing RLS in a backend script):
# supabase_service_role_key: str = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
# if supabase_service_role_key:
#     supabase_admin: Client = create_client(supabase_url, supabase_service_role_key)
#     # Use supabase_admin for operations that require higher privileges
