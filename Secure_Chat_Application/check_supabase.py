"""
check_supabase.py — Diagnostic tool to test Supabase connection status.
Tests both the Supabase API / Project Endpoint and direct PostgreSQL connection.
"""
import os
import sys

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, BASE_DIR)

from config import config

print("=" * 65)
print(" SUPABASE CONNECTION STATUS CHECK")
print("=" * 65)

# 1. Test Supabase API Connection
print(f"[*] Supabase Project URL : {config.SUPABASE_URL or '[NOT SET]'}")
print(f"[*] Supabase Key         : {'[CONFIGURED]' if config.SUPABASE_ANON_KEY else '[NOT SET]'}")

api_connected = False
if config.SUPABASE_URL and config.SUPABASE_ANON_KEY:
    try:
        from supabase import create_client
        client = create_client(config.SUPABASE_URL, config.SUPABASE_ANON_KEY)
        # Attempt lightweight probe
        print("[*] Probing Supabase Cloud Project API...")
        try:
            res = client.from_("users").select("id").limit(1).execute()
            print("[STATUS: API] CONNECTED! 'users' table is present.")
            api_connected = True
        except Exception as api_err:
            err_str = str(api_err)
            if "PGRST205" in err_str or "schema cache" in err_str:
                print("[STATUS: API] REACHABLE & AUTHENTICATED!")
                print("  -> Project is live, but PostgreSQL tables have not been created yet.")
                print("  -> Please run database/schema_supabase.sql in your Supabase SQL Editor.")
                api_connected = True
            else:
                print(f"[STATUS: API] Response: {api_err}")
    except Exception as e:
        print(f"[STATUS: API] Failed to initialize client: {e}")

print("-" * 65)

# 2. Test Direct PostgreSQL Connection
print(f"[*] PostgreSQL Host : {config.SUPABASE_DB_HOST or '[NOT SET]'}")
print(f"[*] PostgreSQL Port : {config.SUPABASE_DB_PORT}")
print(f"[*] PostgreSQL User : {config.SUPABASE_DB_USER}")
print(f"[*] PostgreSQL Password : {'[CONFIGURED]' if config.SUPABASE_DB_PASSWORD else '[EMPTY]'}")

dsn = config.get_postgres_dsn()
if not dsn:
    print("\n[STATUS: POSTGRESQL] PENDING DATABASE PASSWORD")
    print("  -> To enable direct PostgreSQL queries, add your database password to .env:")
    print("     SUPABASE_DB_PASSWORD=your_database_password")
    print(f"     or set DATABASE_URL=postgresql://postgres:[PASSWORD]@{config.SUPABASE_DB_HOST}:5432/postgres?sslmode=require")
    print("\n[CURRENT MODE] Running on local SQLite fallback mode with full E2EE.")
else:
    try:
        import psycopg2
        print("[*] Connecting to Supabase PostgreSQL via psycopg2...")
        conn = psycopg2.connect(dsn, connect_timeout=10)
        cur = conn.cursor()
        cur.execute("SELECT version();")
        v = cur.fetchone()[0]
        print("[STATUS: POSTGRESQL] CONNECTED SUCCESSFULLY!")
        print(f"  -> {v[:60]}...")
        cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public'")
        tables = [r[0] for r in cur.fetchall()]
        print(f"  -> Public tables: {tables}")
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[STATUS: POSTGRESQL] Connection error: {e}")

print("=" * 65)
