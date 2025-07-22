import csv
import psycopg2
import bcrypt

# Database connection details
DB_NAME = "Bank_Server"
DB_USER = "postgres"
DB_PASSWORD = "#Djs240240"
DB_HOST = "localhost"
DB_PORT = "5432"

# Connect to PostgreSQL
conn = psycopg2.connect(
    dbname=DB_NAME,
    user=DB_USER,
    password=DB_PASSWORD,
    host=DB_HOST,
    port=DB_PORT
)
cur = conn.cursor()

# Create users table
cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role VARCHAR(50) NOT NULL
    );
""")
conn.commit()

# Function to hash passwords
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

# Read CSV and insert users into database
with open('bank_users.csv', 'r', newline='') as file:
    reader = csv.DictReader(file)
    for row in reader:
        username = row['username']
        password = hash_password(row['password'])  # Hashing password before inserting
        role = row['role']

        cur.execute(
            "INSERT INTO users (username, password, role) VALUES (%s, %s, %s) ON CONFLICT (username) DO NOTHING;",
            (username, password, role)
        )

conn.commit()
cur.close()
conn.close()

print("User data imported successfully!")
