import csv
import psycopg2
from datetime import datetime

# Database connection settings
DB_NAME = "Bank_Server"
DB_USER = "postgres"
DB_PASSWORD = "#Djs240240"
DB_HOST = "localhost"
DB_PORT = "5432"

# Allowed account types
VALID_ACCOUNT_TYPES = {"Savings", "Regular Current", "Gold Current"}

# Connect to PostgreSQL
conn = psycopg2.connect(
    dbname=DB_NAME,
    user=DB_USER,
    password=DB_PASSWORD,
    host=DB_HOST,
    port=DB_PORT
)
cur = conn.cursor()

# Ensure Customer table exists
cur.execute("""
CREATE TABLE IF NOT EXISTS Customer (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL,
    phone_number VARCHAR(15) NOT NULL,
    address TEXT NOT NULL,
    date_of_birth VARCHAR(20),
    account_number VARCHAR(20),
    account_type VARCHAR(20) CHECK (account_type IN ('Savings', 'Regular Current', 'Gold Current')) NOT NULL,
    account_balance DECIMAL(15,2) NOT NULL,
    last_login TIMESTAMP,
    failed_login_attempts INT DEFAULT 0
);
""")
conn.commit()

# Read and insert data from CSV
with open("customers.csv", newline="", encoding="utf-8") as csvfile:
    reader = csv.reader(csvfile)
    next(reader)  # Skip header row
    
    for row in reader:
        try:
            # Extract and validate data
            user_id = int(row[0])  # user_id (not used in insert)
            username = row[1]  # username
            full_name = row[2]  # full_name
            email = row[3]  # email
            phone = str(int(float(row[4])))  # Convert phone to string to avoid scientific notation
            address = row[5]  # address
            dob=row[6]
            account_number=row[7]
            
            # ✅ **Fix: Correct index for `account_type` (Column 8)**
            account_type = row[8].strip()

            # ✅ **Fix: Correct index for `balance` (Column 9)**
            account_balance = float(row[9])

            # ✅ **Fix: Correct index for `last_login` (Column 10)**
            last_login = row[10].strip()
            if last_login:
                last_login = datetime.strptime(last_login, "%d-%m-%Y %H:%M").strftime("%Y-%m-%d %H:%M:%S")
            else:
                last_login = None

            # ✅ **Fix: Correct index for `failed_login_attempts` (Column 11)**
            failed_login_attempts = int(row[11])

            # Validate account_type
            if account_type not in VALID_ACCOUNT_TYPES:
                print(f"Skipping row due to invalid account_type: {account_type}")
                continue
            
            # Insert into database
            cur.execute("""
            INSERT INTO Customer (username, full_name, email, phone_number, address,date_of_birth,account_number, account_type, account_balance, last_login, failed_login_attempts)
            VALUES (%s,%s,%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (username) DO NOTHING;
            """, (username, full_name, email, phone, address,dob,account_number, account_type, account_balance, last_login, failed_login_attempts))
            
            conn.commit()  # Commit each row individually
            
        except Exception as e:
            print(f"Skipping row due to error: {e}")
            conn.rollback()  # Reset transaction to continue inserting next rows

# Close the connection
cur.close()
conn.close()

print("Customer data imported successfully!")
