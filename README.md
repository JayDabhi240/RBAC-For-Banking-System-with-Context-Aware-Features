# Role-Based Access Control for Banking System with Context-Aware Features

A secure banking system implementing Role-Based Access Control (RBAC) with geolocation-based access control, time-based restrictions, device-based authentication, rate limiting, and database auditing.

## 🚀 Features

- Role-Based Access Control (RBAC)
- Geolocation-based access restrictions
- Time-based login constraints
- Device-based authentication (optional)
- Rate limiting to prevent DoS attacks
- Failed login attempt tracking and account lockout
- Session timeout and auto logout
- Database auditing and log generation
- Secure PostgreSQL database interactions

## 🛠️ Technologies Used

- Node.js  
- Express.js  
- PostgreSQL  
- JavaScript, HTML, CSS  

## 📦 Installation

1. Clone the repository:

2. Install dependencies:

3. Set up PostgreSQL database:
- Create the database and required tables.
- Update database credentials in `server.js` or config file.

4. Run the application:

## ⚙️ Usage

- Tellers: View & update customer balances
- Managers: Approve high-value transactions (within working hours)
- Admins: Manage users and monitor logs
- Customers: View account and loan details

Access control dynamically adapts based on:
- Location (within authorized areas)
- Working hours (9 AM to 5 PM)
- Registered devices (optional)

## 📊 Audit & Logs

- All critical events are logged into `logs.txt` and a dedicated PostgreSQL audit log table.
- Failed login attempts, balance updates, and security incidents are monitored.

## 📋 Future Enhancements

- Multi-factor authentication (MFA)
- IP-based access control for customers
- Real-time threat detection with alerts

## 📄 License

This project is for academic use. Feel free to customize for personal or educational purposes.
