const express = require("express");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = 3000;

// PostgreSQL Database Setup
const pool = new Pool({
  user: "postgres",
  host: "localhost",
  database: "Bank_Server",
  password: "#Djs240240", // Change if needed
  port: 5432,
});

// File upload setup
const upload = multer({ dest: "uploads/" });

// Middleware
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static("public"));
app.use(
  session({
    secret: "secret-key",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 300000 },
  })
);

app.use(passport.initialize());
app.use(passport.session());

// Session expiration
app.use((req, res, next) => {
  if (!req.session.lastActivity) {
    req.session.lastActivity = Date.now();
  } else if (Date.now() - req.session.lastActivity > 300000) {
    req.session.destroy((err) => {
      if (err) console.error("Session destruction error:", err);
      return res.redirect("/");
    });
    return;
  }
  req.session.lastActivity = Date.now();
  next();
});

app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Logging & Auditing
const logFile = "logs.txt";
function logEvent(event) {
  const logEntry = `[${new Date().toISOString()}] ${event}\n`;
  fs.appendFileSync(logFile, logEntry);
}
async function logAudit(action, username, details) {
  try {
    await pool.query(
      "INSERT INTO audit_logs (action, username, details, timestamp) VALUES ($1, $2, $3, NOW())",
      [action, username, details]
    );
  } catch (err) {
    console.error("Audit Log Error:", err);
  }
}
// Helper after good-------------------------------------------

async function isDelegatedLoanOfficer(req, res, next) {
  if (!req.isAuthenticated()) return res.redirect("/");

  const { username, role } = req.user;
  const now = new Date();

  // Check if user is a Branch Manager during delegation
  if (role === "Branch Manager") {
    const result = await pool.query(
      `SELECT * FROM delegation_history 
       WHERE branch_manager_username = $1 AND start_time <= $2 AND end_time >= $2`,
      [username, now]
    );
    if (result.rows.length > 0) {
      return res.send(
        "You are temporarily delegated. Cannot log in as Branch Manager."
      );
    }
  }

  // Check if Loan Officer has delegated access
  if (role === "Loan Officer") {
    const result = await pool.query(
      `SELECT * FROM delegation_history 
       WHERE loan_officer_username = $1 AND start_time <= $2 AND end_time >= $2`,
      [username, now]
    );
    if (result.rows.length > 0) {
      req.user.role = "Delegated Branch Manager";
    }
  }

  next();
}



const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 10,
  message: { error: "Too many requests, please try again later." },
  handler: async (req, res, next, options) => {
    const now = Date.now();

    // Print IP alert in console
    console.log(`[ALERT] Rate limit triggered by IP: ${req.ip} on ${req.originalUrl} at ${new Date(now).toISOString()}`);

    // Log audit
    await logAudit(
      "Rate Limit Triggered", 
      req.user?.username || "anonymous", 
      `IP ${req.ip} exceeded rate limit on ${req.originalUrl}`
    );

    // Send response
    res.status(options.statusCode).send(options.message);
  }
});

app.use("/api/", apiLimiter);

// Passport Auth
passport.use(
  new LocalStrategy(
    {
      usernameField: "username",
      passwordField: "password",
      passReqToCallback: true,
    },
    async (req, username, password, done) => {
      try {
        const role = req.body.role;
        const result = await pool.query(
          "SELECT * FROM users WHERE username = $1 AND role = $2",
          [username, role]
        );

        // if (result.rows.length === 0) {
        //   logEvent(`Failed login attempt - Username: ${username}`);
        //   return done(null, false, { message: "Invalid credentials" });
        // }
        if (result.rows.length === 0) {
          logEvent(`Failed login attempt - Username: ${username}`);
          await pool.query(
            "INSERT INTO failed_login (username, role) VALUES ($1, $2)",
            [username, role]
          );
          return done(null, false, { message: "Invalid credentials" });
        }

        ////////////////////////////////////////////////////////////////
        // const user = result.rows[0];
        // const passwordMatch = await bcrypt.compare(password, user.password);

        // if (!passwordMatch) {
        //   logEvent(`Failed login attempt - Username: ${username}`);
        //   await pool.query(
        //     "INSERT INTO failed_login (username, role) VALUES ($1, $2)",
        //     [username, role]
        //   );
        //   return done(null, false, { message: "Invalid credentials" });
        // }
        ////////////////////////////////////////////////

        const user = result.rows[0];

        if (!user) {
          return done(null, false, { message: "User not found" });
        }

        // Check if user is locked out
        const failedLoginResult = await pool.query(
          "SELECT * FROM failed_login WHERE username = $1",
          [username]
        );

        if (failedLoginResult.rowCount > 0) {
          const failedLogin = failedLoginResult.rows[0];
          const now = new Date();
          const lastAttempt = new Date(failedLogin.timestamp);
          const diffInHours = (now - lastAttempt) / (1000 * 60 * 60);

          // Reset if more than 24 hours passed
          if (diffInHours >= 24) {
            await pool.query(
              "UPDATE failed_login SET failed_attempts = 0, timestamp = NOW() WHERE username = $1",
              [username]
            );
          } else if (failedLogin.failed_attempts >= 3) {
            logEvent(`Locked out - Username: ${username}`);
            return done(null, false, {
              message:
                "Account locked due to too many failed login attempts. Try again later.",
            });
          }
        }

        // Password check
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
          logEvent(`Failed login attempt - Username: ${username}`);

          if (failedLoginResult.rowCount > 0) {
            // Update attempt count
            await pool.query(
              `UPDATE failed_login 
       SET failed_attempts = failed_attempts + 1, timestamp = NOW() 
       WHERE username = $1`,
              [username]
            );
          } else {
            // First failed attempt
            await pool.query(
              "INSERT INTO failed_login (username, role, failed_attempts, timestamp) VALUES ($1, $2, 1, NOW())",
              [username, role]
            );
          }

          return done(null, false, { message: "Invalid credentials" });
        }

        // Successful login
        await pool.query("DELETE FROM failed_login WHERE username = $1", [
          username,
        ]);

        logEvent(`Successful login - Username: ${username}, Role: ${role}`);
        await logAudit("Login", username, `User logged in as ${role}`);
        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  )
);

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const result = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
    done(null, result.rows[0]);
  } catch (err) {
    done(err, null);
  }
});

// Login
app.post(
  "/login",
  passport.authenticate("local", { failureRedirect: "/" }),
  (req, res) => {
    const roleRedirects = {
      Teller: "/teller-home",

      "Loan Officer": "/loan-officer-home",
      "Branch Manager": "/branch-manager-home",

      "System Administrator": "/admin-home",

      "Bank Customer": "/customer-home",
    };
    res.redirect(roleRedirects[req.user.role] || "/");
  }
);

app.get("/teller-home", (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/");
  res.sendFile(path.join(__dirname, "public", "TellerHome.html"));
});


// ---------- FETCH CUSTOMER DETAILS FOR TELLER ----------
app.get("/api/teller_customer/:account_number", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT account_number, full_name, account_type, account_balance FROM customer WHERE account_number = $1",
      [req.params.account_number]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Customer not found" });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error("Database Error:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.put("/api/customer/update-balance", async (req, res) => {
  const { account_number, account_balance } = req.body;

  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Unauthorized access" });
  }

  try {
    const result = await pool.query(
      "SELECT account_balance FROM customer WHERE account_number = $1",
      [account_number]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Customer not found" });
    }

    await pool.query(
      "UPDATE customer SET account_balance = $1 WHERE account_number = $2",
      [account_balance, account_number]
    );

    logEvent(`Balance updated for account ${account_number} to ${account_balance}`);
    await logAudit(
      "Balance Update",
      req.user.username,
      `Updated balance for account ${account_number}`
    );

    res.json({ message: "Account balance updated successfully!" });
  } catch (err) {
    console.error("Database Error:", err);
    res.status(500).json({ error: "Error updating balance" });
  }
})


// Serve Customer Home
app.get("/customer-home", (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/");
  res.sendFile(path.join(__dirname, "public", "CustomerHome.html"));
});

app.get("/branch-manager-home", isDelegatedLoanOfficer, (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/");
  if (
    req.user.role === "Branch Manager" ||
    req.user.role === "Delegated Branch Manager"
  ) {
    return res.sendFile(
      path.join(__dirname, "public", "BranchManagerHome.html")
    );
  }

  return res.redirect("/");
});

app.get("/loan-officer-home", isDelegatedLoanOfficer, (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/");

  if (req.user.role === "Loan Officer") {
    return res.sendFile(path.join(__dirname, "public", "LoanOfficerHome.html"));
  }

  if (req.user.role === "Delegated Branch Manager") {
    return res.sendFile(
      path.join(__dirname, "public", "BranchManagerHome.html")
    );
  }

  return res.redirect("/");
});

app.get("/admin-home", (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/");
  if (req.user.role !== "System Administrator") return res.redirect("/");
  res.sendFile(path.join(__dirname, "public", "AdministratorHome.html"));
});

// Get customer details
app.get("/api/customer/:username", async (req, res) => {
  try {
    const { username } = req.params;
    const result = await pool.query(
      "SELECT username, full_name, account_number, account_type, account_balance FROM customer WHERE username = $1",
      [username]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ error: "Customer not found" });
    res.json(result.rows[0]);
  } catch (error) {
    console.error("Database error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Loan application endpoint
app.post("/api/apply-loan", upload.single("document"), async (req, res) => {
  const { username, account_number, loan_amount } = req.body;
  const document = req.file ? req.file.path : null;

  if (!username || !account_number || !loan_amount || !document) {
    return res.status(400).json({ error: "Missing fields" });
  }

  try {
    await pool.query(
      "INSERT INTO loan_table (username, account_number, loan_amount, document, status) VALUES ($1, $2, $3, $4, $5)",
      [username, account_number, loan_amount, document, "Pending"]
    );

    logEvent(`Loan application submitted by ${username}`);
    await logAudit(
      "Loan Application",
      username,
      `Loan applied for amount ${loan_amount}`
    );
    res.status(200).json({ message: "Loan application successful" });
  } catch (err) {
    console.error("Error inserting loan:", err);
    res.status(500).json({ error: "Failed to apply loan" });
  }
});

// Logout
app.get("/logout", (req, res) => {
  if (req.isAuthenticated()) {
    logEvent(`User ${req.user.username} logged out`);
    logAudit("Logout", req.user.username, "User logged out");
  }
  req.logout(() => res.redirect("/"));
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

// Get loan status for a customer (without timestamp)
app.get("/api/loan-status/:username", async (req, res) => {
  try {
    const { username } = req.params;
    const result = await pool.query(
      "SELECT loan_amount, status FROM loan_table WHERE username = $1 ORDER BY id DESC",
      [username]
    );
    res.json({ loans: result.rows });
  } catch (error) {
    console.error("Loan status fetch error:", error);
    res.status(500).json({ error: "Failed to fetch loan status" });
  }
});

// Get all loan applications
app.get("/api/loan-applications", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, username, loan_amount, status, document FROM loan_table ORDER BY id DESC"
    );
    res.json({ loans: result.rows });
  } catch (error) {
    console.error("Error fetching loan applications:", error);
    res.status(500).json({ error: "Failed to fetch loan applications" });
  }
});

// Approve loan application
app.post("/api/approve-loan/:loanId", async (req, res) => {
  try {
    const { loanId } = req.params;

    // Update the status of the loan to "Approved"
    await pool.query("UPDATE loan_table SET status = $1 WHERE id = $2", [
      "Approved",
      loanId,
    ]);

    logEvent(`Loan application approved for loan ID: ${loanId}`);
    await logAudit(
      "Loan Approval",
      req.user.username,
      `Loan ID ${loanId} approved`
    );

    res.status(200).json({ message: "Loan approved successfully" });
  } catch (error) {
    console.error("Error updating loan status:", error);
    res.status(500).json({ error: "Failed to approve loan" });
  }
});

// Get all customers
app.get("/api/all-customers", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT username, full_name, account_number, account_type, account_balance FROM customer"
    );
    res.json({ customers: result.rows });
  } catch (err) {
    console.error("Error fetching customers:", err);
    res.status(500).json({ error: "Failed to fetch customers" });
  }
});

// Get all loan details
app.get("/api/all-loans", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, username, account_number, loan_amount, document, status FROM loan_table"
    );
    res.json({ loans: result.rows });
  } catch (err) {
    console.error("Error fetching loan details:", err);
    res.status(500).json({ error: "Failed to fetch loans" });
  }
});

// Get all audit logs (Admin only)
app.get("/api/audit-logs", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM audit_logs ORDER BY id DESC"
    );
    res.json({ logs: result.rows });
  } catch (error) {
    console.error("Error fetching audit logs:", error);
    res.status(500).json({ error: "Failed to fetch audit logs" });
  }
});



app.post("/api/delegate-access", async (req, res) => {
  try {
    if (!req.isAuthenticated() || req.user.role !== "Branch Manager") {
      return res.status(403).json({ message: "Unauthorized" });
    }

    const branchManagerUsername = req.user.username;
    const { toUsername, durationHours } = req.body;

    const startTime = new Date();
    const endTime = new Date(
      startTime.getTime() + durationHours * 60 * 60 * 1000
    );

    await pool.query(
      `INSERT INTO delegation_history (branch_manager_username, loan_officer_username, start_time, end_time)
       VALUES ($1, $2, $3, $4)`,
      [branchManagerUsername, toUsername, startTime, endTime]
    );

    logEvent(
      `Delegated access from ${branchManagerUsername} to ${toUsername} for ${durationHours} hour(s)`
    );
    await logAudit(
      "Delegation",
      branchManagerUsername,
      `Delegated access to ${toUsername} for ${durationHours} hours`
    );

    res.json({ message: "Access delegated successfully." });
  } catch (error) {
    console.error("Delegation error:", error);
    res.status(500).json({ message: "Delegation failed." });
  }
});
