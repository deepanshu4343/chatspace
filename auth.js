
require("dotenv").config();

const express = require("express");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const session = require("express-session");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const path = require("path");

const router = express.Router();
const db = new Database(path.join(__dirname, "users.db"));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )
`);

const columns = db.prepare("PRAGMA table_info(users)").all();
const hasColumn = (name) => columns.some((column) => column.name === name);

if (!hasColumn("email")) {
  db.exec("ALTER TABLE users ADD COLUMN email TEXT COLLATE NOCASE");
}
if (!hasColumn("email_verified")) {
  db.exec("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0");
}
if (!hasColumn("verification_hash")) {
  db.exec("ALTER TABLE users ADD COLUMN verification_hash TEXT");
}
if (!hasColumn("verification_expires")) {
  db.exec("ALTER TABLE users ADD COLUMN verification_expires INTEGER");
}
if (!hasColumn("reset_hash")) {
  db.exec("ALTER TABLE users ADD COLUMN reset_hash TEXT");
}
if (!hasColumn("reset_expires")) {
  db.exec("ALTER TABLE users ADD COLUMN reset_expires INTEGER");
}

db.exec("CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users(email) WHERE email IS NOT NULL");

const sessionMiddleware = session({
  name: "chat.sid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: false,
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
});

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "smtp.gmail.com",
  port: Number(process.env.SMTP_PORT || 465),
  secure: Number(process.env.SMTP_PORT || 465) === 465,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

function makeToken() {
  return crypto.randomBytes(32).toString("hex");
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function baseUrl() {
  return (process.env.BASE_URL || "http://localhost:3000").replace(/\/$/, "");
}

function sendEmail(to, subject, text) {
  return transporter.sendMail({
    from: process.env.SMTP_USER,
    to,
    subject,
    text
  });
}

function createLoginSession(req, user) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((error) => {
      if (error) return reject(error);

      req.session.user = {
        id: user.id,
        username: user.username
      };

      req.session.save((saveError) => {
        if (saveError) return reject(saveError);
        resolve();
      });
    });
  });
}

router.get("/me", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: "Please log in." });
  }

  res.json({ user: req.session.user });
});

router.post("/signup", async (req, res) => {
  try {
    const username = typeof req.body.username === "string"
      ? req.body.username.trim()
      : "";
    const email = typeof req.body.email === "string"
      ? req.body.email.trim().toLowerCase()
      : "";
    const password = typeof req.body.password === "string"
      ? req.body.password
      : "";

    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
      return res.status(400).json({
        error: "Username 3–20 characters ka ho: letters, numbers, underscore."
      });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
      return res.status(400).json({ error: "Valid email address enter karo." });
    }

    if (password.length < 8 || password.length > 72) {
      return res.status(400).json({
        error: "Password 8 se 72 characters ka hona chahiye."
      });
    }

    const existing = db.prepare(
      "SELECT id FROM users WHERE username = ? OR email = ?"
    ).get(username, email);

    if (existing) {
      return res.status(409).json({
        error: "Username ya email pehle se registered hai."
      });
    }

    const token = makeToken();
    const passwordHash = await bcrypt.hash(password, 12);

    db.prepare(`
      INSERT INTO users
        (username, email, password_hash, email_verified,
         verification_hash, verification_expires)
      VALUES (?, ?, ?, 0, ?, ?)
    `).run(
      username,
      email,
      passwordHash,
      hashToken(token),
      Date.now() + 30 * 60 * 1000
    );

    const link = `${baseUrl()}/?verify=${token}`;

    try {
      await sendEmail(
        email,
        "Verify your chat account",
        `Hi ${username},\n\nVerify your email using this link (valid for 30 minutes):\n${link}\n\nIf you did not create this account, ignore this email.`
      );
    } catch (mailError) {
      db.prepare("DELETE FROM users WHERE email = ? AND email_verified = 0")
        .run(email);
      console.error("Verification email error:", mailError.message);
      return res.status(500).json({
        error: "Verification email nahi bhej paaye. SMTP settings check karo."
      });
    }

    res.status(201).json({
      message: "Account bana diya! Email mein verification link check karo."
    });
  } catch (error) {
    console.error("Signup error:", error.message);
    res.status(500).json({ error: "Signup fail hua. Dobara try karo." });
  }
});

router.get("/verify", (req, res) => {
  const token = typeof req.query.token === "string" ? req.query.token : "";
  if (!token) {
    return res.status(400).json({ error: "Verification token missing hai." });
  }

  const user = db.prepare(`
    SELECT id FROM users
    WHERE verification_hash = ? AND verification_expires > ?
  `).get(hashToken(token), Date.now());

  if (!user) {
    return res.status(400).json({
      error: "Verification link invalid ya expire ho gaya. Naya account verification link maango."
    });
  }

  db.prepare(`
    UPDATE users
    SET email_verified = 1,
        verification_hash = NULL,
        verification_expires = NULL
    WHERE id = ?
  `).run(user.id);

  res.json({ message: "Email verified! Ab login kar sakte ho." });
});

router.post("/login", async (req, res) => {
  try {
    const username = typeof req.body.username === "string"
      ? req.body.username.trim()
      : "";
    const password = typeof req.body.password === "string"
      ? req.body.password
      : "";

    const user = db.prepare(`
      SELECT id, username, password_hash, email_verified
      FROM users WHERE username = ?
    `).get(username);

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Username ya password galat hai." });
    }

    if (!user.email_verified) {
      return res.status(403).json({
        error: "Pehle apne email ka verification link open karo."
      });
    }

    await createLoginSession(req, user);
    res.json({ user: { id: user.id, username: user.username } });
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({ error: "Login fail hua. Dobara try karo." });
  }
});

router.post("/forgot-password", async (req, res) => {
  const email = typeof req.body.email === "string"
    ? req.body.email.trim().toLowerCase()
    : "";

  // Same response whether the email exists or not.
  const response = {
    message: "Agar is email par verified account hai, reset link bhej diya jayega."
  };

  try {
    const user = db.prepare(`
      SELECT id, username, email FROM users
      WHERE email = ? AND email_verified = 1
    `).get(email);

    if (user) {
      const token = makeToken();

      db.prepare(`
        UPDATE users SET reset_hash = ?, reset_expires = ? WHERE id = ?
      `).run(hashToken(token), Date.now() + 15 * 60 * 1000, user.id);

      const link = `${baseUrl()}/?reset=${token}`;

      try {
        await sendEmail(
          user.email,
          "Reset your chat password",
          `Hi ${user.username},\n\nReset your password using this link (valid for 15 minutes):\n${link}\n\nIf you did not request this, ignore this email.`
        );
      } catch (mailError) {
        console.error("Password reset email error:", mailError.message);
      }
    }

    res.json(response);
  } catch (error) {
    console.error("Forgot password error:", error.message);
    res.status(500).json({ error: "Request process nahi ho saki." });
  }
});

router.post("/reset-password", async (req, res) => {
  try {
    const token = typeof req.body.token === "string" ? req.body.token : "";
    const password = typeof req.body.password === "string" ? req.body.password : "";

    if (password.length < 8 || password.length > 72) {
      return res.status(400).json({
        error: "Naya password 8 se 72 characters ka hona chahiye."
      });
    }

    const user = db.prepare(`
      SELECT id FROM users
      WHERE reset_hash = ? AND reset_expires > ?
    `).get(hashToken(token), Date.now());

    if (!user) {
      return res.status(400).json({
        error: "Reset link invalid ya expire ho gaya. Naya link request karo."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    db.prepare(`
      UPDATE users
      SET password_hash = ?, reset_hash = NULL, reset_expires = NULL
      WHERE id = ?
    `).run(passwordHash, user.id);

    res.json({ message: "Password reset ho gaya! Ab naye password se login karo." });
  } catch (error) {
    console.error("Reset password error:", error.message);
    res.status(500).json({ error: "Password reset nahi ho paaya." });
  }
});

router.post("/logout", (req, res) => {
  if (!req.session) {
    return res.json({ message: "Logged out." });
  }

  req.session.destroy((error) => {
    if (error) {
      return res.status(500).json({ error: "Logout fail hua." });
    }

    res.clearCookie("chat.sid");
    res.json({ message: "Logged out." });
  });
});

function requireAuth(req, res, next) {
  if (!req.session?.user) {
    return res.status(401).json({ error: "Please log in first." });
  }
  next();
}

module.exports = { router, sessionMiddleware, requireAuth, db };
