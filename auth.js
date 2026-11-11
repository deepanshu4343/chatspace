require("dotenv").config();

const express = require("express");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const session = require("express-session");
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
    secure: process.env.NODE_ENV === "production",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
});

function makeToken() {
  return crypto.randomBytes(32).toString("hex");
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function baseUrl() {
  return (process.env.BASE_URL || "https://chatspace-5rs3.onrender.com").replace(/\/$/, "");
}

async function sendEmail(to, subject, text) {
  if (!process.env.RESEND_API_KEY) {
    throw new Error("RESEND_API_KEY is missing from the environment");
  }

  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${process.env.RESEND_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      from: "ChatSpace <onboarding@resend.dev>",
      to: [to],
      subject,
      text
    })
  });

  const result = await response.json();

  if (!response.ok) {
    throw new Error(JSON.stringify(result));
  }

  return result;
}
