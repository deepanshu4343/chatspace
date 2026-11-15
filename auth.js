
require("dotenv").config();

const express = require("express");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const session = require("express-session");
const crypto = require("crypto");
const path = require("path");
const { OAuth2Client } = require("google-auth-library");

const router = express.Router();
const db = new Database(path.join(__dirname, "users.db"));

const googleClient = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID
);

// --------------------------------------------------
// DATABASE
// --------------------------------------------------

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )
`);

const columns = db.prepare("PRAGMA table_info(users)").all();

const hasColumn = (name) =>
  columns.some((column) => column.name === name);


const migrations = [
  ["email", "TEXT COLLATE NOCASE"],
  ["email_verified", "INTEGER NOT NULL DEFAULT 0"],
  ["verification_hash", "TEXT"],
  ["verification_expires", "INTEGER"],
  ["reset_hash", "TEXT"],
  ["reset_expires", "INTEGER"],
  ["phone", "TEXT"],
  ["google_id", "TEXT"],
  ["recovery_email", "TEXT COLLATE NOCASE"],
  ["recovery_email_verified", "INTEGER NOT NULL DEFAULT 0"],
  ["recovery_verification_hash", "TEXT"],
  ["recovery_verification_expires", "INTEGER"],
  ["pending_email", "TEXT COLLATE NOCASE"],
  ["pending_email_hash", "TEXT"],
  ["pending_email_expires", "INTEGER"]
];

for (const [name, definition] of migrations) {
  if (!hasColumn(name)) {
    db.exec(`ALTER TABLE users ADD COLUMN ${name} ${definition}`);
  }
}

db.exec(`
  CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique
  ON users(email)
  WHERE email IS NOT NULL;

  CREATE UNIQUE INDEX IF NOT EXISTS users_phone_unique
  ON users(phone)
  WHERE phone IS NOT NULL;

  CREATE UNIQUE INDEX IF NOT EXISTS users_google_id_unique
  ON users(google_id)
  WHERE google_id IS NOT NULL;
  CREATE UNIQUE INDEX IF NOT EXISTS users_recovery_email_unique
ON users(recovery_email)
WHERE recovery_email IS NOT NULL;
`);

// --------------------------------------------------
// SESSION
// --------------------------------------------------

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

// --------------------------------------------------
// HELPERS
// --------------------------------------------------

function makeToken() {
  return crypto.randomBytes(32).toString("hex");
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function normalizePhone(value) {
  let phone = String(value || "").replace(/[\s\-()]/g, "");

  if (phone.startsWith("+91")) {
    phone = phone.slice(3);
  } else if (phone.startsWith("91") && phone.length === 12) {
    phone = phone.slice(2);
  }

  return /^\d{10}$/.test(phone) ? phone : "";
}

function baseUrl() {
  return (
    process.env.BASE_URL ||
    "https://chatspace-5rs3.onrender.com"
  ).replace(/\/$/, "");
}

async function sendEmail(to, subject, text) {
  if (!process.env.EMAIL59_KEY) {
    throw new Error("EMAIL59_KEY is missing from the environment");
  }

  const response = await fetch("https://email59.com/v1/send", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${process.env.EMAIL59_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      from: "chatspace",
      to,
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

// Creates an available username for a new Google account.
function generateGoogleUsername(email) {
  let base = email
    .split("@")[0]
    .replace(/[^a-zA-Z0-9_]/g, "")
    .slice(0, 14);

  if (base.length < 3) {
    base = "user";
  }

  for (let i = 0; i < 30; i++) {
    const suffix = crypto.randomInt(1000, 99999);
    const username = `${base}_${suffix}`.slice(0, 20);

    const exists = db.prepare(`
      SELECT id FROM users WHERE username = ?
    `).get(username);

    if (!exists) {
      return username;
    }
  }

  throw new Error("Could not generate a unique username");
}

// --------------------------------------------------
// CURRENT USER
// --------------------------------------------------

router.get("/me", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({
      error: "Please log in."
    });
  }

  res.json({
    user: req.session.user
  });
});

// --------------------------------------------------
// GOOGLE SIGN-IN
// POST /api/auth/google
// --------------------------------------------------

router.post("/google", async (req, res) => {
  try {
    if (!process.env.GOOGLE_CLIENT_ID) {
      console.error("GOOGLE_CLIENT_ID is missing");

      return res.status(500).json({
        error: "Google Sign-In is not configured."
      });
    }

    const credential =
      typeof req.body.credential === "string"
        ? req.body.credential
        : "";

    if (!credential) {
      return res.status(400).json({
        error: "Google credential missing."
      });
    }

    // Verify the Google ID token.
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();

    if (
      !payload ||
      !payload.sub ||
      !payload.email ||
      payload.email_verified !== true
    ) {
      return res.status(401).json({
        error: "Google account could not be verified."
      });
    }

    const googleId = payload.sub;
    const email = payload.email.trim().toLowerCase();

    // First, look for an account already linked to this Google ID.
    let user = db.prepare(`
      SELECT id, username, email, google_id
      FROM users
      WHERE google_id = ?
    `).get(googleId);

    if (!user) {
      // Check whether this email already has a ChatSpace account.
      user = db.prepare(`
        SELECT id, username, email, google_id
        FROM users
        WHERE email = ?
      `).get(email);

      if (user) {
        // Do not link an email already connected to another Google account.
        if (user.google_id && user.google_id !== googleId) {
          return res.status(409).json({
            error: "This email is linked to another Google account."
          });
        }

        // Link the verified Google account to the existing ChatSpace account.
        db.prepare(`
          UPDATE users
          SET google_id = ?,
              email_verified = 1
          WHERE id = ?
        `).run(googleId, user.id);

      } else {
        // Create a new Google-only ChatSpace account.
        const username = generateGoogleUsername(email);

        // This random password is never shown to or requested from the user.
        const randomPassword = crypto.randomBytes(32).toString("hex");
        const passwordHash = await bcrypt.hash(randomPassword, 12);

        const result = db.prepare(`
          INSERT INTO users (
            username,
            email,
            password_hash,
            email_verified,
            google_id
          )
          VALUES (?, ?, ?, 1, ?)
        `).run(
          username,
          email,
          passwordHash,
          googleId
        );

        user = {
          id: Number(result.lastInsertRowid),
          username,
          email,
          google_id: googleId
        };
      }
    }

    await createLoginSession(req, user);

    return res.json({
      message: "Google Sign-In successful.",
      user: {
        id: user.id,
        username: user.username
      }
    });

  } catch (error) {
    console.error("Google Sign-In error:", error.message);

    return res.status(401).json({
      error: "Google Sign-In failed. Please try again."
    });
  }
});

// --------------------------------------------------
// SIGNUP
// --------------------------------------------------

router.post("/signup", async (req, res) => {
  try {
    const username = typeof req.body.username === "string"
      ? req.body.username.trim()
      : "";

    const email = typeof req.body.email === "string"
      ? req.body.email.trim().toLowerCase()
      : "";

    const phone = normalizePhone(req.body.phone);

    const password = typeof req.body.password === "string"
      ? req.body.password
      : "";

    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
      return res.status(400).json({
        error: "Username 3-20 characters ka hona chahiye."
      });
    }

    if (
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      email.length > 254
    ) {
      return res.status(400).json({
        error: "Valid email address enter karo."
      });
    }

    if (req.body.phone && !phone) {
      return res.status(400).json({
        error: "Valid 10-digit Indian mobile number enter karo."
      });
    }

    if (password.length < 8 || password.length > 72) {
      return res.status(400).json({
        error: "Password 8 se 72 characters ka hona chahiye."
      });
    }

    const existing = db.prepare(`
      SELECT id FROM users
      WHERE username = ? OR email = ? OR phone = ?
    `).get(username, email, phone || null);

    if (existing) {
      return res.status(409).json({
        error: "Username, email ya mobile number already registered hai."
      });
    }

    const token = makeToken();
    const passwordHash = await bcrypt.hash(password, 12);

    db.prepare(`
      INSERT INTO users (
        username,
        email,
        phone,
        password_hash,
        email_verified,
        verification_hash,
        verification_expires
      )
      VALUES (?, ?, ?, ?, 0, ?, ?)
    `).run(
      username,
      email,
      phone || null,
      passwordHash,
      hashToken(token),
      Date.now() + 30 * 60 * 1000
    );

    const link =
      `${baseUrl()}/api/auth/verify?token=${encodeURIComponent(token)}`;

    try {
      await sendEmail(
        email,
        "Verify your ChatSpace account",
        `Hi ${username},

Verify your email using this link (valid for 30 minutes):

${link}

If you did not create this account, ignore this email.`
      );

    } catch (mailError) {
      db.prepare(`
        DELETE FROM users
        WHERE email = ? AND email_verified = 0
      `).run(email);

      console.error("Verification email error:", mailError.message);

      return res.status(500).json({
        error: "Verification email nahi bhej paaye. Email address check karo."
      });
    }

    res.status(201).json({
      message: "Account bana diya! Email mein verification link check karo."
    });

  } catch (error) {
    console.error("Signup error:", error.message);

    res.status(500).json({
      error: "Signup fail hua. Dobara try karo."
    });
  }
});

// --------------------------------------------------
// EMAIL VERIFICATION
// --------------------------------------------------

router.get("/verify", (req, res) => {
  const token = typeof req.query.token === "string"
    ? req.query.token
    : "";

  if (!token) {
    return res.status(400).json({
      error: "Verification token missing hai."
    });
  }

  const user = db.prepare(`
    SELECT id FROM users
    WHERE verification_hash = ? AND verification_expires > ?
  `).get(hashToken(token), Date.now());

  if (!user) {
    return res.status(400).json({
      error: "Verification link invalid ya expire ho gaya."
    });
  }

  db.prepare(`
    UPDATE users
    SET email_verified = 1,
        verification_hash = NULL,
        verification_expires = NULL
    WHERE id = ?
  `).run(user.id);

  res.json({
    message: "Email verified! Ab login kar sakte ho."
  });
});

// --------------------------------------------------
// NORMAL LOGIN
// Username, email or mobile + ChatSpace password
// --------------------------------------------------

router.post("/login", async (req, res) => {
  try {
    const identifier = typeof req.body.identifier === "string"
      ? req.body.identifier.trim()
      : typeof req.body.username === "string"
        ? req.body.username.trim()
        : "";

    const password = typeof req.body.password === "string"
      ? req.body.password
      : "";

    if (!identifier || !password) {
      return res.status(400).json({
        error: "Username, email ya mobile number aur password enter karo."
      });
    }

    const email = identifier.toLowerCase();
    const phone = normalizePhone(identifier);

    const user = db.prepare(`
      SELECT id, username, password_hash, email_verified
      FROM users
      WHERE username = ? OR email = ? OR phone = ?
    `).get(identifier, email, phone || null);

    if (!user) {
      return res.status(401).json({
        error: "Login details ya password galat hain."
      });
    }

    const passwordMatches = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordMatches) {
      return res.status(401).json({
        error: "Login details ya password galat hain."
      });
    }

    await createLoginSession(req, user);

    res.json({
      user: {
        id: user.id,
        username: user.username
      }
    });

  } catch (error) {
    console.error("Login error:", error.message);

    res.status(500).json({
      error: "Login fail hua. Dobara try karo."
    });
  }
});

// --------------------------------------------------
// FORGOT PASSWORD
// --------------------------------------------------

router.post("/forgot-password", async (req, res) => {
  const email = typeof req.body.email === "string"
    ? req.body.email.trim().toLowerCase()
    : "";

  const response = {
    message: "Agar is email par verified account hai, reset link bhej diya jayega."
  };

  try {
    const user = db.prepare(`
      SELECT id, username, email
      FROM users
      WHERE email = ? AND email_verified = 1
    `).get(email);

    if (user) {
      const token = makeToken();

      db.prepare(`
        UPDATE users
        SET reset_hash = ?, reset_expires = ?
        WHERE id = ?
      `).run(
        hashToken(token),
        Date.now() + 15 * 60 * 1000,
        user.id
      );

      const link = `${baseUrl()}/?reset=${token}`;

      try {
        await sendEmail(
          user.email,
          "Reset your ChatSpace password",
          `Hi ${user.username},

Reset your password using this link (valid for 15 minutes):

${link}

If you did not request this, ignore this email.`
        );

      } catch (mailError) {
        console.error("Password reset email error:", mailError.message);
      }
    }

    res.json(response);

  } catch (error) {
    console.error("Forgot password error:", error.message);

    res.status(500).json({
      error: "Request process nahi ho saki."
    });
  }
});

// --------------------------------------------------
// RESET PASSWORD
// --------------------------------------------------

router.post("/reset-password", async (req, res) => {
  try {
    const token = typeof req.body.token === "string"
      ? req.body.token
      : "";

    const password = typeof req.body.password === "string"
      ? req.body.password
      : "";

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
        error: "Reset link invalid ya expire ho gaya."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    db.prepare(`
      UPDATE users
      SET password_hash = ?,
          reset_hash = NULL,
          reset_expires = NULL
      WHERE id = ?
    `).run(passwordHash, user.id);

    res.json({
      message: "Password reset ho gaya! Ab naye password se login karo."
    });

  } catch (error) {
    console.error("Reset password error:", error.message);

    res.status(500).json({
      error: "Password reset nahi ho paaya."
    });
  }
});

// --------------------------------------------------
// LOGOUT
// --------------------------------------------------

router.post("/logout", (req, res) => {
  if (!req.session) {
    return res.json({
      message: "Logged out."
    });
  }

  req.session.destroy((error) => {
    if (error) {
      return res.status(500).json({
        error: "Logout fail hua."
      });
    }

    res.clearCookie("chat.sid");

    res.json({
      message: "Logged out."
    });
  });
});

// --------------------------------------------------
// AUTHENTICATION MIDDLEWARE
// --------------------------------------------------

function requireAuth(req, res, next) {
  if (!req.session?.user) {
    return res.status(401).json({
      error: "Please log in first."
    });
  }

  next();
}

// --------------------------------------------------
// EXPORTS
// --------------------------------------------------


function validEmail(email) {
  return (
    typeof email === "string" &&
    email.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  );
}

// GET /api/auth/settings
router.get("/settings", requireAuth, (req, res) => {
  const user = db.prepare(`
    SELECT id, username, email, email_verified, phone,
           recovery_email, recovery_email_verified, created_at
    FROM users
    WHERE id = ?
  `).get(req.session.user.id);

  if (!user) {
    return res.status(404).json({ error: "Account not found." });
  }

  res.json({ user });
});

// POST /api/auth/change-username
router.post("/change-username", requireAuth, (req, res) => {
  const username = typeof req.body.username === "string"
    ? req.body.username.trim()
    : "";

  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
    return res.status(400).json({
      error: "Username must be 3-20 characters and use only letters, numbers or underscores."
    });
  }

  const existing = db.prepare(`
    SELECT id FROM users
    WHERE username = ? AND id != ?
  `).get(username, req.session.user.id);

  if (existing) {
    return res.status(409).json({
      error: "That username is already taken."
    });
  }

  db.prepare(`
    UPDATE users SET username = ? WHERE id = ?
  `).run(username, req.session.user.id);

  req.session.user.username = username;

  req.session.save((error) => {
    if (error) {
      console.error("Username session update error:", error.message);
      return res.status(500).json({ error: "Could not update session." });
    }

    res.json({
      message: "Username updated successfully.",
      username
    });
  });
});

// POST /api/auth/change-email
// The new email only becomes active after verification.

router.post("/change-email", requireAuth, async (req, res) => {
  const email = typeof req.body.email === "string"
    ? req.body.email.trim().toLowerCase()
    : "";

  if (!validEmail(email)) {
    return res.status(400).json({ error: "Enter a valid email address." });
  }

  const userId = req.session.user.id;

  const user = db.prepare(`
    SELECT email FROM users WHERE id = ?
  `).get(userId);

  if (!user) {
    return res.status(404).json({ error: "Account not found." });
  }

  if (email === user.email) {
    return res.status(400).json({
      error: "This is already your current email."
    });
  }

  const existing = db.prepare(`
    SELECT id FROM users
    WHERE (email = ? OR recovery_email = ?) AND id != ?
  `).get(email, email, userId);

  if (existing) {
    return res.status(409).json({
      error: "This email is already associated with another account."
    });
  }
  const token = makeToken();

  db.prepare(`
    UPDATE users
    SET pending_email = ?,
        pending_email_hash = ?,
        pending_email_expires = ?
    WHERE id = ?
  `).run(
    email,
    hashToken(token),
    Date.now() + 30 * 60 * 1000,
    userId
  );

  try {
    const link =
      `${baseUrl()}/api/auth/verify-change-email?token=${encodeURIComponent(token)}`;

    await sendEmail(
      email,
      "Verify your new ChatSpace email",
      `You requested to change your ChatSpace email.

Verify the new address using this link (valid for 30 minutes):

${link}

If you did not request this change, ignore this email.`
    );

    res.json({
      message: "Verification link sent to your new email address."
    });
  } catch (error) {
    db.prepare(`
      UPDATE users
      SET pending_email = NULL,
          pending_email_hash = NULL,
          pending_email_expires = NULL
      WHERE id = ?
    `).run(userId);

    console.error("Change email error:", error.message);
    res.status(500).json({
      error: "Could not send the verification email."
    });
  }
});

// GET /api/auth/verify-change-email
router.get("/verify-change-email", (req, res) => {
  const token = typeof req.query.token === "string"
    ? req.query.token
    : "";

  const user = db.prepare(`
    SELECT id, pending_email
    FROM users
    WHERE pending_email_hash = ?
      AND pending_email_expires > ?
  `).get(hashToken(token), Date.now());

  if (!user) {
    return res.status(400).send(
      "This email verification link is invalid or expired."
    );
  }

  const conflict = db.prepare(`
    SELECT id FROM users
    WHERE (email = ? OR recovery_email = ?) AND id != ?
  `).get(user.pending_email, user.pending_email, user.id);

  if (conflict) {
    return res.status(409).send(
      "This email is already associated with another account. Please contact support."
    );
  }

  db.prepare(`
    UPDATE users
    SET email = pending_email,
        email_verified = 1,
        pending_email = NULL,
        pending_email_hash = NULL,
        pending_email_expires = NULL
    WHERE id = ?
  `).run(user.id);

  res.send("Your ChatSpace email has been updated and verified. You can return to ChatSpace.");
});

// POST /api/auth/add-recovery-email
router.post("/add-recovery-email", requireAuth, async (req, res) => {
  const email = typeof req.body.email === "string"
    ? req.body.email.trim().toLowerCase()
    : "";

  if (!validEmail(email)) {
    return res.status(400).json({ error: "Enter a valid recovery email." });
  }

  const userId = req.session.user.id;

  const existing = db.prepare(`
    SELECT id FROM users
    WHERE (email = ? OR recovery_email = ?) AND id != ?
  `).get(email, email, userId);

  if (existing) {
    return res.status(409).json({
      error: "This email is already associated with another account."
    });
  }

  const user = db.prepare(`
    SELECT email FROM users WHERE id = ?
  `).get(userId);

  if (!user) {
    return res.status(404).json({ error: "Account not found." });
  }

  if (email === user.email) {
    return res.status(400).json({
      error: "Recovery email must be different from your main email."
    });
  }

  const token = makeToken();

  db.prepare(`
    UPDATE users
    SET recovery_email = ?,
        recovery_email_verified = 0,
        recovery_verification_hash = ?,
        recovery_verification_expires = ?
    WHERE id = ?
  `).run(
    email,
    hashToken(token),
    Date.now() + 30 * 60 * 1000,
    userId
  );

  try {
    const link =
      `${baseUrl()}/api/auth/verify-recovery-email?token=${encodeURIComponent(token)}`;

    await sendEmail(
      email,
      "Verify your ChatSpace recovery email",
      `Verify this address as your ChatSpace recovery email using this link (valid for 30 minutes):

${link}

If you did not request this, ignore this email.`
    );

    res.json({
      message: "Recovery email verification link sent."
    });
  } catch (error) {
    db.prepare(`
      UPDATE users
      SET recovery_email = NULL,
          recovery_email_verified = 0,
          recovery_verification_hash = NULL,
          recovery_verification_expires = NULL
      WHERE id = ?
    `).run(userId);

    console.error("Recovery email error:", error.message);
    res.status(500).json({
      error: "Could not send the recovery email."
    });
  }
});

// GET /api/auth/verify-recovery-email
router.get("/verify-recovery-email", (req, res) => {
  const token = typeof req.query.token === "string"
    ? req.query.token
    : "";

  const user = db.prepare(`
    SELECT id, recovery_email
    FROM users
    WHERE recovery_verification_hash = ?
      AND recovery_verification_expires > ?
  `).get(hashToken(token), Date.now());

  if (!user) {
    return res.status(400).send(
      "This recovery email verification link is invalid or expired."
    );
  }

  const conflict = db.prepare(`
    SELECT id FROM users
    WHERE (email = ? OR recovery_email = ?) AND id != ?
  `).get(user.recovery_email, user.recovery_email, user.id);

  if (conflict) {
    return res.status(409).send(
      "This email is already associated with another account."
    );
  }

  db.prepare(`
    UPDATE users
    SET recovery_email_verified = 1,
        recovery_verification_hash = NULL,
        recovery_verification_expires = NULL
    WHERE id = ?
  `).run(user.id);

  res.send("Your ChatSpace recovery email has been verified.");
});

// POST /api/auth/change-password
router.post("/change-password", requireAuth, async (req, res) => {
  try {
    const currentPassword =
      typeof req.body.currentPassword === "string"
        ? req.body.currentPassword
        : "";

    const newPassword =
      typeof req.body.newPassword === "string"
        ? req.body.newPassword
        : "";

    if (newPassword.length < 8 || newPassword.length > 72) {
      return res.status(400).json({
        error: "New password must be 8-72 characters."
      });
    }

    const user = db.prepare(`
      SELECT password_hash FROM users WHERE id = ?
    `).get(req.session.user.id);

    if (!user) {
      return res.status(404).json({ error: "Account not found." });
    }

    const matches = await bcrypt.compare(
      currentPassword,
      user.password_hash
    );

    if (!matches) {
      return res.status(401).json({
        error: "Current password is incorrect."
      });
    }

    const passwordHash = await bcrypt.hash(newPassword, 12);

    db.prepare(`
      UPDATE users
      SET password_hash = ?,
          reset_hash = NULL,
          reset_expires = NULL
      WHERE id = ?
    `).run(passwordHash, req.session.user.id);

    res.json({ message: "Password changed successfully." });

  } catch (error) {
    console.error("Change password error:", error.message);
    res.status(500).json({
      error: "Could not change your password."
    });
  }
});

module.exports = {
  router,
  sessionMiddleware,
  requireAuth,
  db
};
