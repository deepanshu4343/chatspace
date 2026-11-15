
require("dotenv").config();

const express = require("express");
const http = require("http");
const path = require("path");
const fs = require("fs");
const { Server } = require("socket.io");

const {
  router: authRouter,
  sessionMiddleware,
  requireAuth,
  db
} = require("./auth");

if (!process.env.SESSION_SECRET) {
  throw new Error("SESSION_SECRET is missing from Environment Variables");
}

const app = express();
app.set("trust proxy", 1);

app.use(express.json({ limit: "10kb" }));
app.use(sessionMiddleware);
app.use("/api/auth", authRouter);
app.use("/public", express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "auth.html"));
});

app.get("/chat", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "chat.html"));
});

const server = http.createServer(app);
const io = new Server(server);

io.engine.use(sessionMiddleware);

io.use((socket, next) => {
  const account = socket.request.session?.user;

  if (!account?.id) {
    return next(new Error("Please log in first."));
  }

  const user = db.prepare(
    "SELECT id, username FROM users WHERE id = ?"
  ).get(account.id);

  if (!user) {
    return next(new Error("Account not found."));
  }

  socket.user = user;
  next();
});

// DATABASE
db.exec(`
  CREATE TABLE IF NOT EXISTS private_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS private_messages_conversation
  ON private_messages(sender_id, recipient_id, id);

  CREATE TABLE IF NOT EXISTS message_reactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    emoji TEXT NOT NULL,
    UNIQUE(message_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS message_receipts (
    message_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    read_at INTEGER NOT NULL,
    PRIMARY KEY(message_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS pinned_messages (
    message_id INTEGER PRIMARY KEY,
    pinned_by INTEGER NOT NULL,
    pinned_at INTEGER NOT NULL
  );
`);

// Safe migrations for existing databases.
const columns = db.prepare(
  "PRAGMA table_info(private_messages)"
).all().map(column => column.name);

if (!columns.includes("edited_at")) {
  db.exec("ALTER TABLE private_messages ADD COLUMN edited_at INTEGER");
}

if (!columns.includes("deleted_at")) {
  db.exec("ALTER TABLE private_messages ADD COLUMN deleted_at INTEGER");
}

if (!columns.includes("reply_to")) {
  db.exec("ALTER TABLE private_messages ADD COLUMN reply_to INTEGER");
}

// PUBLIC CHAT HISTORY
const historyFile = path.join(__dirname, "messages.json");
let messages = [];

try {
  if (fs.existsSync(historyFile)) {
    const saved = JSON.parse(fs.readFileSync(historyFile, "utf8"));
    if (Array.isArray(saved)) messages = saved.slice(-200);
  }
} catch (error) {
  console.error("History load error:", error.message);
}

function saveMessages() {
  try {
    fs.writeFileSync(historyFile, JSON.stringify(messages, null, 2));
  } catch (error) {
    console.error("History save error:", error.message);
  }
}

const onlineUsers = new Map();

function formatTime(timestamp) {
  return new Date(timestamp).toLocaleTimeString("en-IN", {
    hour: "2-digit",
    minute: "2-digit"
  });
}

function getOnlineUsers() {
  const users = new Map();

  for (const user of onlineUsers.values()) {
    users.set(user.id, {
      id: String(user.id),
      username: user.username
    });
  }

  return Array.from(users.values());
}

function sendOnlineUsers() {
  io.emit("online users", getOnlineUsers());
}

function findUser(username) {
  if (typeof username !== "string") return null;

  const clean = username.trim().slice(0, 20);
  if (!clean) return null;

  return db.prepare(`
    SELECT id, username
    FROM users
    WHERE username = ? COLLATE NOCASE
  `).get(clean);
}

function getMessage(messageId, userId) {
  return db.prepare(`
    SELECT *
    FROM private_messages
    WHERE id = ?
    AND (sender_id = ? OR recipient_id = ?)
  `).get(messageId, userId, userId);
}

function getConversationUsers(message) {
  return [message.sender_id, message.recipient_id];
}

function emitToConversation(message, event, data) {
  for (const id of getConversationUsers(message)) {
    io.to(`user:${id}`).emit(event, data);
  }
}

function messageObject(message, currentUserId) {
  const reactions = db.prepare(`
    SELECT user_id, emoji
    FROM message_reactions
    WHERE message_id = ?
  `).all(message.id);

  const read = db.prepare(`
    SELECT 1
    FROM message_receipts
    WHERE message_id = ?
    LIMIT 1
  `).get(message.id);

  const reply = message.reply_to
    ? db.prepare(`
        SELECT id, text, sender_id
        FROM private_messages
        WHERE id = ?
      `).get(message.reply_to)
    : null;

  const sender = db.prepare(
    "SELECT username FROM users WHERE id = ?"
  ).get(message.sender_id);

  return {
    id: message.id,
    from: sender?.username || "User",
    text: message.deleted_at ? "This message was deleted." : message.text,
    time: formatTime(message.created_at),
    created_at: message.created_at,
    mine: message.sender_id === currentUserId,
    edited: Boolean(message.edited_at),
    deleted: Boolean(message.deleted_at),
    replyTo: reply ? {
      id: reply.id,
      text: reply.text,
      username: db.prepare(
        "SELECT username FROM users WHERE id = ?"
      ).get(reply.sender_id)?.username || "User"
    } : null,
    reactions,
    read: Boolean(read),
    pinned: Boolean(db.prepare(
      "SELECT 1 FROM pinned_messages WHERE message_id = ?"
    ).get(message.id))
  };
}

io.on("connection", socket => {
  const user = socket.user;
  const room = `user:${user.id}`;

  socket.join(room);
  onlineUsers.set(socket.id, user);

  console.log("Connected:", user.username);

  socket.emit("chat history", messages);
  sendOnlineUsers();

  // GENERAL CHAT
  socket.on("chat message", data => {
    if (typeof data?.text !== "string") return;

    const text = data.text.trim().slice(0, 1000);
    if (!text) return;

    const timestamp = Date.now();

    const message = {
      id: `${timestamp}-${socket.id}`,
      username: user.username,
      text,
      time: formatTime(timestamp)
    };

    messages.push(message);
    messages = messages.slice(-200);

    saveMessages();
    io.emit("chat message", message);
  });

  // PRIVATE MESSAGE
  socket.on("private message", data => {
    if (typeof data?.to !== "string" ||
        typeof data?.text !== "string") return;

    const recipient = findUser(data.to);
    const text = data.text.trim().slice(0, 1000);

    if (!recipient || recipient.id === user.id || !text) {
      socket.emit("private message error", {
        error: "Invalid recipient or message."
      });
      return;
    }

    let replyTo = null;

    if (data.replyTo != null) {
      const reply = getMessage(Number(data.replyTo), user.id);

      if (!reply ||
          !(
            (reply.sender_id === user.id &&
             reply.recipient_id === recipient.id) ||
            (reply.sender_id === recipient.id &&
             reply.recipient_id === user.id)
          )) {
        socket.emit("private message error", {
          error: "The message you are replying to is unavailable."
        });
        return;
      }

      replyTo = reply.id;
    }

    const timestamp = Date.now();

    try {
      const result = db.prepare(`
        INSERT INTO private_messages
          (sender_id, recipient_id, text, created_at, reply_to)
        VALUES (?, ?, ?, ?, ?)
      `).run(user.id, recipient.id, text, timestamp, replyTo);

      const saved = getMessage(result.lastInsertRowid, user.id);

      emitToConversation(saved, "private message", {
        ...messageObject(saved, recipient.id),
        mine: false
      });

      socket.emit("private message sent", {
        ...messageObject(saved, user.id),
        mine: true
      });

    } catch (error) {
      console.error("Private message error:", error.message);
      socket.emit("private message error", {
        error: "Could not save your message."
      });
    }
  });

  // PRIVATE HISTORY
  socket.on("get private history", data => {
    if (typeof data?.username !== "string") return;

    const other = findUser(data.username);

    if (!other || other.id === user.id) {
      socket.emit("private history", {
        username: data.username,
        messages: []
      });
      return;
    }

    const history = db.prepare(`
      SELECT *
      FROM private_messages
      WHERE
        (sender_id = ? AND recipient_id = ?)
        OR
        (sender_id = ? AND recipient_id = ?)
      ORDER BY id DESC
      LIMIT 200
    `).all(user.id, other.id, other.id, user.id).reverse();

    socket.emit("private history", {
      username: other.username,
      messages: history.map(message =>
        messageObject(message, user.id)
      )
    });
  });

  // EDIT A MESSAGE
  socket.on("edit private message", data => {
    const id = Number(data?.id);
    const text = typeof data?.text === "string"
      ? data.text.trim().slice(0, 1000)
      : "";

    if (!Number.isSafeInteger(id) || !text) return;

    const message = getMessage(id, user.id);

    if (!message ||
        message.sender_id !== user.id ||
        message.deleted_at) return;

    db.prepare(`
      UPDATE private_messages
      SET text = ?, edited_at = ?
      WHERE id = ? AND sender_id = ?
    `).run(text, Date.now(), id, user.id);

    const updated = getMessage(id, user.id);

    emitToConversation(updated, "private message updated", {
      id,
      text,
      edited: true
    });
  });

  // DELETE A MESSAGE
  socket.on("delete private message", data => {
    const id = Number(data?.id);

    if (!Number.isSafeInteger(id)) return;

    const message = getMessage(id, user.id);

    if (!message || message.sender_id !== user.id) return;

    db.prepare(`
      UPDATE private_messages
      SET text = '', deleted_at = ?
      WHERE id = ? AND sender_id = ?
    `).run(Date.now(), id, user.id);

    db.prepare(
      "DELETE FROM message_reactions WHERE message_id = ?"
    ).run(id);

    db.prepare(
      "DELETE FROM pinned_messages WHERE message_id = ?"
    ).run(id);

    emitToConversation(message, "private message deleted", { id });
  });

  // REACT TO A MESSAGE
  socket.on("react to private message", data => {
    const id = Number(data?.id);
    const emoji = data?.emoji;

    const allowed = [
      "❤️", "😂", "😮", "😢", "👍", "👎",
      "🔥", "👏", "🎉", "🙏"
    ];

    if (!Number.isSafeInteger(id) || !allowed.includes(emoji)) return;

    const message = getMessage(id, user.id);

    if (!message || message.deleted_at) return;

    const existing = db.prepare(`
      SELECT id, emoji
      FROM message_reactions
      WHERE message_id = ? AND user_id = ?
    `).get(id, user.id);

    if (existing?.emoji === emoji) {
      db.prepare(`
        DELETE FROM message_reactions
        WHERE message_id = ? AND user_id = ?
      `).run(id, user.id);
    } else {
      db.prepare(`
        INSERT INTO message_reactions (message_id, user_id, emoji)
        VALUES (?, ?, ?)
        ON CONFLICT(message_id, user_id)
        DO UPDATE SET emoji = excluded.emoji
      `).run(id, user.id, emoji);
    }

    const reactions = db.prepare(`
      SELECT user_id, emoji
      FROM message_reactions
      WHERE message_id = ?
    `).all(id);

    emitToConversation(message, "private message reactions", {
      id,
      reactions
    });
  });

  // READ RECEIPT
  socket.on("read private messages", data => {
    const other = findUser(data?.username);

    if (!other || other.id === user.id) return;

    const unreadMessages = db.prepare(`
      SELECT id
      FROM private_messages
      WHERE sender_id = ?
      AND recipient_id = ?
      AND id <= ?
    `).all(other.id, user.id, Number(data?.upToId) || 0);

    const insertReceipt = db.prepare(`
      INSERT OR IGNORE INTO message_receipts
        (message_id, user_id, read_at)
      VALUES (?, ?, ?)
    `);

    const timestamp = Date.now();

    const transaction = db.transaction(rows => {
      for (const row of rows) {
        insertReceipt.run(row.id, user.id, timestamp);
      }
    });

    transaction(unreadMessages);

    io.to(`user:${other.id}`).emit("private messages read", {
      username: user.username,
      upToId: Number(data?.upToId) || 0
    });
  });

  // PIN / UNPIN A PRIVATE MESSAGE
  socket.on("toggle pin private message", data => {
    const id = Number(data?.id);
    if (!Number.isSafeInteger(id)) return;

    const message = getMessage(id, user.id);

    if (!message || message.deleted_at) return;

    const existing = db.prepare(
      "SELECT message_id FROM pinned_messages WHERE message_id = ?"
    ).get(id);

    if (existing) {
      db.prepare(
        "DELETE FROM pinned_messages WHERE message_id = ?"
      ).run(id);
    } else {
      db.prepare(`
        INSERT INTO pinned_messages (message_id, pinned_by, pinned_at)
        VALUES (?, ?, ?)
      `).run(id, user.id, Date.now());
    }

    const pinned = !existing;

    emitToConversation(message, "private message pin changed", {
      id,
      pinned
    });
  });

  // TYPING
  socket.on("typing", data => {
    const recipient = findUser(data?.to);
    if (!recipient || recipient.id === user.id) return;

    io.to(`user:${recipient.id}`).emit("user typing", {
      username: user.username
    });
  });

  socket.on("stop typing", data => {
    const recipient = findUser(data?.to);
    if (!recipient || recipient.id === user.id) return;

    io.to(`user:${recipient.id}`).emit("user stopped typing", {
      username: user.username
    });
  });

  socket.on("disconnect", () => {
    onlineUsers.delete(socket.id);
    sendOnlineUsers();
    console.log("Disconnected:", user.username);
  });
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Chat server running on port ${PORT}`);
});
