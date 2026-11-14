
require("dotenv").config();

const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");
const fs = require("fs");

const {
  router: authRouter,
  sessionMiddleware,
  requireAuth,
  db
} = require("./auth");

const app = express();

app.set("trust proxy", 1);

app.use(express.json({ limit: "10kb" }));
app.use(sessionMiddleware);
app.use("/api/auth", authRouter);

// Serve public assets only. Do not expose server files or the database.
app.use("/public", express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "auth.html"));
});

app.get("/chat", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "chat.html"));
});

const server = http.createServer(app);

const io = new Server(server);

// Attach the existing login session to Socket.IO.
io.use((socket, next) => {
  sessionMiddleware(socket.request, {}, (error) => {
    if (error) return next(error);

    if (!socket.request.session?.user) {
      return next(new Error("Please log in first."));
    }

    next();
  });
});

// Public message history
const historyFile = path.join(__dirname, "messages.json");
let messages = [];

try {
  if (fs.existsSync(historyFile)) {
    const saved = JSON.parse(
      fs.readFileSync(historyFile, "utf8")
    );

    if (Array.isArray(saved)) {
      messages = saved.slice(-200);
    }
  }
} catch (error) {
  console.error("History load error:", error.message);
}

function saveMessages() {
  try {
    fs.writeFileSync(
      historyFile,
      JSON.stringify(messages, null, 2)
    );
  } catch (error) {
    console.error("History save error:", error.message);
  }
}

// Private messages are stored in the existing SQLite database.
db.exec(`
  CREATE TABLE IF NOT EXISTS private_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    created_at INTEGER NOT NULL
  )
`);

db.exec(`
  CREATE INDEX IF NOT EXISTS private_messages_users
  ON private_messages(sender_id, recipient_id, id)
`);

// Each socket belongs to an authenticated account.
const onlineUsers = new Map();

function getOnlineUsers() {
  const uniqueUsers = new Map();

  for (const [socketId, user] of onlineUsers.entries()) {
    if (!uniqueUsers.has(user.id)) {
      uniqueUsers.set(user.id, {
        id: socketId,
        userId: user.id,
        username: user.username
      });
    }
  }

  return Array.from(uniqueUsers.values());
}

function sendOnlineUsers() {
  io.emit("online users", getOnlineUsers());
}

function formatTime(timestamp) {
  return new Date(timestamp).toLocaleTimeString("en-IN", {
    hour: "2-digit",
    minute: "2-digit"
  });
}

io.on("connection", (socket) => {
  const account = socket.request.session.user;

  const user = {
    id: account.id,
    username: account.username
  };

  onlineUsers.set(socket.id, user);

  console.log(`${user.username} connected:`, socket.id);

  socket.emit("chat history", messages);
  sendOnlineUsers();

  // Public community chat
  socket.on("chat message", (data) => {
    if (!data || typeof data.text !== "string") return;

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

    if (messages.length > 200) {
      messages = messages.slice(-200);
    }

    saveMessages();

    io.emit("chat message", message);
  });

  // Private messaging
  socket.on("private message", (data) => {
    if (!data || typeof data.to !== "string") return;
    if (typeof data.text !== "string") return;

    const recipientSocketId = data.to;
    const text = data.text.trim().slice(0, 1000);

    if (!text || recipientSocketId === socket.id) return;

    const recipient = onlineUsers.get(recipientSocketId);

    if (!recipient) {
      socket.emit("private message error", {
        error: "This user is currently offline."
      });
      return;
    }

    const timestamp = Date.now();

    try {
      const result = db.prepare(`
        INSERT INTO private_messages
          (sender_id, recipient_id, text, created_at)
        VALUES (?, ?, ?, ?)
      `).run(
        user.id,
        recipient.id,
        text,
        timestamp
      );

      const message = {
        id: result.lastInsertRowid,
        from: user.username,
        text,
        time: formatTime(timestamp)
      };

      // Send to all active tabs/devices of the recipient.
      for (const [id, onlineUser] of onlineUsers.entries()) {
        if (onlineUser.id === recipient.id) {
          io.to(id).emit("private message", message);
        }
      }

    } catch (error) {
      console.error("Private message error:", error.message);

      socket.emit("private message error", {
        error: "Message could not be saved."
      });
    }
  });

  // Request saved private conversation history.
  socket.on("get private history", (data) => {
    if (!data || typeof data.username !== "string") return;

    const username = data.username.trim().slice(0, 20);

    if (!username) return;

    const otherUser = db.prepare(`
      SELECT id, username
      FROM users
      WHERE username = ?
    `).get(username);

    if (!otherUser || otherUser.id === user.id) {
      socket.emit("private history", {
        username,
        messages: []
      });
      return;
    }

    try {
      const history = db.prepare(`
        SELECT id, sender_id, recipient_id, text, created_at
        FROM private_messages
        WHERE
          (sender_id = ? AND recipient_id = ?)
          OR
          (sender_id = ? AND recipient_id = ?)
        ORDER BY id ASC
        LIMIT 200
      `).all(
        user.id,
        otherUser.id,
        otherUser.id,
        user.id
      );

      socket.emit("private history", {
        username: otherUser.username,
        messages: history.map((message) => ({
          id: message.id,
          from: message.sender_id === user.id
            ? user.username
            : otherUser.username,
          text: message.text,
          time: formatTime(message.created_at),
          mine: message.sender_id === user.id
        }))
      });

    } catch (error) {
      console.error("Private history error:", error.message);

      socket.emit("private history", {
        username: otherUser.username,
        messages: []
      });
    }
  });

  socket.on("disconnect", () => {
    onlineUsers.delete(socket.id);

    sendOnlineUsers();

    console.log(`${user.username} disconnected:`, socket.id);
  });
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Chat server running on port ${PORT}`);
});
