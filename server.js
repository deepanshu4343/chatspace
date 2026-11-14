
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

// Only expose the public assets folder.
app.use("/public", express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "auth.html"));
});

app.get("/chat", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "chat.html"));
});

const server = http.createServer(app);
const io = new Server(server);

// Use the same Express session for Socket.IO.
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

// Private message database.
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
  CREATE INDEX IF NOT EXISTS private_messages_conversation
  ON private_messages(sender_id, recipient_id, id)
`);

// Public message history.
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

io.on("connection", (socket) => {
  const user = socket.user;
  const room = `user:${user.id}`;

  socket.join(room);
  onlineUsers.set(socket.id, user);

  console.log("Connected:", user.username);

  socket.emit("chat history", messages);
  sendOnlineUsers();

  // Public community chat.
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
    messages = messages.slice(-200);

    saveMessages();
    io.emit("chat message", message);
  });

  // Send a private message using the recipient's username.
  socket.on("private message", (data) => {
    if (!data || typeof data.to !== "string") return;
    if (typeof data.text !== "string") return;

    const recipient = findUser(data.to);
    const text = data.text.trim().slice(0, 1000);

    if (!recipient || recipient.id === user.id || !text) {
      socket.emit("private message error", {
        error: "Invalid recipient or message."
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

      // Send to every connected device of the recipient.
      io.to(`user:${recipient.id}`).emit("private message", {
        ...message,
        mine: false
      });

      // Confirm the saved message to the sender.
      socket.emit("private message sent", {
        ...message,
        mine: true
      });

    } catch (error) {
      console.error("Private message error:", error.message);

      socket.emit("private message error", {
        error: "Could not save your message."
      });
    }
  });

  // Load a private conversation.
  socket.on("get private history", (data) => {
    if (!data || typeof data.username !== "string") return;

    const otherUser = findUser(data.username);

    if (!otherUser || otherUser.id === user.id) {
      socket.emit("private history", {
        username: data.username,
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
        ORDER BY id DESC
        LIMIT 200
      `).all(
        user.id,
        otherUser.id,
        otherUser.id,
        user.id
      ).reverse();

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

  // Typing indicators.
  socket.on("typing", (data) => {
    const recipient = findUser(data?.to);

    if (!recipient || recipient.id === user.id) return;

    io.to(`user:${recipient.id}`).emit("user typing", {
      username: user.username
    });
  });

  socket.on("stop typing", (data) => {
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
