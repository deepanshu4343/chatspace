
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");
const fs = require("fs");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.static(__dirname));

// Agar teri HTML file ka naam index.html hai,
// toh chat.html ko index.html kar dena.
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "chat.html"));
});

const historyFile = path.join(__dirname, "messages.json");
let messages = [];

try {
  if (fs.existsSync(historyFile)) {
    const saved = JSON.parse(
      fs.readFileSync(historyFile, "utf8")
    );
    if (Array.isArray(saved)) messages = saved.slice(-200);
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

function sendOnlineUsers() {
  io.emit(
    "online users",
    Array.from(onlineUsers.entries()).map(([id, username]) => ({
      id,
      username
    }))
  );
}

io.on("connection", (socket) => {
  console.log("Connected:", socket.id);

  socket.emit("chat history", messages);

  socket.on("set username", (name) => {
    if (typeof name !== "string") return;

    const username = name.trim().slice(0, 25);
    if (!username) return;

    onlineUsers.set(socket.id, username);
    sendOnlineUsers();
  });

  // Public community chat
  socket.on("chat message", (data) => {
    if (!data || typeof data.text !== "string") return;

    const username = onlineUsers.get(socket.id);
    const text = data.text.trim().slice(0, 1000);

    if (!username || !text) return;

    const message = {
      username,
      text,
      time: new Date().toLocaleTimeString("en-IN", {
        hour: "2-digit",
        minute: "2-digit"
      })
    };

    messages.push(message);

    if (messages.length > 200) {
      messages = messages.slice(-200);
    }

    saveMessages();
    io.emit("chat message", message);
  });

  // Private message to an online user
  socket.on("private message", (data) => {
    if (!data || typeof data.to !== "string") return;
    if (typeof data.text !== "string") return;

    const username = onlineUsers.get(socket.id);
    const recipient = data.to;
    const text = data.text.trim().slice(0, 1000);

    if (!username || !text) return;
    if (recipient === socket.id) return;
    if (!onlineUsers.has(recipient)) return;

    io.to(recipient).emit("private message", {
      from: username,
      text,
      time: new Date().toLocaleTimeString("en-IN", {
        hour: "2-digit",
        minute: "2-digit"
      })
    });
  });

  socket.on("disconnect", () => {
    onlineUsers.delete(socket.id);
    sendOnlineUsers();
    console.log("Disconnected:", socket.id);
  });
});

server.listen(3000, () => {
  console.log("Chat server running at http://localhost:3000");
});
