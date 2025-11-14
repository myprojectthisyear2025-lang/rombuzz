/**
 * ============================================================
 * 📁 File: config/socket.js
 * ⚡ Purpose: Initialize and configure Socket.IO for RomBuzz
 *
 * Exports:
 *   - setupSocket(server): creates a Socket.IO instance
 *
 * Integrates with:
 *   - server/socket.js for global access via initSocket()
 *   - sockets/connection.js for actual event handlers
 *
 * Notes:
 *   - Includes full CORS whitelist for production + localhost
 *   - Logs connections and disconnections
 * ============================================================
 */

const { Server } = require("socket.io");
const { initSocket } = require("../socket");

function setupSocket(server) {
  const io = new Server(server, {
    cors: {
      origin: [
        "https://rombuzz.com",
        "https://www.rombuzz.com",
        "https://rombuzz.vercel.app",
        "http://localhost:3000",
        "http://localhost:5173",
      ],
      methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
      credentials: true,
    },
  });

  // 🧠 Store instance globally for other modules
  initSocket(io);

  // Basic connection logs
  io.on("connection", (socket) => {
    console.log(`⚡ Socket connected: ${socket.id}`);

    socket.on("disconnect", () => {
      console.log(`❌ Socket disconnected: ${socket.id}`);
    });
  });

  return io;
}

module.exports = { setupSocket };
