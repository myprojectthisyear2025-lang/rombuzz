// server/socket.js
let io = null;

function initSocket(serverIO) {
  io = serverIO;
}

function getIO() {
  if (!io) {
    throw new Error("Socket.io instance not initialized");
  }
  return io;
}

module.exports = { io, initSocket, getIO };
