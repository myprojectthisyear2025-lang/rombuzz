/**
 * ============================================================
 * 📁 File: models/state.js
 * 💾 Purpose: Centralized in-memory state for transient runtime data
 *
 * Exports:
 *   - buzzLocks → prevents multiple simultaneous streak updates
 *   - onlineUsers → tracks users connected via sockets
 *
 * Why:
 *   - Keeps transient data separate from persistent DB (LowDB)
 *   - Prepares for future scaling (e.g., Redis or clustered memory)
 * ============================================================
 */

// 🧠 Users currently connected via sockets
const onlineUsers = {};

// 🔒 Lock set to prevent concurrent streak updates or race conditions
const buzzLocks = new Set();

module.exports = {
  onlineUsers,
  buzzLocks,
};
