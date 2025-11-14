/**
 * ============================================================
 * 📁 File: models/ChatRoom.js
 * 💾 Purpose: Mongoose schema for chat rooms and embedded messages
 *
 * Description:
 *   Each ChatRoom document represents a conversation between two users.
 *   Messages are stored as embedded subdocuments inside `messages` array.
 *   This mirrors the previous LowDB structure exactly, enabling a clean
 *   migration without changing route logic or Socket.IO behavior.
 *
 * ============================================================
 */

const mongoose = require("mongoose");

const messageSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, index: true },   // shortid-style
    from: { type: String, required: true },
    to: { type: String, required: true },
    text: { type: String, default: "" },
    type: { type: String, enum: ["text", "media"], default: "text" },
    time: { type: Date, default: Date.now },
    edited: { type: Boolean, default: false },
    deleted: { type: Boolean, default: false },
    reactions: { type: Map, of: String, default: {} },   // { userId: "❤️" }
    hiddenFor: [{ type: String, default: [] }],
    ephemeral: {
      mode: { type: String, enum: ["none", "once"], default: "none" },
    },
  },
  { _id: false }
);

const chatRoomSchema = new mongoose.Schema(
  {
    roomId: { type: String, required: true, unique: true, index: true },
    participants: [{ type: String, required: true }],     // [a, b]
    messages: [messageSchema],
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

module.exports =
  mongoose.models.ChatRoom || mongoose.model("ChatRoom", chatRoomSchema);
