/**
 * ============================================================
 * 📁 File: models/Message.js
 * 💾 Purpose: MongoDB schema for RomBuzz user messages
 * ============================================================
 */

const mongoose = require("mongoose");

const messageSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true, index: true },
  from: { type: String, required: true },
  to: { type: String, required: true },
  text: { type: String, default: "" },
  type: { type: String, enum: ["text", "photo", "video"], default: "text" },
  url: { type: String, default: null },
  ephemeral: { type: String, enum: ["keep", "once"], default: "keep" },
  createdAt: { type: Date, default: Date.now },
});

module.exports =
  mongoose.models.Message || mongoose.model("Message", messageSchema);
