/**
 * ============================================================
 * 📁 File: models/MicroBuzzPresence.js
 * 💾 Purpose: Tracks active MicroBuzz users with selfie + coords
 * ============================================================
 */
const mongoose = require("mongoose");

const microBuzzPresenceSchema = new mongoose.Schema({
  userId: { type: String, required: true, index: true, unique: true },
  selfieUrl: { type: String, required: true },
  lat: { type: Number, required: true },
  lng: { type: Number, required: true },
  updatedAt: { type: Date, default: Date.now },
});

module.exports =
  mongoose.models.MicroBuzzPresence ||
  mongoose.model("MicroBuzzPresence", microBuzzPresenceSchema);
