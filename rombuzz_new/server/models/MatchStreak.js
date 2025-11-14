/**
 * ============================================================
 * 📁 File: models/MatchStreak.js
 * 💾 Purpose: Stores streak count between two matched users
 * ============================================================
 */
const mongoose = require("mongoose");

const matchStreakSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true, index: true },
    key: { type: String, required: true, unique: true }, // from_to pair
    from: { type: String, required: true, index: true },
    to: { type: String, required: true, index: true },
    count: { type: Number, default: 0 },
    lastBuzz: { type: Date, default: null },
    createdAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

module.exports =
  mongoose.models.MatchStreak ||
  mongoose.model("MatchStreak", matchStreakSchema);
