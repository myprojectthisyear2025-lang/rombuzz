/**
 * ============================================================
 * 📁 File: models/DailyStreak.js
 * 💾 Purpose: Tracks each user's daily login/check-in streak
 * ============================================================
 */
const mongoose = require("mongoose");

const dailyStreakSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true, index: true },
    userId: { type: String, required: true, index: true },
    count: { type: Number, default: 0 },
    lastCheckIn: { type: String, default: null }, // ISO date string (YYYY-MM-DD)
  },
  { timestamps: true }
);

module.exports =
  mongoose.models.DailyStreak || mongoose.model("DailyStreak", dailyStreakSchema);
