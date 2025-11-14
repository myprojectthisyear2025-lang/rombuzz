/**
 * ============================================================
 * 📁 File: models/MicroBuzzBuzz.js
 * 💾 Purpose: Temporary storage for buzz requests between users
 * ============================================================
 */
const mongoose = require("mongoose");

const microBuzzBuzzSchema = new mongoose.Schema({
  fromId: { type: String, required: true, index: true },
  toId: { type: String, required: true, index: true },
  time: { type: Date, default: Date.now },
});

module.exports =
  mongoose.models.MicroBuzzBuzz ||
  mongoose.model("MicroBuzzBuzz", microBuzzBuzzSchema);
