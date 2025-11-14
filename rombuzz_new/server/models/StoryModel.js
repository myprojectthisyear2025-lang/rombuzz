/**
 * ============================================================
 * 📁 File: models/StoryModel.js
 * 💾 Purpose: Mongoose schema for 24-hour user stories
 * ============================================================
 */
const mongoose = require("mongoose");

const storySchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true, index: true },
    userId: { type: String, required: true, index: true },
    mediaUrl: { type: String, required: true },
    text: { type: String, default: "" },
    type: { type: String, enum: ["image", "video"], default: "image" },
    createdAt: { type: Date, default: Date.now },
    expiresAt: { type: Date, required: true },
    isActive: { type: Boolean, default: true },
    views: { type: [String], default: [] },
  },
  { timestamps: true }
);

storySchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // Auto-remove after expiry

module.exports =
  mongoose.models.StoryModel || mongoose.model("StoryModel", storySchema);
