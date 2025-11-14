/**
 * ============================================================
 * 📁 File: models/User.js
 * 💾 Purpose: Mongoose schema for RomBuzz users
 * ============================================================
 */

const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    // ✅ Primary identity
    id: { type: String, required: true, unique: true, index: true }, // mirrors LowDB shortid
    email: { type: String, required: true, unique: true, index: true },
    firstName: { type: String, default: "" },
    lastName: { type: String, default: "" },

    // 🔐 Auth
    passwordHash: { type: String, default: "" },
    googleId: { type: String, default: "" },

    // 💫 Profile fields
    gender: { type: String, default: "" },
    dob: { type: String, default: "" },
    lookingFor: { type: String, default: "" },
    interestedIn: { type: [String], default: [] },
    preferences: { type: Object, default: {} },
    visibilityMode: { type: String, default: "public" },
    interests: { type: [String], default: [] },
    avatar: { type: String, default: "" },
    photos: { type: [String], default: [] },
    phone: { type: String, default: "" },
    voiceUrl: { type: String, default: "" },

    // 💬 Activity / status
    lastActive: { type: Date, default: Date.now },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },

    // 🔒 System flags
    isPremium: { type: Boolean, default: false },
    isVerified: { type: Boolean, default: false },
    blockedUsers: { type: [String], default: [] },
  },
  {
    timestamps: true, // auto adds createdAt + updatedAt
    minimize: true,
  }

);

// ❌ Remove the redundant manual index; we already have `index: true` on `email`
// userSchema.index({ email: 1 });

module.exports =
  mongoose.models.User || mongoose.model("User", userSchema);
