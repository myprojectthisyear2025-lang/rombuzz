/**
 * ============================================================
 * 📁 File: models/Match.js
 * 💾 Purpose: Mongoose schema for user matches / buzz connections
 *
 * Description:
 *   Stores pairwise match relationships between users.
 *   Mirrors LowDB structure and supports array-based queries.
 * ============================================================
 */

const mongoose = require("mongoose");

const matchSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true, index: true },

    // For compatibility with older routes
    user1: { type: String, required: true, index: true },
    user2: { type: String, required: true, index: true },

    // ✅ Added field used by all migrated routes (array-based lookups)
    users: { type: [String], required: true, index: true },

    status: {
      type: String,
      enum: ["pending", "matched", "rejected", "blocked"],
      default: "matched",
    },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

// 🧠 Automatically fill `users` array
matchSchema.pre("save", function (next) {
  if (!this.users || this.users.length !== 2) {
    this.users = [this.user1, this.user2];
  }
  next();
});

module.exports =
  mongoose.models.Match || mongoose.model("Match", matchSchema);
