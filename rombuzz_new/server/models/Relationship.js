/**
 * ============================================================
 * 📁 File: models/Relationship.js
 * 💾 Purpose: Unified schema for Likes, Blocks, and Follows
 *
 * Description:
 *   Lightweight model storing relationship-based data such as
 *   likes, blocks, and (future) follows between users.
 *
 *   Each document defines the "from" and "to" user IDs and
 *   the relationship type (e.g. like, block, follow).
 *
 * Used in:
 *   - routes/publicProfile.js
 *   - routes/viewProfile.js
 *   - routes/buzzPosts.js
 *   - routes/users.js
 * ============================================================
 */

const mongoose = require("mongoose");

const relationshipSchema = new mongoose.Schema(
  {
    from: { type: String, required: true, index: true }, // user initiating action
    to: { type: String, required: true, index: true },   // target user
    type: {
      type: String,
      enum: ["like", "block", "follow"],
      required: true,
    },
    createdAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

// ✅ Create compound index to prevent duplicate pairs
relationshipSchema.index({ from: 1, to: 1, type: 1 }, { unique: true });

module.exports =
  mongoose.models.Relationship ||
  mongoose.model("Relationship", relationshipSchema);
