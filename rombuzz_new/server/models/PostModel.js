/**
 * ============================================================
 * 📁 File: models/PostModel.js
 * 💾 Purpose: MongoDB (Mongoose) schema for all RomBuzz posts.
 *
 * Description:
 *   Represents user posts in the RomBuzz feed — text, image, video,
 *   reel, or story. Each post supports comments, reactions, likes,
 *   bookmarks, and shares. This schema mirrors the LowDB structure
 *   exactly, allowing a smooth migration.
 *
 * Usage:
 *   - Used by auth.js (welcome post)
 *   - Will later replace LowDB usage in posts.js & buzzPosts.js
 *
 * Notes:
 *   - Keeps shortid-style IDs for backward compatibility.
 *   - Each post belongs to one user (via userId).
 * ============================================================
 */

const mongoose = require("mongoose");

const commentSchema = new mongoose.Schema(
  {
    id: { type: String, required: true },
    userId: { type: String, required: true },
    text: { type: String, required: true },

    // ➕ New fields to match LowDB behavior
    parentId: { type: String, default: null },      // reply-to comment
    reactions: { type: Map, of: String, default: {} }, // { userId: "😊" }
    visibleTo: [{ type: String }],                  // [postOwnerId, commenterId]
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
  },
  { _id: false }
);


const postSchema = new mongoose.Schema(
  {
    // 🔑 Identifiers
    id: { type: String, required: true, unique: true, index: true }, // shortid-style
    userId: { type: String, required: true, index: true },

    // 📝 Content
    text: { type: String, default: "" },
    mediaUrl: { type: String, default: "" },
    type: {
      type: String,
      enum: ["text", "photo", "video", "reel", "story"],
      default: "text",
    },

    // 👁️ Privacy
    privacy: {
      type: String,
      enum: ["public", "matches", "specific"],
      default: "matches",
    },
    sharedWith: [{ type: String }],
    expiresAt: { type: Date, default: null },
    isActive: { type: Boolean, default: true },

    // 📈 Engagement
    reactions: { type: Map, of: String, default: {} }, // { userId: "emoji" }
    comments: [commentSchema],
    likes: [
      {
        userId: String,
        name: String,
        avatar: String,
        createdAt: { type: Date, default: Date.now },
      },
    ],
    bookmarks: [{ type: String }], // userIds
    shares: [{ userId: String, sharedBy: String, sharedAt: Date }],
    viewCount: { type: Number, default: 0 },

    // 🕓 Meta
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
  },
  {
    timestamps: true,
  }
);

module.exports =
  mongoose.models.PostModel ||
  mongoose.model("PostModel", postSchema);
