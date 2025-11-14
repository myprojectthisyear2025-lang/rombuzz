/**
 * ============================================================
 * 📁 File: routes/publicProfile.js
 * 🧩 Purpose: Fetches a user’s public or full profile view.
 *
 * Endpoint:
 *   GET /api/users/:id                   → View another user's profile
 *
 * Features:
 *   - Shows full profile only if self or matched
 *   - Returns limited preview otherwise
 *   - Handles likes, matches, and block checks
 *   - Sanitizes output to avoid private data leakage
 *
 * Dependencies:
 *   - mongodb       → Database access
 *   - authMiddleware.js  → JWT validation
 *   - utils/helpers.js   → baseSanitizeUser()
 *
 * Notes:
 *   - Used by ViewProfile.jsx
 *   - Respects privacy fields (visibilityMode, fieldVisibility)
 * ============================================================
 */

const express = require("express");
const router = express.Router();
const authMiddleware = require("../routes/auth-middleware");
const { baseSanitizeUser } = require("../utils/helpers");

// Mongo models
const User = require("../models/User");
const PostModel = require("../models/PostModel");
const MatchModel = require("../models/MatchModel");
const Relationship = require("../models/Relationship"); // unified like/block model

router.get("/:id", authMiddleware, async (req, res) => {
  try {
    const viewerId = req.user.id;
    const targetId = req.params.id;

    // 1️⃣ Fetch target user
    const target = await User.findOne({ id: targetId }).lean();
    if (!target) return res.status(404).json({ error: "User not found" });

   // 2️⃣ Check block relationship
const isBlocked = await Relationship.exists({
  $or: [
    { from: viewerId, to: targetId, type: "block" },
    { from: targetId, to: viewerId, type: "block" },
  ],
});

    if (isBlocked)
      return res
        .status(403)
        .json({ error: "You are blocked or have blocked this user." });

    // 3️⃣ Relationship context (likes + match)
   const likedByMe = await Relationship.exists({ from: viewerId, to: targetId, type: "like" });
const likedMe = await Relationship.exists({ from: targetId, to: viewerId, type: "like" });

    const matched = await MatchModel.exists({
      status: "matched",
      $or: [
        { user1: viewerId, user2: targetId },
        { user1: targetId, user2: viewerId },
        { users: { $all: [viewerId, targetId] } },
      ],
    });

    // 4️⃣ Limited preview (not self or matched)
    if (viewerId !== targetId && !matched) {
      const preview = {
        id: target.id,
        firstName: target.firstName,
        lastName: (target.lastName ? target.lastName[0] : "") || "",
        avatar: target.avatar || "",
        bio: target.bio || "",
        vibe: target.vibe || "",
        gender: target.gender || "",
        verified: !!target.verified,
        visibilityMode: target.visibilityMode,
        fieldVisibility: target.fieldVisibility || {},
        media: (target.photos || []).slice(0, 3),
        posts: [],
      };

      return res.json({
        user: preview,
        likedByMe: !!likedByMe,
        likedMe: !!likedMe,
        matched: false,
        blocked: !!isBlocked,
      });
    }

    // 5️⃣ Full view (self or matched)
    const safeUser = baseSanitizeUser(target);

    const posts = await PostModel.find({
      userId: targetId,
      $or: [
        { privacy: "public" },
        { privacy: "matches" },
        { privacy: "specific", sharedWith: viewerId },
      ],
    })
      .sort({ createdAt: -1 })
      .lean();

    safeUser.media = (target.photos || []).filter(
      (p) => p.privacy !== "private"
    );
    safeUser.posts = posts;

    res.json({
      user: safeUser,
      likedByMe: !!likedByMe,
      likedMe: !!likedMe,
      matched: !!matched,
      blocked: !!isBlocked,
    });
  } catch (err) {
    console.error("❌ Error in /api/users/:id:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

module.exports = router;
