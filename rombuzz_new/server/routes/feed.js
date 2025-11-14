/**
 * ============================================================
 * 📁 File: routes/feed.js
 * 🧩 Purpose: Aggregates posts & reels from matched users.
 *
 * Endpoints:
 *   GET /api/feed                     → Show matched users’ posts and reels
 *
 * Features:
 *   - Collects both image and video posts
 *   - Includes only visibility: "matches" or "public"
 *   - Sorts feed by creation date (newest first)
 *   - Uses baseSanitizeUser() for safe user info
 *
 * Dependencies:
 *   - models/User.js        → Mongoose user schema
 *   - models/Match.js       → Match relationship collection
 *   - authMiddleware.js     → Validates JWT session
 *   - utils/helpers.js      → baseSanitizeUser()
 *
 * Notes:
 *   - Used by LetsBuzz.jsx and Discover.jsx
 * ============================================================
 */

const express = require("express");
const router = express.Router();
const authMiddleware = require("../routes/auth-middleware");
const User = require("../models/User");
const Match = require("../models/Match");
const { baseSanitizeUser } = require("../utils/helpers");

/* ============================================================
   🏠 FEED ENDPOINT — show matched users’ posts & reels
============================================================ */
router.get("/", authMiddleware, async (req, res) => {
  try {
    const myId = req.user.id;

    // 🧩 Fetch all matches where I’m one of the users
    const matches = await Match.find({ users: myId }).lean();
    const myMatches = matches
      .map((m) => m.users.find((id) => id !== myId))
      .filter(Boolean);

    const feed = [];

    // 🔍 For each matched user, fetch posts with allowed visibility
    const matchedUsers = await User.find({ id: { $in: myMatches } }).lean();

    for (const u of matchedUsers) {
      if (!Array.isArray(u.posts)) continue;

      for (const p of u.posts) {
        if (["matches", "public"].includes(p.visibility)) {
          feed.push({
            ...p,
            user: baseSanitizeUser(u),
          });
        }
      }
    }

    // 📅 Sort newest first
    feed.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));

    res.json({ posts: feed });
  } catch (err) {
    console.error("❌ Feed fetch failed:", err);
    res.status(500).json({ error: "failed to load feed" });
  }
});

module.exports = router;
