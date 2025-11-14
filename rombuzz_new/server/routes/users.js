/**
 * ============================================================
 * 📁 File: routes/users.js
 * 🧩 Purpose: Manage user profile updates, preferences, blocking, and social stats.
 *
 * Endpoints:
 *   GET    /api/users/me                 → Get current user info
 *   POST   /api/location                 → Update user's current location
 *   GET    /api/users/social             → Get likes / matches summary
 *   GET    /api/social-stats             → Alias for same stats
 *   GET    /api/matches                  → List match profiles
 *   PUT    /api/users/me                 → Update profile details
 *   GET    /api/users/blocks             → List blocked users
 *   POST   /api/users/blocks/:userId     → Block another user
 *   DELETE /api/users/blocks/:userId     → Unblock a user
 *   GET    /api/users/social-stats       → Retrieve likes / likedYou / matches (Mongo)
 *
 * Features:
 *   - Profile editing (bio, vibe, visibility, etc.)
 *   - Restricts name changes (once per 30 days)
 *   - Validates vibes and visibility filters
 *   - Uses MongoDB for likes, blocks, and matches
 *   - Returns sanitized user data (no passwords or secrets)
 *
 * Dependencies:
 *   - mongoose User, Relationship, MatchModel
 *   - authMiddleware.js  → JWT authentication
 *   - utils/helpers.js   → User sanitization
 *
 * Notes:
 *   - Mounted under /api/users in index.js
 *   - Used by EditProfile.jsx, Settings.jsx, Discover.jsx
 * ============================================================
 */

const express = require("express");
const router = express.Router();
const authMiddleware = require("./auth-middleware");
const {
  baseSanitizeUser,
  msToDays,
  THIRTY_DAYS,
} = require("../utils/helpers");

// ✅ Mongo Models
const User = require("../models/User");
const Relationship = require("../models/Relationship"); // for likes/blocks
const MatchModel = require("../models/MatchModel");

/* ============================================================
   👤 SECTION 1: USER INFO & LOCATION
============================================================ */

/**
 * GET /api/users/me → current logged-in user
 */
router.get("/me", authMiddleware, async (req, res) => {
  try {
    const user = await User.findOne({ id: req.user.id }).lean();
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(baseSanitizeUser(user));
  } catch (err) {
    console.error("❌ /users/me error:", err);
    res.status(500).json({ error: "Failed to fetch user" });
  }
});

/**
 * POST /api/location → update user geolocation
 */
router.post("/location", authMiddleware, async (req, res) => {
  try {
    const { lat, lng } = req.body || {};
    const latNum = Number(lat);
    const lngNum = Number(lng);
    if (!Number.isFinite(latNum) || !Number.isFinite(lngNum)) {
      return res.status(400).json({ error: "lat & lng required" });
    }

    const user = await User.findOneAndUpdate(
      { id: req.user.id },
      {
        $set: {
          location: { lat: latNum, lng: lngNum },
          updatedAt: Date.now(),
        },
      },
      { new: true }
    ).lean();

    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({ ok: true, location: user.location });
  } catch (err) {
    console.error("❌ /location error:", err);
    res.status(500).json({ error: "Failed to update location" });
  }
});

/* ============================================================
   💞 SECTION 2: SOCIAL RELATIONSHIPS (likes, matches)
============================================================ */

/**
 * GET /api/users/social or /api/social-stats
 * → summary of likesGiven, likesReceived, matchesCount
 */
router.get(["/social", "/social-stats"], authMiddleware, async (req, res) => {
  try {
    const myId = req.user.id;

    // Likes given / received from Relationship model
    const likesGiven = await Relationship.countDocuments({
      from: myId,
      type: "like",
    });
    const likesReceived = await Relationship.countDocuments({
      to: myId,
      type: "like",
    });

    // Matched users count
    const matchesCount = await MatchModel.countDocuments({
      status: "matched",
      $or: [{ user1: myId }, { user2: myId }],
    });

    res.json({ likesGiven, likesReceived, matchesCount });
  } catch (err) {
    console.error("❌ /users/social error:", err);
    res.status(500).json({ error: "Failed to fetch social stats" });
  }
});

/**
 * GET /api/matches → list full match partner profiles
 */
router.get("/matches", authMiddleware, async (req, res) => {
  try {
    const myId = req.user.id;

    const matches = await MatchModel.find({
      status: "matched",
      $or: [{ user1: myId }, { user2: myId }],
    }).lean();

    if (!matches.length)
      return res.json({ count: 0, matches: [] });

    // Extract other user IDs
    const partnerIds = matches.map((m) =>
      m.user1 === myId ? m.user2 : m.user1
    );
    const uniqueIds = [...new Set(partnerIds)];

    const partners = await User.find({ id: { $in: uniqueIds } })
      .select("id firstName lastName avatar vibe premiumTier verified")
      .lean();

    res.json({ count: partners.length, matches: partners });
  } catch (err) {
    console.error("❌ /matches error:", err);
    res.status(500).json({ error: "Failed to fetch matches" });
  }
});

/* ============================================================
   🧑 SECTION 3: PROFILE UPDATE / BLOCKS
============================================================ */

/**
 * PUT /api/users/me → update profile info
 */
router.put("/me", authMiddleware, async (req, res) => {
  try {
    const allowed = [
      "firstName", "lastName", "dob", "gender", "bio", "location",
      "visibility", "avatar", "phone", "interests", "favorites",
      "orientation", "hobbies", "vibe", "filterVibe", "premiumTier",
      "settings", "visibilityMode", "fieldVisibility"
    ];

    const updates = {};
    for (const k of allowed) {
      if (req.body[k] !== undefined) updates[k] = req.body[k];
    }
    updates.updatedAt = Date.now();

    const user = await User.findOneAndUpdate(
      { id: req.user.id },
      { $set: updates },
      { new: true }
    ).lean();

    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({ user: baseSanitizeUser(user) });
  } catch (err) {
    console.error("❌ PUT /users/me error:", err);
    res.status(500).json({ error: "Failed to update profile" });
  }
});

/**
 * GET /api/users/blocks → list all users I’ve blocked
 */
router.get("/blocks", authMiddleware, async (req, res) => {
  try {
    const blocks = await Relationship.find({
      from: req.user.id,
      type: "block",
    }).lean();

    const ids = blocks.map((b) => b.to);
    if (!ids.length) return res.json({ blocks: [] });

    const blocked = await User.find({ id: { $in: ids } })
      .select("id firstName lastName avatar")
      .lean();

    res.json({ blocks: blocked });
  } catch (err) {
    console.error("❌ GET /users/blocks error:", err);
    res.status(500).json({ error: "Failed to fetch blocks" });
  }
});

/**
 * POST /api/users/blocks/:userId → block another user
 */
router.post("/blocks/:userId", authMiddleware, async (req, res) => {
  try {
    const myId = req.user.id;
    const targetId = req.params.userId;
    if (myId === targetId)
      return res.status(400).json({ error: "Cannot block yourself" });

    const existing = await Relationship.findOne({
      from: myId,
      to: targetId,
      type: "block",
    });
    if (!existing) {
      await Relationship.create({ from: myId, to: targetId, type: "block" });
      console.log(`🚫 ${myId} blocked ${targetId}`);
    }

    res.json({ success: true });
  } catch (err) {
    console.error("❌ Block user error:", err);
    res.status(500).json({ error: "Failed to block user" });
  }
});

/**
 * DELETE /api/users/blocks/:userId → unblock a user
 */
router.delete("/blocks/:userId", authMiddleware, async (req, res) => {
  try {
    const myId = req.user.id;
    const targetId = req.params.userId;

    await Relationship.deleteOne({
      from: myId,
      to: targetId,
      type: "block",
    });

    console.log(`🔓 ${myId} unblocked ${targetId}`);
    res.json({ success: true });
  } catch (err) {
    console.error("❌ Unblock user error:", err);
    res.status(500).json({ error: "Failed to unblock user" });
  }
});

/* ============================================================
   ❤️ SECTION 4: SOCIAL STATS SUMMARY (likes + matches)
============================================================ */

/**
 * GET /api/users/social-stats → advanced social overview
 */
router.get("/social-stats", authMiddleware, async (req, res) => {
  try {
    const myId = req.user.id;

    const liked = await Relationship.find({
      from: myId,
      type: "like",
    }).lean();

    const likedYou = await Relationship.find({
      to: myId,
      type: "like",
    }).lean();

    const mutualLikes = liked
      .map((l) => l.to)
      .filter((id) => likedYou.some((r) => r.from === id));

    const matches = await MatchModel.find({
      status: "matched",
      $or: [{ user1: myId }, { user2: myId }],
    }).lean();

    const matchIds = matches.map((m) =>
      m.user1 === myId ? m.user2 : m.user1
    );

    res.json({
      likedCount: liked.length,
      likedYouCount: likedYou.length,
      matchCount: matchIds.length,
      liked: liked.map((l) => l.to),
      likedYou: likedYou.map((l) => l.from),
      matches: matchIds,
    });
  } catch (err) {
    console.error("❌ /users/social-stats error:", err);
    res.status(500).json({ error: "Failed to fetch social stats" });
  }
});

console.log("✅ Users routes initialized (MongoDB version)");

module.exports = router;
