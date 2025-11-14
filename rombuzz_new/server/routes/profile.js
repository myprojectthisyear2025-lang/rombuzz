/**
 * ============================================================
 * 📁 File: routes/profile.js
 * 🧩 Purpose: Handles profile completion, onboarding, and full profile retrieval.
 *
 * Endpoints:
 *   GET  /api/profile/full              → Get full profile (with media & posts)
 *   POST /api/profile/complete          → Complete profile for logged-in user
 *   PUT  /api/users/complete-profile    → Complete profile for Google users
 *
 * Features:
 *   - Updates avatar, hobbies, match preferences, and photos
 *   - Auto-creates posts for uploaded photos
 *   - Sends notifications to matched users
 *   - Marks user as `profileComplete` and `hasOnboarded`
 *   - Returns full sanitized profile with media and posts
 *
 * Dependencies:
 *   - db.lowdb.js
 *   - authMiddleware.js
 *   - shortid
 *   - socket.io (optional for real-time notifications)
 *   - utils/helpers.js (baseSanitizeUser)
 * ============================================================
 */

const express = require("express");
const router = express.Router();
const shortid = require("shortid");
const { io } = require("../sockets/connection"); // optional socket export
const { baseSanitizeUser } = require("../utils/helpers");
const authMiddleware = require("./auth-middleware");
const db = require("../models/db.lowdb");
const User = require("../models/User");

/* ============================================================
   👤 SECTION 1: FULL PROFILE (with media)
============================================================ */

/**
 * GET /api/profile/full
 * Returns the full profile of the authenticated user including media & posts.
 */
// ============================================================
// 👤 FULL PROFILE (MongoDB version)
// ============================================================
router.get("/profile/full", authMiddleware, async (req, res) => {
  try {
    const PostModel = require("../models/PostModel");
    const Notification = require("../models/Notification");

    // 1️⃣ Fetch user
    const user = await User.findOne({ id: req.user.id }).lean();
    if (!user) return res.status(404).json({ error: "User not found" });

    // 2️⃣ Fetch posts from MongoDB
    const posts = await PostModel.find({ userId: user.id })
      .sort({ createdAt: -1 })
      .lean();

    // 3️⃣ Fetch latest notifications (optional enrichment)
    const notifications = await Notification.find({ toId: user.id })
      .sort({ createdAt: -1 })
      .limit(20)
      .lean();

    // 4️⃣ Build response
    res.json({
      user: {
        ...baseSanitizeUser(user),
        media: user.photos || [],
        posts,
        notifications,
      },
    });
  } catch (err) {
    console.error("❌ /profile/full (Mongo) error:", err);
    res.status(500).json({ error: "Failed to fetch full profile" });
  }
});



/* ============================================================
   🌟 SECTION 2: COMPLETE PROFILE ROUTE
============================================================ */

/**
 * POST /api/profile/complete
 * Completes profile setup for a logged-in user.
 * Used during onboarding after signup.
 */
router.post("/profile/complete", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { avatar, photos = [], hobbies, matchPref, locationRadius, ageRange } = req.body;

    const user = await User.findOneAndUpdate(
      { id: userId },
      {
        $set: {
          avatar,
          photos,
          hobbies,
          matchPref,
          locationRadius,
          ageRange,
          profileComplete: true,
          hasOnboarded: true,
          updatedAt: Date.now(),
        },
      },
      { new: true }
    ).lean();

    if (!user) return res.status(404).json({ error: "User not found" });

    // ✅ Create posts directly in MongoDB
const PostModel = require("../models/PostModel");

for (const photoUrl of photos) {
  await PostModel.create({
    id: shortid.generate(),
    userId: user.id,
    type: "photo",
    mediaUrl: photoUrl,
    text: `${user.firstName || "Someone"} just joined RomBuzz ✨ Let's Buzz!`,
    privacy: "public",
    createdAt: Date.now(),
    updatedAt: Date.now(),
  });
}


   // ✅ Notify matched users (MongoDB)
const Notification = require("../models/Notification");

// ✅ Fetch matched users (MongoDB)
const MatchModel = require("../models/MatchModel");

const matches = await MatchModel.find({
  status: "matched",
  $or: [{ user1: user.id }, { user2: user.id }],
}).lean();

const matchedUsers = matches.map((m) =>
  m.user1 === user.id ? m.user2 : m.user1
);

for (const matchId of matchedUsers) {
  const notif = {
    id: shortid.generate(),
    toId: matchId,
    fromId: user.id,
    type: "new_post",
    message: `${user.firstName || "Someone"} just shared new photos! 💫`,
    href: "/letsbuzz",
    postOwnerId: user.id,
    createdAt: Date.now(),
    read: false,
  };

  await Notification.create(notif);

  if (io) io.to(matchId).emit("notification:new_post", notif);
}


    res.json(baseSanitizeUser(user));
  } catch (err) {
    console.error("❌ /profile/complete error:", err);
    res.status(500).json({ error: "Failed to complete profile" });
  }
});


/* ============================================================
   🧩 SECTION 3: COMPLETE PROFILE FOR GOOGLE USERS
============================================================ */

/**
 * PUT /api/users/complete-profile
 * Completes profile for Google-authenticated users.
 */
router.put("/users/complete-profile", authMiddleware, async (req, res) => {
  try {
    const updates = {
      ...req.body,
      profileComplete: true,
      hasOnboarded: true,
      updatedAt: Date.now(),
    };

    const user = await User.findOneAndUpdate({ id: req.user.id }, { $set: updates }, { new: true }).lean();
    if (!user) return res.status(404).json({ error: "User not found" });

    res.json({ success: true, user: baseSanitizeUser(user) });
  } catch (err) {
    console.error("❌ PUT /users/complete-profile error:", err);
    res.status(500).json({ error: "Failed to complete profile" });
  }
});


console.log("✅ Profile routes initialized (full + complete + google)");

module.exports = router;
