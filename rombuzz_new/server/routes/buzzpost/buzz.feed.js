/**
 * ============================================================
 * 📁 File: routes/buzzpost/buzz.feed.js
 * 💬 Purpose: Fetch and manage the LetsBuzz feed — including
 *             main feed, reels feed, and view counter updates.
 *
 * Description:
 *   - Retrieves posts visible to the current user based on privacy
 *     (public, matches, specific).
 *   - Supports filtering by type (text, image, video).
 *   - Supports search and sorting (newest / popular).
 *   - Handles view counter updates (e.g., for Reels autoplay).
 *
 * Endpoints:
 *   GET  /api/buzz/feed               → Main feed (matches + visibility)
 *   GET  /api/buzz/reels              → Only video/reel posts
 *   POST /api/buzz/posts/:postId/view → Increment post view count
 *
 * Dependencies:
 *   - auth-middleware.js
 *   - models/PostModel.js
 *   - models/User.js
 *   - db.lowdb.js (temporary for match references)
 *   - utils/helpers.js → baseSanitizeUser()
 * ============================================================
 */

const express = require("express");
const router = express.Router();
const authMiddleware = require("../auth-middleware");

const { db } = require("../../models/db.lowdb");
const PostModel = require("../../models/PostModel");
const User = require("../../models/User");
const { baseSanitizeUser } = require("../../utils/helpers");

// =======================================================
// ✅ GET: Main feed (MongoDB)
// =======================================================
router.get("/buzz/feed", authMiddleware, async (req, res) => {
  try {
    const {
      type,             // filter by post type
      search,           // search in text/tags
      sort = "newest",  // newest | popular
      limit = 50,
      offset = 0,
    } = req.query;

    const myId = req.user.id;

    // 1️⃣ Read matches from LowDB (to be migrated later)
    await db.read();
    const myMatches = (db.data.matches || [])
      .filter(
        (m) =>
          (Array.isArray(m.users) && m.users.includes(myId)) ||
          m.userA === myId ||
          m.userB === myId
      )
      .map((m) =>
        Array.isArray(m.users)
          ? m.users.find((id) => id !== myId)
          : m.userA === myId
          ? m.userB
          : m.userA
      )
      .filter(Boolean);

    // 2️⃣ Build Mongo query
    const visibilityQuery = {
      $or: [
        { userId: myId },
        { privacy: "public" },
        { privacy: "matches", userId: { $in: myMatches } },
        { privacy: "specific", sharedWith: myId },
      ],
      isActive: true,
    };

    if (type && type !== "all") visibilityQuery.type = type;

    if (search) {
      const regex = new RegExp(search, "i");
      visibilityQuery.$or.push({ text: regex });
      visibilityQuery.$or.push({ tags: regex });
    }

    // 3️⃣ Fetch posts
    let posts = await PostModel.find(visibilityQuery)
      .sort(
        sort === "popular"
          ? { viewCount: -1, createdAt: -1 }
          : { createdAt: -1 }
      )
      .skip(parseInt(offset))
      .limit(parseInt(limit))
      .lean();

    if (!posts.length)
      return res.json({ posts: [], total: 0, hasMore: false });

    // 4️⃣ Get owners
    const userIds = [...new Set(posts.map((p) => p.userId))];
    const owners = await User.find({ id: { $in: userIds } }).lean();
    const ownersMap = new Map(owners.map((u) => [u.id, baseSanitizeUser(u)]));

    // 5️⃣ Format for frontend
    const formatted = posts.map((p) => ({
      ...p,
      user:
        ownersMap.get(p.userId) || {
          id: p.userId,
          firstName: "",
          lastName: "",
          avatar: "",
        },
      reactionCount: Object.keys(p.reactions || {}).length,
      commentCount: (p.comments || []).length,
      shareCount: (p.shares || []).length,
      hasBookmarked: (p.bookmarks || []).includes(myId),
      myReaction: p.reactions?.[myId] || null,
    }));

    const total = await PostModel.countDocuments(visibilityQuery);
    res.json({
      posts: formatted,
      total,
      hasMore: parseInt(offset) + parseInt(limit) < total,
    });
  } catch (err) {
    console.error("❌ Mongo GET /buzz/feed error:", err);
    res.status(500).json({ error: "Failed to load feed" });
  }
});

// =======================================================
// ✅ GET: Reels Feed (MongoDB)
// =======================================================
router.get("/buzz/reels", authMiddleware, async (req, res) => {
  try {
    const myId = req.user.id;

    await db.read();
    const myMatches = (db.data.matches || [])
      .filter((m) => Array.isArray(m.users) && m.users.includes(myId))
      .map((m) => m.users.find((id) => id !== myId))
      .filter(Boolean);

    const reels = await PostModel.find({
      userId: { $in: myMatches },
      type: { $in: ["reel", "video"] },
      isActive: true,
    })
      .sort({ createdAt: -1 })
      .lean();

    if (!reels.length) return res.json({ posts: [] });

    const owners = await User.find({
      id: { $in: [...new Set(reels.map((p) => p.userId))] },
    }).lean();

    const ownerMap = new Map(owners.map((u) => [u.id, baseSanitizeUser(u)]));

    const posts = reels.map((p) => ({
      ...p,
      user:
        ownerMap.get(p.userId) || {
          id: p.userId,
          firstName: "",
          lastName: "",
          avatar: "",
        },
    }));

    res.json({ posts });
  } catch (err) {
    console.error("❌ Mongo GET /buzz/reels error:", err);
    res.status(500).json({ error: "Failed to fetch reels" });
  }
});

// =======================================================
// ✅ POST: Increment view counter (used by reels autoplay)
// =======================================================
router.post("/buzz/posts/:postId/view", authMiddleware, async (req, res) => {
  try {
    const { postId } = req.params;
    const post = await PostModel.findOne({ id: postId });
    if (!post) return res.status(404).json({ error: "Post not found" });

    post.viewCount = (post.viewCount || 0) + 1;
    post.updatedAt = Date.now();
    await post.save();

    res.json({ ok: true, viewCount: post.viewCount });
  } catch (err) {
    console.error("❌ Mongo POST /buzz/posts/:postId/view error:", err);
    res.status(500).json({ error: "Failed to record view" });
  }
});

module.exports = router;
