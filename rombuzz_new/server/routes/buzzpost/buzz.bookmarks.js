/**
 * ============================================================
 * 📁 File: routes/buzzpost/buzz.bookmarks.js
 * 💬 Purpose: Handles post bookmarking and sharing actions
 *             in the LetsBuzz feed.
 *
 * Description:
 *   - Bookmark or un-bookmark any post.
 *   - Retrieve all bookmarked posts (with user info).
 *   - Share posts with matches or specific users.
 *   - Sends notifications for new shares.
 *
 * Endpoints:
 *   POST   /api/buzz/posts/:postId/bookmark   → Save post
 *   DELETE /api/buzz/posts/:postId/bookmark   → Remove bookmark
 *   GET    /api/buzz/bookmarks                → Get all bookmarks
 *   POST   /api/buzz/posts/:postId/share      → Share post with matches
 *
 * Dependencies:
 *   - auth-middleware.js
 *   - models/PostModel.js
 *   - models/User.js
 *   - utils/helpers.js → sendNotification(), baseSanitizeUser()
 *   - db.lowdb.js (temporary for matches)
 * ============================================================
 */

const express = require("express");
const router = express.Router();
const authMiddleware = require("../auth-middleware");
const PostModel = require("../../models/PostModel");
const User = require("../../models/User");
const { sendNotification, baseSanitizeUser } = require("../../utils/helpers");
const { db } = require("../../models/db.lowdb");

// =======================================================
// ✅ Bookmark a post
// =======================================================
router.post("/buzz/posts/:postId/bookmark", authMiddleware, async (req, res) => {
  try {
    const { postId } = req.params;
    const myId = req.user.id;

    const post = await PostModel.findOne({ id: postId });
    if (!post) return res.status(404).json({ error: "Post not found" });

    post.bookmarks = post.bookmarks || [];
    if (!post.bookmarks.includes(myId)) {
      post.bookmarks.push(myId);
      await post.save();
    }

    res.json({ success: true, bookmarked: true });
  } catch (err) {
    console.error("❌ Mongo POST /buzz/posts/:postId/bookmark error:", err);
    res.status(500).json({ error: "Failed to bookmark post" });
  }
});

// =======================================================
// ✅ Remove bookmark
// =======================================================
router.delete("/buzz/posts/:postId/bookmark", authMiddleware, async (req, res) => {
  try {
    const { postId } = req.params;
    const myId = req.user.id;

    const post = await PostModel.findOne({ id: postId });
    if (!post) return res.status(404).json({ error: "Post not found" });

    post.bookmarks = (post.bookmarks || []).filter((id) => id !== myId);
    await post.save();

    res.json({ success: true, bookmarked: false });
  } catch (err) {
    console.error("❌ Mongo DELETE /buzz/posts/:postId/bookmark error:", err);
    res.status(500).json({ error: "Failed to remove bookmark" });
  }
});

// =======================================================
// ✅ Get all bookmarked posts (MongoDB)
// =======================================================
router.get("/buzz/bookmarks", authMiddleware, async (req, res) => {
  try {
    const myId = req.user.id;

    const posts = await PostModel.find({ bookmarks: myId, isActive: true })
      .sort({ createdAt: -1 })
      .lean();

    if (!posts.length) return res.json({ posts: [] });

    const userIds = [...new Set(posts.map((p) => p.userId))];
    const users = await User.find({ id: { $in: userIds } }).lean();
    const map = new Map(users.map((u) => [u.id, baseSanitizeUser(u)]));

    const formatted = posts.map((p) => ({
      ...p,
      user:
        map.get(p.userId) || { id: p.userId, firstName: "", lastName: "", avatar: "" },
      hasBookmarked: true,
    }));

    res.json({ posts: formatted });
  } catch (err) {
    console.error("❌ Mongo GET /buzz/bookmarks error:", err);
    res.status(500).json({ error: "Failed to fetch bookmarks" });
  }
});

// =======================================================
// ✅ Share a post with matches or selected users
// =======================================================
router.post("/buzz/posts/:postId/share", authMiddleware, async (req, res) => {
  try {
    const { postId } = req.params;
    const { shareWith = [] } = req.body || {}; // array of user IDs
    const myId = req.user.id;

    const post = await PostModel.findOne({ id: postId });
    if (!post) return res.status(404).json({ error: "Post not found" });

    post.shares = post.shares || [];

    // Prevent duplicates
    const newShares = shareWith.filter(
      (uid) => !post.shares.some((s) => s.userId === uid)
    );

    post.shares.push(
      ...newShares.map((uid) => ({
        userId: uid,
        sharedBy: myId,
        sharedAt: Date.now(),
      }))
    );

    await post.save();

    // 🔔 Notify newly shared users
    const meUser = await User.findOne({ id: myId }).lean();
    for (const uid of newShares) {
      await sendNotification(uid, {
        fromId: myId,
        type: "share",
        message: `${meUser?.firstName || "Someone"} shared a post with you 🔗`,
        href: `/buzz/post/${postId}`,
        entity: "post",
        entityId: postId,
        postId,
        postOwnerId: post.userId,
      });
    }

    res.json({ success: true, shares: post.shares });
  } catch (err) {
    console.error("❌ Mongo POST /buzz/posts/:postId/share error:", err);
    res.status(500).json({ error: "Failed to share post" });
  }
});

module.exports = router;
