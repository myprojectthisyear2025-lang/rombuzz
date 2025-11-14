/**
 * ============================================================
 * 📁 File: routes/buzzpost/buzz.comments.js
 * 💬 Purpose: Handles comment creation, fetching, editing,
 *             and deletion for LetsBuzz posts.
 *
 * Description:
 *   - Allows matched users to comment on each other's posts.
 *   - Supports editing and deletion by comment owner only.
 *   - Automatically attaches sanitized author info for frontend.
 *   - Used across LetsBuzz feed, ViewProfile, and MyBuzz pages.
 *
 * Endpoints:
 *   POST   /api/posts/:postId/comment
 *   GET    /api/posts/:postId/comments
 *   PATCH  /api/posts/:postId/comments/:commentId
 *   DELETE /api/posts/:postId/comments/:commentId
 *
 * Dependencies:
 *   - auth-middleware.js
 *   - models/PostModel.js
 *   - models/User.js
 *   - utils/helpers.js → baseSanitizeUser()
 * ============================================================
 */

const express = require("express");
const router = express.Router();
const shortid = require("shortid");
const authMiddleware = require("../auth-middleware");
const PostModel = require("../../models/PostModel");
const User = require("../../models/User");
const { baseSanitizeUser } = require("../../utils/helpers");

// =======================================================
// ✅ Add a new comment
// =======================================================
router.post("/posts/:postId/comment", authMiddleware, async (req, res) => {
  try {
    const { postId } = req.params;
    const { text } = req.body || {};
    const myId = req.user.id;

    if (!text?.trim()) return res.status(400).json({ error: "Text required" });

    const post = await PostModel.findOne({ id: postId });
    if (!post) return res.status(404).json({ error: "Post not found" });

    const newComment = {
      id: shortid.generate(),
      userId: myId,
      text: text.trim(),
      createdAt: Date.now(),
      updatedAt: Date.now(),
      reactions: {},
    };

    post.comments.push(newComment);
    await post.save();

    res.json({ success: true, comment: newComment });
  } catch (err) {
    console.error("❌ Mongo POST /posts/:postId/comment error:", err);
    res.status(500).json({ error: "Failed to add comment" });
  }
});

// =======================================================
// ✅ Fetch all comments for a post
// =======================================================
router.get("/posts/:postId/comments", authMiddleware, async (req, res) => {
  try {
    const { postId } = req.params;

    const post = await PostModel.findOne({ id: postId }).lean();
    if (!post) return res.status(404).json({ error: "Post not found" });

    const userIds = [...new Set(post.comments.map((c) => c.userId))];
    const authors = await User.find({ id: { $in: userIds } }).lean();
    const authorMap = new Map(authors.map((u) => [u.id, baseSanitizeUser(u)]));

    const comments = post.comments.map((c) => ({
      ...c,
      author:
        authorMap.get(c.userId) || {
          id: c.userId,
          firstName: "",
          lastName: "",
          avatar: "",
        },
    }));

    res.json({ comments });
  } catch (err) {
    console.error("❌ Mongo GET /posts/:postId/comments error:", err);
    res.status(500).json({ error: "Failed to fetch comments" });
  }
});

// =======================================================
// ✅ Edit own comment
// =======================================================
router.patch(
  "/posts/:postId/comments/:commentId",
  authMiddleware,
  async (req, res) => {
    try {
      const { postId, commentId } = req.params;
      const { text } = req.body || {};
      const myId = req.user.id;

      if (!text?.trim())
        return res.status(400).json({ error: "Text required" });

      const post = await PostModel.findOne({ id: postId });
      if (!post) return res.status(404).json({ error: "Post not found" });

      const comment = post.comments.find((c) => c.id === commentId);
      if (!comment) return res.status(404).json({ error: "Comment not found" });
      if (comment.userId !== myId)
        return res.status(403).json({ error: "Not your comment" });

      comment.text = text.trim();
      comment.updatedAt = Date.now();

      await post.save();
      res.json({ success: true, comment });
    } catch (err) {
      console.error("❌ Mongo PATCH /posts/:postId/comments/:commentId error:", err);
      res.status(500).json({ error: "Failed to edit comment" });
    }
  }
);

// =======================================================
// ✅ Delete own comment
// =======================================================
router.delete(
  "/posts/:postId/comments/:commentId",
  authMiddleware,
  async (req, res) => {
    try {
      const { postId, commentId } = req.params;
      const myId = req.user.id;

      const post = await PostModel.findOne({ id: postId });
      if (!post) return res.status(404).json({ error: "Post not found" });

      const before = post.comments.length;
      post.comments = post.comments.filter(
        (c) => !(c.id === commentId && c.userId === myId)
      );

      const changed = before !== post.comments.length;
      if (changed) await post.save();

      res.json({ success: changed });
    } catch (err) {
      console.error("❌ Mongo DELETE /posts/:postId/comments/:commentId error:", err);
      res.status(500).json({ error: "Failed to delete comment" });
    }
  }
);

module.exports = router;
