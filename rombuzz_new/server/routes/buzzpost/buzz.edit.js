/**
 * ============================================================
 * 📁 File: routes/buzzpost/buzz.edit.js
 * 🧩 Purpose: Handles post editing, privacy updates, and deletion
 *             for the Enhanced LetsBuzz feed.
 *
 * Description:
 *   - Allows post owners to update text or privacy level.
 *   - Soft deletes posts by marking inactive (isActive = false).
 *   - Compatible with old LowDB structure and frontend routes.
 *
 * Endpoints:
 *   PATCH  /api/posts/:postId           → Edit post text or privacy
 *   DELETE /api/posts/:postId           → Delete post
 *
 * Dependencies:
 *   - auth-middleware.js
 *   - models/PostModel.js
 * ============================================================
 */

const express = require("express");
const router = express.Router();
const authMiddleware = require("../auth-middleware");
const PostModel = require("../../models/PostModel");

// =======================================================
// ✅ Edit a post (text or privacy)
// =======================================================
router.patch("/posts/:postId", authMiddleware, async (req, res) => {
  try {
    const { postId } = req.params;
    const { text, privacy } = req.body || {};
    const myId = req.user.id;

    const post = await PostModel.findOne({ id: postId });
    if (!post) return res.status(404).json({ error: "Post not found" });
    if (post.userId !== myId)
      return res.status(403).json({ error: "Not your post" });

    if (typeof text === "string") post.text = text.trim();
    if (privacy) post.privacy = privacy;

    post.updatedAt = Date.now();
    await post.save();

    res.json({ success: true, post });
  } catch (err) {
    console.error("❌ Mongo PATCH /posts/:postId error:", err);
    res.status(500).json({ error: "Failed to update post" });
  }
});

// =======================================================
// ✅ Delete a post (soft delete for safety)
// =======================================================
router.delete("/posts/:postId", authMiddleware, async (req, res) => {
  try {
    const { postId } = req.params;
    const myId = req.user.id;

    const post = await PostModel.findOne({ id: postId });
    if (!post) return res.status(404).json({ error: "Post not found" });
    if (post.userId !== myId)
      return res.status(403).json({ error: "Not your post" });

    // Soft delete: mark inactive
    post.isActive = false;
    post.updatedAt = Date.now();
    await post.save();

    res.json({ success: true });
  } catch (err) {
    console.error("❌ Mongo DELETE /posts/:postId error:", err);
    res.status(500).json({ error: "Failed to delete post" });
  }
});

module.exports = router;
