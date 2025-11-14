/**
 * ============================================================
 * 📁 File: routes/buzzComments.js
 * 💬 Purpose: Handle all comment-related functionality for
 *             LetsBuzz posts, including creation, fetching with
 *             visibility rules, editing, deletion, and emoji reactions.
 *
 * Endpoints:
 *   POST    /api/buzz/posts/:postId/comments                → Add new comment or reply
 *   GET     /api/buzz/posts/:postId/comments                → Fetch visible comments
 *   PATCH   /api/buzz/posts/:postId/comments/:commentId     → Edit comment (author only)
 *   DELETE  /api/buzz/posts/:postId/comments/:commentId     → Delete comment (author only)
 *   POST    /api/buzz/posts/:postId/comments/:commentId/react → React (emoji) to comment
 *   DELETE  /api/buzz/posts/:postId/comments/:commentId/react → Remove comment reaction
 *
 * Dependencies:
 *   - db (LowDB instance)
 *   - authMiddleware.js
 *   - utils/helpers.js → sendNotification(), baseSanitizeUser()
 *   - shortid
 *   - Socket.IO (io) [for live comment broadcasts]
 * ============================================================
 */


const express = require("express");
const router = express.Router();
const shortid = require("shortid");
const PostModel = require("../models/PostModel");
const User = require("../models/User");
const { io } = global; // socket (your project already sets globals)
const Notification = require("../models/Notification"); // fallback if no helper

// ✅ fixed middleware path
const authMiddleware = require("../routes/auth-middleware");

// ✅ fixed helper + db imports
const { sendNotification, baseSanitizeUser } = require("../utils/helpers");
const { db } = require("../models/db.lowdb");


/* ======================
   BUZZ COMMENTS SYSTEM
====================== */

// ============================================================
// 💬 Add a new comment (MongoDB version)
// ============================================================
router.post("/buzz/posts/:postId/comments", authMiddleware, async (req, res) => {
  try {
    const { postId } = req.params;
    const { text, parentId = null } = req.body || {};
    const myId = req.user.id;

    if (!text?.trim()) return res.status(400).json({ error: "Comment text required" });

    const post = await PostModel.findOne({ id: postId });
    if (!post) return res.status(404).json({ error: "Post not found" });

    const comment = {
      id: shortid.generate(),
      userId: myId,
      text: text.trim(),
      parentId,
      createdAt: new Date(),
      updatedAt: new Date(),
      visibleTo: [post.userId, myId],
      reactions: {},
    };

    post.comments.push(comment);
    post.updatedAt = Date.now();
    await post.save();

    // 🔔 Notify post owner
    if (post.userId !== myId) {
      const user = await User.findOne({ id: myId }).lean();
      const commenterName = user?.firstName || "Someone";
      const notif = {
        id: shortid.generate(),
        toId: post.userId,
        fromId: myId,
        type: "comment",
        message: `${commenterName} commented on your post: "${text.slice(0, 50)}${
          text.length > 50 ? "..." : ""
        }"`,
        href: `/buzz/post/${postId}`,
        postId,
        postOwnerId: post.userId,
      };
      await Notification.create(notif);
      if (io) io.to(String(post.userId)).emit("notification:new", notif);
    }

    // 📡 Real-time broadcast
    if (io) {
      io.to(String(myId)).emit("comment:new", { postId, comment });
      if (post.userId !== myId)
        io.to(String(post.userId)).emit("comment:new", { postId, comment });
    }

    res.json({ success: true, comment });
  } catch (error) {
    console.error("❌ Add comment error:", error);
    res.status(500).json({ error: "Failed to add comment" });
  }
});


// ============================================================
// 💬 Get all comments for a post (MongoDB version)
// ============================================================
router.get("/buzz/posts/:postId/comments", authMiddleware, async (req, res) => {
  try {
    const { postId } = req.params;
    const myId = req.user.id;

    // Fetch post and comments
    const post = await PostModel.findOne({ id: postId }).lean();
    if (!post) return res.status(404).json({ error: "Post not found" });

    // Filter by visibility
    const filteredComments = (post.comments || []).filter((c) =>
      Array.isArray(c.visibleTo)
        ? c.visibleTo.includes(myId)
        : c.userId === myId || post.userId === myId
    );

    // Collect all unique user IDs to fetch authors efficiently
    const authorIds = [...new Set(filteredComments.map((c) => c.userId))];
    const users = await User.find({ id: { $in: authorIds } }).lean();

    // Attach author + reactions
    const commentsWithAuthors = filteredComments.map((c) => {
      const author = users.find((u) => u.id === c.userId);
      const reactionCounts = {};
      Object.values(c.reactions || {}).forEach((emoji) => {
        reactionCounts[emoji] = (reactionCounts[emoji] || 0) + 1;
      });
      return {
        ...c,
        author: author ? baseSanitizeUser(author) : { firstName: "Unknown", avatar: "" },
        myReaction: c.reactions?.[myId] || null,
        reactionCounts,
        totalReactions: Object.keys(c.reactions || {}).length,
      };
    });

    res.json({ comments: commentsWithAuthors });
  } catch (err) {
    console.error("❌ Fetch comments (MongoDB) error:", err);
    res.status(500).json({ error: "Failed to fetch comments" });
  }
});


// ============================================================
// ✍️ Edit a Buzz comment (MongoDB version - author only)
// ============================================================
router.patch("/buzz/posts/:postId/comments/:commentId", authMiddleware, async (req, res) => {
  try {
    const { postId, commentId } = req.params;
    const { text = "" } = req.body || {};
    const me = req.user.id;

    if (!text.trim()) {
      return res.status(400).json({ error: "text required" });
    }

    // 1) Load the post that contains this comment
    const post = await PostModel.findOne({ id: postId, "comments.id": commentId }).lean();
    if (!post) return res.status(404).json({ error: "Post or comment not found" });

    const comment = (post.comments || []).find((c) => c.id === commentId);
    if (!comment) return res.status(404).json({ error: "Comment not found" });

    // 2) Ownership check
    if (String(comment.userId) !== String(me)) {
      return res.status(403).json({ error: "Not your comment" });
    }

    // 3) Update the comment text + timestamps
    //    Also ensure visibleTo contains [post.userId, me] for privacy
    await PostModel.updateOne(
      { id: postId, "comments.id": commentId },
      {
        $set: {
          "comments.$.text": text.trim(),
          "comments.$.updatedAt": Date.now(),
        },
        $addToSet: {
          "comments.$.visibleTo": { $each: [post.userId, me] },
        },
      }
    );

    // 4) Re-fetch the updated comment to return it enriched
    const refreshed = await PostModel.findOne(
      { id: postId },
      { _id: 0, comments: 1, userId: 1 }
    ).lean();

    const updated = (refreshed?.comments || []).find((c) => c.id === commentId);
    if (!updated) return res.status(500).json({ error: "Edit applied but comment not found" });

    // 5) Attach author & reaction summary just like before
    const author = await User.findOne({ id: updated.userId }).lean();
    const reactionCounts = {};
    Object.values(updated.reactions || {}).forEach((emoji) => {
      reactionCounts[emoji] = (reactionCounts[emoji] || 0) + 1;
    });

    const enriched = {
      ...updated,
      author: author ? baseSanitizeUser(author) : { firstName: "Unknown", avatar: "" },
      myReaction: (updated.reactions || {})[me] || null,
      reactionCounts,
      totalReactions: Object.keys(updated.reactions || {}).length,
    };

    return res.json({ success: true, comment: enriched });
  } catch (e) {
    console.error("Buzz comment edit (Mongo) error:", e);
    res.status(500).json({ error: "Failed to edit comment" });
  }
});


// ============================================================
// 🗑️ Delete a Buzz comment (MongoDB version - author only)
// ============================================================
router.delete("/buzz/posts/:postId/comments/:commentId", authMiddleware, async (req, res) => {
  try {
    const { postId, commentId } = req.params;
    const me = req.user.id;

    // 1️⃣ Locate the post that contains this comment
    const post = await PostModel.findOne({ id: postId, "comments.id": commentId });
    if (!post) return res.status(404).json({ error: "Post or comment not found" });

    // 2️⃣ Find the target comment
    const comment = post.comments.find((c) => c.id === commentId);
    if (!comment) return res.status(404).json({ error: "Comment not found" });

    // 3️⃣ Only the author can delete
    if (String(comment.userId) !== String(me)) {
      return res.status(403).json({ error: "Not your comment" });
    }

    // 4️⃣ Remove it
    const before = post.comments.length;
    post.comments = post.comments.filter((c) => c.id !== commentId);
    const removed = post.comments.length < before;
    await post.save();

    // 5️⃣ Optional: Emit socket event to refresh comment list
    if (io && io.to) {
      io.to(String(me)).emit("comment:deleted", { postId, commentId });
      if (String(post.userId) !== String(me)) {
        io.to(String(post.userId)).emit("comment:deleted", { postId, commentId });
      }
    }

    res.json({ success: true, removed });
  } catch (e) {
    console.error("Buzz comment delete (Mongo) error:", e);
    res.status(500).json({ error: "Failed to delete comment" });
  }
});


// =======================================================
// 💬 COMMENT REACTIONS ENDPOINTS
// =======================================================
// ============================================================
// 💖 React to a comment (MongoDB version)
// ============================================================
router.post("/buzz/posts/:postId/comments/:commentId/react", authMiddleware, async (req, res) => {
  try {
    const { postId, commentId } = req.params;
    const { emoji = "❤️" } = req.body || {};
    const myId = req.user.id;

    // 1️⃣ Find post containing comment
    const post = await PostModel.findOne({ id: postId, "comments.id": commentId });
    if (!post) return res.status(404).json({ error: "Post or comment not found" });

    const comment = post.comments.find((c) => c.id === commentId);
    if (!comment) return res.status(404).json({ error: "Comment not found" });

    // 2️⃣ Add or update reaction
    const hadReaction = !!comment.reactions?.[myId];
    if (!comment.reactions) comment.reactions = {};
    comment.reactions[myId] = emoji;
    comment.updatedAt = Date.now();
    await post.save();

    // 3️⃣ Notify comment owner if not self and first time reacting
    if (comment.userId !== myId && !hadReaction) {
      await sendNotification(comment.userId, {
        fromId: myId,
        type: "reaction",
        message: `reacted with ${emoji} to your comment`,
        href: `/buzz/post/${postId}`,
        entity: "comment",
        entityId: commentId,
        postId,
        postOwnerId: post.userId,
      });
    }

    // 4️⃣ Build reaction summary
    const reactionCounts = {};
    Object.values(comment.reactions).forEach((e) => {
      reactionCounts[e] = (reactionCounts[e] || 0) + 1;
    });

    // 5️⃣ Optional live socket event
    if (io && io.to) {
      io.to(String(comment.userId)).emit("comment:react", { postId, commentId, emoji });
    }

    return res.json({
      success: true,
      myReaction: emoji,
      reactionCounts,
      totalReactions: Object.keys(comment.reactions).length,
    });
  } catch (err) {
    console.error("💥 Comment reaction (Mongo) error:", err);
    res.status(500).json({ error: "Failed to react to comment" });
  }
});


// ============================================================
// 💔 Remove reaction from a comment (MongoDB version)
// ============================================================
router.delete("/buzz/posts/:postId/comments/:commentId/react", authMiddleware, async (req, res) => {
  try {
    const { postId, commentId } = req.params;
    const myId = req.user.id;

    // 1️⃣ Locate the post with that comment
    const post = await PostModel.findOne({ id: postId, "comments.id": commentId });
    if (!post) return res.status(404).json({ error: "Post or comment not found" });

    const comment = post.comments.find((c) => c.id === commentId);
    if (!comment) return res.status(404).json({ error: "Comment not found" });

    // 2️⃣ Remove my reaction
    if (comment.reactions && comment.reactions[myId]) {
      delete comment.reactions[myId];
      comment.updatedAt = Date.now();
      await post.save();

      // 🔔 Optionally emit socket event
      if (io && io.to) {
        io.to(String(comment.userId)).emit("comment:reactRemoved", { postId, commentId });
      }
    }

    return res.json({ success: true });
  } catch (err) {
    console.error("💥 Remove reaction (Mongo) error:", err);
    res.status(500).json({ error: "Failed to remove reaction" });
  }
});


// --- Comment Edit ---
router.patch('/posts/:postId/comments/:commentId', authMiddleware, async (req, res) => {
  const { postId, commentId } = req.params;
  const { text } = req.body || {};
  await db.read();

  const me = req.user.id;
  const user = db.data.users.find(u =>
    (u.posts || []).some(p => p.id === postId)
  );
  if (!user) return res.status(404).json({ error: 'Post not found' });

  const post = user.posts.find(p => p.id === postId);
  const comment = post.comments.find(c => c.id === commentId && c.userId === me);
  if (!comment) return res.status(404).json({ error: 'Comment not found or not yours' });

  comment.text = text;
  await db.write();
  
  res.json({
    success: true,
    comment,
    comments: post.comments || [],
  });
});

// --- Comment Delete ---
router.delete('/posts/:postId/comments/:commentId', authMiddleware, async (req, res) => {
  const { postId, commentId } = req.params;
  await db.read();

  const me = req.user.id;
  const user = db.data.users.find(u =>
    (u.posts || []).some(p => p.id === postId)
  );
  if (!user) return res.status(404).json({ error: 'Post not found' });

  const post = user.posts.find(p => p.id === postId);
  const before = post.comments.length;
  post.comments = post.comments.filter(c => !(c.id === commentId && c.userId === me));
  const changed = before !== post.comments.length;
  if (changed) await db.write();

  res.json({ success: changed });
});

/* ============================================================
   💾 LEGACY FETCH ROUTE (from original index.js)
   For backward compatibility with old clients
============================================================ */
router.get("/buzz/posts/:id/comments", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    await db.read();

    // Locate the post
    const post = (db.data.buzz_posts || []).find((p) => p.id === id);
    if (!post) return res.status(404).json({ error: "Post not found" });

    // All comments for this post
    const allComments = (db.data.buzz_comments || []).filter((c) => c.postId === id);
    const viewerId = req.user.id;

    // 🔒 Show comments only if viewer is either:
    // 1. The post owner, OR
    // 2. The comment author
    const visible = allComments.filter((c) => {
      const visibleTo = c.visibleTo || [post.userId, c.userId]; // Fallback for old comments
      return visibleTo.includes(viewerId);
    });

    // Enrich with author info
    const withUser = visible.map((c) => ({
      ...c,
      author: db.data.users.find((u) => u.id === c.userId) || null,
    }));

    res.json({ comments: withUser });
  } catch (err) {
    console.error("Comments fetch error:", err);
    res.status(500).json({ error: "Failed to fetch comments" });
  }
});

module.exports = router;
