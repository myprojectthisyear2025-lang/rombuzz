/**
 * ============================================================
 * 📁 File: routes/buzzpost/buzz.media.js
 * 💬 Purpose: Manage all profile media actions (react, comment,
 *             privacy toggle, delete) for user galleries.
 *
 * Description:
 *   - Handles photos, videos, voice, and reels from user.media[].
 *   - Allows matched users to react ❤️ or comment 💬.
 *   - Owner can toggle privacy or delete items.
 *   - Used across ViewProfile.jsx and MyBuzz.jsx.
 *
 * Endpoints:
 *   POST   /api/media/:ownerId/react     → React / unreact to media
 *   POST   /api/media/:ownerId/comment   → Add comment to media
 *   PATCH  /api/media/:id/privacy        → Toggle privacy
 *   DELETE /api/media/:id                → Delete media
 *
 * Dependencies:
 *   - auth-middleware.js
 *   - models/User.js
 *   - models/db.lowdb.js  (temporary fallback)
 *   - utils/helpers.js → sendNotification()
 * ============================================================
 */

const express = require("express");
const router = express.Router();
const shortid = require("shortid");
const authMiddleware = require("../auth-middleware");
const { db } = require("../../models/db.lowdb");
const User = require("../../models/User");
const { sendNotification } = require("../../utils/helpers");

// =======================================================
// ✅ React / unreact to a media item
// =======================================================
router.post("/media/:ownerId/react", authMiddleware, async (req, res) => {
  try {
    const me = req.user.id;
    const { ownerId } = req.params;
    const { mediaId, emoji = "❤️" } = req.body || {};
    if (!mediaId) return res.status(400).json({ error: "mediaId required" });

    await db.read();
    const owner = db.data.users.find((u) => u.id === ownerId);
    if (!owner) return res.status(404).json({ error: "owner not found" });

    const media = (owner.media || []).find((m) => m.id === mediaId);
    if (!media) return res.status(404).json({ error: "media not found" });

    media.reactions = media.reactions || {}; // { userId: "❤️" }

    // Toggle same emoji (like/unlike)
    if (media.reactions[me] === emoji) delete media.reactions[me];
    else media.reactions[me] = emoji;

    await db.write();

    // Compute counts by emoji
    const counts = {};
    for (const e of Object.values(media.reactions))
      counts[e] = (counts[e] || 0) + 1;

    // 🔔 Notify owner if not self
    if (owner.id !== me && emoji) {
      const reactor = db.data.users.find((u) => u.id === me);
      await sendNotification(owner.id, {
        fromId: me,
        type: "media_reaction",
        message: `${reactor?.firstName || "Someone"} reacted ${emoji} to your photo.`,
        entity: "media",
        entityId: mediaId,
        postOwnerId: owner.id,
      });
    }

    res.json({
      ok: true,
      counts,
      mine: media.reactions[me] || null,
    });
  } catch (err) {
    console.error("❌ /media/:ownerId/react error:", err);
    res.status(500).json({ error: "Reaction failed" });
  }
});

// =======================================================
// ✅ Comment on a media item
// =======================================================
router.post("/media/:ownerId/comment", authMiddleware, async (req, res) => {
  try {
    const me = req.user.id;
    const { ownerId } = req.params;
    const { mediaId, text } = req.body || {};
    if (!mediaId || !text)
      return res.status(400).json({ error: "mediaId & text required" });

    await db.read();
    const owner = db.data.users.find((u) => u.id === ownerId);
    if (!owner) return res.status(404).json({ error: "owner not found" });

    const media = (owner.media || []).find((m) => m.id === mediaId);
    if (!media) return res.status(404).json({ error: "media not found" });

    media.comments = media.comments || [];
    const comment = {
      id: shortid.generate(),
      userId: me,
      text: text.trim(),
      createdAt: Date.now(),
    };
    media.comments.push(comment);
    await db.write();

    // 🔔 Notify owner
    if (owner.id !== me) {
      const commenter = db.data.users.find((u) => u.id === me);
      await sendNotification(owner.id, {
        fromId: me,
        type: "media_comment",
        message: `${commenter?.firstName || "Someone"} commented on your photo 💬`,
        entity: "media",
        entityId: mediaId,
        postOwnerId: owner.id,
      });
    }

    res.json({ ok: true, comment });
  } catch (err) {
    console.error("❌ /media/:ownerId/comment error:", err);
    res.status(500).json({ error: "Failed to comment" });
  }
});

// =======================================================
// ✅ Toggle media privacy
// =======================================================
router.patch("/media/:id/privacy", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { privacy } = req.body || {};
    const me = req.user.id;

    await db.read();
    const user = db.data.users.find((u) => u.id === me);
    if (!user) return res.status(404).json({ error: "User not found" });

    const media = user.media.find((m) => m.id === id);
    if (!media) return res.status(404).json({ error: "Media not found" });

    media.privacy = privacy || (media.privacy === "private" ? "public" : "private");
    await db.write();

    res.json({ success: true, media });
  } catch (err) {
    console.error("❌ PATCH /media/:id/privacy error:", err);
    res.status(500).json({ error: "Failed to update privacy" });
  }
});

// =======================================================
// ✅ Delete media
// =======================================================
router.delete("/media/:id", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const me = req.user.id;

    await db.read();
    const user = db.data.users.find((u) => u.id === me);
    if (!user) return res.status(404).json({ error: "User not found" });

    const before = user.media.length;
    user.media = user.media.filter((m) => m.id !== id);
    const changed = before !== user.media.length;
    if (changed) await db.write();

    res.json({ success: changed });
  } catch (err) {
    console.error("❌ DELETE /media/:id error:", err);
    res.status(500).json({ error: "Failed to delete media" });
  }
});

module.exports = router;
