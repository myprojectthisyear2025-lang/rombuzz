/**
 * ============================================================
 * 📁 File: routes/notifications.js
 * 💬 Purpose: Handle all user notifications (MongoDB version)
 *
 * Endpoints:
 *   GET    /api/notifications              → Fetch all notifications
 *   PATCH  /api/notifications/:id/read     → Mark as read
 *   DELETE /api/notifications/:id          → Delete notification
 *   POST   /api/notifications/wingman      → Create AI Wingman message
 *   POST   /api/notifications/block/:userId→ Block user's notifications
 *
 * Notes:
 *   - Fully MongoDB-based, backward-compatible with old LowDB logic.
 *   - Real-time Socket.IO support retained.
 * ============================================================
 */

const express = require("express");
const router = express.Router();
const shortid = require("shortid");
const Notification = require("../models/Notification");
const authMiddleware = require("./auth-middleware");

// Import globals (Socket.IO)
const { io, onlineUsers } = global;

// ============================================================
// ✅ GET all notifications for current user
// ============================================================
router.get("/", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const notifs = await Notification.find({ toId: userId })
      .sort({ createdAt: -1 })
      .lean();

    // enrich with hrefs
    const enrich = (n) => {
      if (n.href?.startsWith("/")) return n;
      const out = { ...n };
      switch (n.type) {
        case "wingman":
          out.href = "/discover";
          break;
        case "match":
        case "buzz":
        case "like":
          if (n.fromId) out.href = `/viewprofile/${n.fromId}`;
          break;
        case "comment":
        case "reaction":
        case "new_post":
        case "share": {
          const postId = n.postId || n.entityId;
          const ownerId = n.postOwnerId || n.ownerId || n.fromId;
          if (postId && ownerId)
            out.href = `/viewprofile/${ownerId}?post=${postId}`;
          else if (n.fromId) out.href = `/viewprofile/${n.fromId}`;
          break;
        }
        default:
          out.href = "/notifications";
      }
      return out;
    };

    res.json(notifs.map(enrich));
  } catch (err) {
    console.error("❌ GET /notifications error:", err);
    res.status(500).json({ error: "Failed to fetch notifications" });
  }
});

// ============================================================
// ✅ PATCH → mark as read
// ============================================================
router.patch("/:id/read", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const notif = await Notification.findOne({ id: req.params.id, toId: userId });
    if (!notif) return res.status(404).json({ error: "Notification not found" });

    notif.read = true;
    await notif.save();

    res.json({ success: true, id: notif.id });
  } catch (err) {
    console.error("❌ PATCH /notifications/:id/read error:", err);
    res.status(500).json({ error: "Failed to mark as read" });
  }
});

// ============================================================
// ✅ DELETE → remove a notification
// ============================================================
router.delete("/:id", authMiddleware, async (req, res) => {
  try {
    await Notification.deleteOne({ id: req.params.id, toId: req.user.id });
    res.json({ success: true });
  } catch (err) {
    console.error("❌ DELETE /notifications/:id error:", err);
    res.status(500).json({ error: "Failed to delete notification" });
  }
});

// ============================================================
// ✅ POST → block another user's notifications (still LowDB for now)
// ============================================================
const { db } = require("../models/db.lowdb");
router.post("/block/:userId", authMiddleware, async (req, res) => {
  await db.read();
  const uid = req.user.id;
  db.data.blocks ||= [];
  const exists = db.data.blocks.find(
    (b) => b.blocker === uid && b.blocked === req.params.userId
  );
  if (!exists) {
    db.data.blocks.push({ blocker: uid, blocked: req.params.userId });
    await db.write();
  }
  res.json({ success: true });
});

// ============================================================
// ✅ POST → AI Wingman message generator (Mongo + sockets)
// ============================================================
router.post("/wingman", authMiddleware, async (req, res) => {
  try {
    const { message } = req.body;
    const toId = req.user.id;

    const notif = await Notification.create({
      id: shortid.generate(),
      toId,
      fromId: "system",
      type: "wingman",
      message: message || "Your AI Wingman has something for you 💡",
      href: "/letsbuzz",
      createdAt: Date.now(),
      read: false,
    });

    if (io && onlineUsers?.[toId]) {
      io.to(onlineUsers[toId]).emit("notification", notif);
    }

    console.log("🤖 AI Wingman →", toId, notif.message);
    res.json({ success: true, message: "Wingman notification sent", notif });
  } catch (err) {
    console.error("❌ POST /notifications/wingman error:", err);
    res.status(500).json({ error: "Failed to create Wingman notification" });
  }
});

module.exports = router;
