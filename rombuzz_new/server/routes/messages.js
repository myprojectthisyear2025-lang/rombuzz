/**
 * ============================================================
 * 📁 File: routes/messages.js
 * 🧩 Purpose: Handle direct messages between users (MongoDB version)
 *
 * Endpoints:
 *   POST /api/messages           → Send new message (text/photo/video)
 *   GET  /api/messages           → Fetch conversation between two users
 *   POST /api/messages/viewed    → Auto-delete "view-once" messages
 *
 * Features:
 *   - Real-time delivery via Socket.IO
 *   - Supports ephemeral "once" messages
 *   - Blocks users if either side blocked the other
 *   - Validates match relationship before opening chat
 *
 * Dependencies:
 *   - models/Message.js       → MongoDB schema
 *   - models/User.js          → For existence checks
 *   - models/Match.js         → For chat permission
 *   - auth-middleware.js      → JWT validation
 *   - utils/helpers.js        → isBlocked()
 *   - io, onlineUsers         → from global context
 * ============================================================
 */

const express = require("express");
const router = express.Router();
const shortid = require("shortid");
const authMiddleware = require("../routes/auth-middleware");
const { isBlocked } = require("../utils/helpers");
const Message = require("../models/Message");
const User = require("../models/User");
const Match = require("../models/Match");
const { io, onlineUsers } = global;

/* ============================================================
   📩 SEND NEW MESSAGE
============================================================ */
router.post("/", authMiddleware, async (req, res) => {
  try {
    const { to, text, type, url, ephemeral } = req.body || {};
    const from = req.user.id;

    if (!to) return res.status(400).json({ error: "recipient required" });
    if (!text && !url)
      return res.status(400).json({ error: "either text or media url required" });

    // 🚫 Block check
    if (isBlocked(from, to))
      return res.status(403).json({ error: "blocked" });

    // 🧠 Validate user existence
    const exists = await User.findOne({ id: to });
    if (!exists) return res.status(404).json({ error: "recipient not found" });

    // 💬 Create and store message
    const msgType = type || (url ? "photo" : "text");
    const msg = await Message.create({
      id: shortid.generate(),
      from,
      to,
      text: text || "",
      type: msgType,
      url: url || null,
      ephemeral: ephemeral || "keep",
      createdAt: new Date(),
    });

    // 📨 Live delivery via Socket.IO
    const receiverSocket = onlineUsers[to];
    if (receiverSocket) {
      io.to(receiverSocket).emit("message", msg);
      io.to(String(to)).emit("direct:message", {
        id: msg.id,
        roomId: [String(msg.from), String(msg.to)].sort().join("_"),
        from: msg.from,
        to: msg.to,
        time: new Date(msg.createdAt).toISOString(),
        preview: (msg.text || "").slice(0, 80),
        type: "text",
      });
    }

    // ✅ Delivery acknowledgment to sender
    const senderSocket = onlineUsers[from];
    if (senderSocket) {
      io.to(senderSocket).emit("message:delivered", {
        id: msg.id,
        to: msg.to,
        time: msg.createdAt,
      });
    }

    res.json({ message: msg });
  } catch (err) {
    console.error("❌ Message send error:", err);
    res.status(500).json({ error: "failed to send message" });
  }
});

/* ============================================================
   💬 FETCH CONVERSATION
============================================================ */
router.get("/", authMiddleware, async (req, res) => {
  try {
    const { user1, user2 } = req.query;
    const self = req.user.id;

    if (!user1 || !user2)
      return res.status(400).json({ error: "user1 & user2 required" });
    if (![user1, user2].includes(self))
      return res.status(403).json({ error: "forbidden" });
    if (isBlocked(user1, user2))
      return res.status(403).json({ error: "blocked" });

    // ✅ Check if matched
    const matched = await Match.exists({ users: { $all: [user1, user2] } });
    if (!matched)
      return res.status(403).json({ error: "No match yet" });

    // ✅ Fetch conversation (sorted oldest→newest)
    const convo = await Message.find({
      $or: [
        { from: user1, to: user2 },
        { from: user2, to: user1 },
      ],
    })
      .sort({ createdAt: 1 })
      .lean();

    res.json({
      messages: convo.map((m) => ({
        id: m.id,
        from: m.from,
        to: m.to,
        text: m.text || "",
        type: m.type || "text",
        url: m.url || null,
        ephemeral: m.ephemeral || "keep",
        createdAt: m.createdAt,
      })),
    });
  } catch (err) {
    console.error("❌ Fetch conversation error:", err);
    res.status(500).json({ error: "failed to load conversation" });
  }
});

/* ============================================================
   🔥 AUTO-DELETE VIEW-ONCE MESSAGES
============================================================ */
router.post("/viewed", authMiddleware, async (req, res) => {
  try {
    const { messageId } = req.body || {};
    if (!messageId)
      return res.status(400).json({ error: "messageId required" });

    const msg = await Message.findOne({ id: messageId });
    if (!msg)
      return res.status(404).json({ error: "Message not found" });

    if (msg.ephemeral === "once") {
      await Message.deleteOne({ id: messageId });
      console.log(`🗑️ View-once message deleted: ${messageId}`);

      // Notify both users about deletion
      const socketTo = onlineUsers[msg.to];
      const socketFrom = onlineUsers[msg.from];
      if (socketTo)
        io.to(socketTo).emit("message:removed", { id: messageId });
      if (socketFrom)
        io.to(socketFrom).emit("message:removed", { id: messageId });
    }

    res.json({ success: true });
  } catch (err) {
    console.error("Auto-delete error:", err);
    res.status(500).json({ error: "server error" });
  }
});

module.exports = router;
