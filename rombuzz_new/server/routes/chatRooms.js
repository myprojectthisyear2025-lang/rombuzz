/**
 * ============================================================
 * 📁 File: routes/chatRooms.js
 * 💬 Purpose: Manage realtime chat rooms, persisted messages,
 *             edits, deletions, reactions, and full conversation hide.
 *
 * Endpoints:
 *   GET    /api/chat/rooms/:roomId                → Get chat messages
 *   POST   /api/chat/rooms/:roomId                → Send message
 *   PATCH  /api/chat/rooms/:roomId/:msgId         → Edit message
 *   DELETE /api/chat/rooms/:roomId/:msgId         → Delete message
 *   POST   /api/chat/rooms/:roomId/:msgId/react   → React / unreact
 *   DELETE /api/chat/rooms/:roomId                → Hide all messages for me (merged)
 *
 * Dependencies:
 *   -  models/ChatRoom.js  → Mongoose schema for rooms/messages
 *   - auth-middleware.js  → Token validation
 *   - Socket.IO (io, onlineUsers)
 * ============================================================
 */


const express = require("express");
const router = express.Router();
const shortid = require("shortid");
const authMiddleware = require("../routes/auth-middleware");
const ChatRoom = require("../models/ChatRoom");

// Safely bind socket globals if available
const { io, onlineUsers } = global;

// =======================
// 🧩 Utilities
// =======================

// Parse participants from roomId ("a_b")
function getPeersFromRoomId(roomId) {
  const [a, b] = String(roomId).split("_");
  return { a, b };
}

// Ensure ChatRoom exists or create new
async function getRoomDoc(roomId) {
  let room = await ChatRoom.findOne({ roomId });
  if (!room) {
    const { a, b } = getPeersFromRoomId(roomId);
    room = await ChatRoom.create({
      roomId,
      participants: [a, b],
      messages: [],
    });
  }
  return room;
}

// ============================================================
// 💬 GET CHAT ROOM MESSAGES
// ============================================================
router.get("/chat/rooms/:roomId", authMiddleware, async (req, res) => {
  try {
    const { roomId } = req.params;
    const userId = req.user.id;

    const room = await getRoomDoc(roomId);
    if (!room) return res.status(404).json({ error: "Room not found" });

    // Filter out ephemeral messages
    const keep = [];
    const remove = [];

    for (const msg of room.messages) {
      if (msg.ephemeral?.mode === "once" && msg.from !== userId) {
        remove.push(msg.id);
      } else {
        keep.push(msg);
      }
    }

    // Remove ephemeral messages if needed
    if (remove.length) {
      room.messages = room.messages.filter((m) => !remove.includes(m.id));
      await room.save();
    }

    res.json(keep);
  } catch (err) {
    console.error("❌ GET chat room error:", err);
    res.status(500).json({ error: "Failed to load messages" });
  }
});

// ============================================================
// 📤 SEND MESSAGE
// ============================================================
router.post("/chat/rooms/:roomId", authMiddleware, async (req, res) => {
  try {
    const { roomId } = req.params;
    const { text } = req.body || {};
    if (!text) return res.status(400).json({ error: "text required" });

    const { a, b } = getPeersFromRoomId(roomId);
    if (![a, b].includes(req.user.id))
      return res.status(403).json({ error: "forbidden" });

    const fromId = req.user.id;
    const toId = fromId === a ? b : a;

    const msg = {
      id: shortid.generate(),
      from: fromId,
      to: toId,
      text,
      type: text.startsWith("::RBZ::") ? "media" : "text",
      time: new Date(),
      edited: false,
      deleted: false,
      reactions: {},
      hiddenFor: [],
      ephemeral: { mode: "none" },
    };

    const room = await getRoomDoc(roomId);
    room.messages.push(msg);
    await room.save();

    // Socket events (room + direct)
    io.to(roomId).emit("message", msg);
    const sid = onlineUsers?.[toId];
    if (sid)
      io.to(sid).emit("direct:message", {
        id: msg.id,
        roomId,
        from: fromId,
        to: toId,
        time: msg.time,
        preview: (msg.text || "").slice(0, 80),
        type: msg.type || "text",
      });

    res.json({ message: msg });
  } catch (err) {
    console.error("❌ POST message error:", err);
    res.status(500).json({ error: "Failed to send message" });
  }
});

// ============================================================
// ✍️ EDIT MESSAGE
// ============================================================
router.patch("/chat/rooms/:roomId/:msgId", authMiddleware, async (req, res) => {
  try {
    const { roomId, msgId } = req.params;
    const { text } = req.body || {};
    if (!text) return res.status(400).json({ error: "text required" });

    const room = await getRoomDoc(roomId);
    const msg = room.messages.find((m) => m.id === msgId);
    if (!msg) return res.status(404).json({ error: "not found" });
    if (msg.from !== req.user.id) return res.status(403).json({ error: "not owner" });

    const oneHour = 60 * 60 * 1000;
    if (Date.now() - new Date(msg.time).getTime() > oneHour)
      return res.status(400).json({ error: "edit window expired" });

    msg.text = text;
    msg.edited = true;
    await room.save();

    io.to(roomId).emit("message:edit", { msgId, text });
    res.json({ ok: true });
  } catch (err) {
    console.error("❌ PATCH edit message error:", err);
    res.status(500).json({ error: "Failed to edit message" });
  }
});

// ============================================================
// 🗑️ DELETE / HIDE MESSAGE
// ============================================================
router.delete("/chat/rooms/:roomId/:msgId", authMiddleware, async (req, res) => {
  try {
    const { roomId, msgId } = req.params;
    const { scope = "me" } = req.query;

    const room = await getRoomDoc(roomId);
    const msg = room.messages.find((m) => m.id === msgId);
    if (!msg) return res.status(404).json({ error: "not found" });

    if (scope === "me") {
      if (!msg.hiddenFor.includes(req.user.id)) msg.hiddenFor.push(req.user.id);
      await room.save();
      return res.json({ ok: true });
    }

    if (scope === "all") {
      if (msg.from !== req.user.id) return res.status(403).json({ error: "not owner" });
      msg.deleted = true;
      msg.text = "This message was unsent";
      await room.save();
      io.to(roomId).emit("message:delete", { msgId });
      return res.json({ ok: true });
    }

    res.status(400).json({ error: "invalid scope" });
  } catch (err) {
    console.error("❌ DELETE message error:", err);
    res.status(500).json({ error: "Failed to delete message" });
  }
});

// ============================================================
// 💣 DELETE ENTIRE CONVERSATION
// ============================================================
router.delete("/chat/rooms/:roomId", authMiddleware, async (req, res) => {
  try {
    const { roomId } = req.params;
    const { scope = "me" } = req.query;
    const room = await getRoomDoc(roomId);

    if (!room) return res.status(404).json({ error: "not found" });

    const myId = req.user.id;
    room.messages.forEach((m) => {
      if (!m.hiddenFor.includes(myId)) m.hiddenFor.push(myId);
    });

    await room.save();
    res.json({ ok: true, scope });
  } catch (err) {
    console.error("❌ DELETE conversation error:", err);
    res.status(500).json({ error: "Failed to delete conversation" });
  }
});

// ============================================================
// ❤️ REACTIONS
// ============================================================
router.post("/chat/rooms/:roomId/:msgId/react", authMiddleware, async (req, res) => {
  try {
    const { roomId, msgId } = req.params;
    const { emoji } = req.body || {};
    if (!emoji) return res.status(400).json({ error: "emoji required" });

    const room = await getRoomDoc(roomId);
    const msg = room.messages.find((m) => m.id === msgId);
    if (!msg) return res.status(404).json({ error: "not found" });

    msg.reactions = msg.reactions || {};
    if (msg.reactions.get(req.user.id) === emoji) {
      msg.reactions.delete(req.user.id);
    } else {
      msg.reactions.set(req.user.id, emoji);
    }

    await room.save();

    io.to(roomId).emit("message:react", {
      msgId,
      userId: req.user.id,
      emoji: msg.reactions.get(req.user.id) || null,
    });

    res.json({ ok: true, reactions: Object.fromEntries(msg.reactions) });
  } catch (err) {
    console.error("❌ REACT message error:", err);
    res.status(500).json({ error: "Failed to react" });
  }
});

module.exports = router;

