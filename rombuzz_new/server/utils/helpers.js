/**
 * ================================================================
 * 📁 File: utils/helpers.js
 * 🧩 Purpose:
 *   Centralized reusable utility functions for the RomBuzz backend.
 *
 *   Includes:
 *   - User data sanitization
 *   - Block check
 *   - Time + distance utilities
 *   - Chat room persistence
 *   - Match streak increment
 *   - Notification dispatcher (MongoDB + Socket.io hybrid)
 *
 * ⚙️ Updated:
 *   Added `sendNotification()` — uses MongoDB Notification model,
 *   falls back to LowDB if Mongo is unavailable, and emits
 *   real-time events via Socket.IO (global.io).
 *
 *   © 2025 RomBuzz (Neptrixx Technologies)
 * ================================================================
 */

const shortid = require("shortid");
const { db } = require("../models/db.lowdb");
const Notification = require("../models/Notification");

const THIRTY_DAYS = 30 * 24 * 60 * 60 * 1000; // constant: 30 days in ms

// Access globals safely
const { io, onlineUsers } = global || {};

// ============================================================
// 🔔 sendNotification()
// ------------------------------------------------------------
// Unified MongoDB + LowDB + Socket notification dispatcher.
// All modules (buzzPosts, matches, chat, etc.) can call this.
// ============================================================
async function sendNotification(toId, data = {}) {
  const notif = {
    id: shortid.generate(),
    toId,
    fromId: data.fromId || "",
    type: data.type || "system",
    message: data.message || "",
    href: data.href || "",
    entity: data.entity || "",
    entityId: data.entityId || "",
    postId: data.postId || "",
    postOwnerId: data.postOwnerId || "",
    createdAt: Date.now(),
    read: false,
  };

  try {
    // ✅ Primary storage: MongoDB
    const mongoNotif = await Notification.create(notif);

    // 🔔 Real-time socket emit
    if (io && onlineUsers && onlineUsers[toId]) {
      io.to(onlineUsers[toId]).emit("notification", mongoNotif);
    }

    console.log(`🔔 Notification (Mongo) → ${toId}: ${notif.message}`);
    return mongoNotif;
  } catch (err) {
    console.error("⚠️ MongoDB notification failed, falling back:", err.message);

    // ⚙️ Fallback to LowDB (temporary compatibility)
    try {
      await db.read();
      db.data.notifications ||= [];
      db.data.notifications.push(notif);
      await db.write();

      if (io && onlineUsers && onlineUsers[toId]) {
        io.to(onlineUsers[toId]).emit("notification", notif);
      }

      console.log(`🔔 Notification (LowDB fallback) → ${toId}: ${notif.message}`);
      return notif;
    } catch (fallbackErr) {
      console.error("❌ Notification failed completely:", fallbackErr);
      return null;
    }
  }
}

/* ============================================================
   🧼 baseSanitizeUser(user)
============================================================ */
function baseSanitizeUser(user) {
  if (!user) return null;
  const { passwordHash, emailVerificationCode, pendingEmailChange, ...safe } = user;
  return {
    ...safe,
    profileComplete: user.profileComplete || false,
  };
}

/* ============================================================
   🚫 isBlocked(db, user1, user2)
============================================================ */
function isBlocked(db, user1, user2) {
  if (!db.data.blocks) return false;
  return db.data.blocks.some(
    (b) =>
      (b.blocker === user1 && b.blocked === user2) ||
      (b.blocker === user2 && b.blocked === user1)
  );
}

/* ============================================================
   ⏱️ msToDays(ms)
============================================================ */
function msToDays(ms) {
  return Math.ceil(ms / (24 * 60 * 60 * 1000));
}

/* ============================================================
   📏 distanceKm(loc1, loc2)
============================================================ */
function distanceKm(loc1, loc2) {
  if (!loc1 || !loc2) return 0;
  const R = 6371; // Earth radius in km
  const dLat = ((loc2.lat - loc1.lat) * Math.PI) / 180;
  const dLon = ((loc2.lng - loc1.lng) * Math.PI) / 180;
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos((loc1.lat * Math.PI) / 180) *
      Math.cos((loc2.lat * Math.PI) / 180) *
      Math.sin(dLon / 2) ** 2;
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

/* ============================================================
   💬 getRoomDoc(db, roomId)
============================================================ */
async function getRoomDoc(db, roomId) {
  await db.read();
  db.data.roomMessages = db.data.roomMessages || [];

  let doc = db.data.roomMessages.find((r) => r.roomId === roomId);
  if (!doc) {
    doc = { roomId, list: [] };
    db.data.roomMessages.push(doc);
    await db.write();
  }
  return doc;
}

/* ============================================================
   🔥 incMatchStreakOut(dbData, fromId, toId)
============================================================ */
function incMatchStreakOut(dbData, fromId, toId) {
  dbData.matchStreaks = dbData.matchStreaks || {};
  const key = `${String(fromId)}_${String(toId)}`;

  let s = dbData.matchStreaks[key];
  if (!s) {
    s = dbData.matchStreaks[key] = {
      from: String(fromId),
      to: String(toId),
      count: 0,
      lastBuzz: null,
      createdAt: Date.now(),
    };
  }

  s.count = Number(s.count || 0) + 1;
  s.lastBuzz = Date.now();
  return s;
}

// ============================================================
// 📦 Exports
// ============================================================
module.exports = {
  sendNotification,
  baseSanitizeUser,
  isBlocked,
  msToDays,
  distanceKm,
  getRoomDoc,
  incMatchStreakOut,
  THIRTY_DAYS,
};
