/**
 * ============================================================
 * 📁 File: sockets/meetSocket.js
 * ⚡ Purpose: Manage realtime Meet-in-Middle & presence events
 *             through Socket.IO (location sharing, buzz popups,
 *             meet requests, and live status updates).
 *
 * Events:
 *   user:register / register         → Track active socket users
 *   meet:request / accept / decline  → Coordinate meet flow
 *   meet:chosen                      → Notify both users of selected venue
 *   buzz_request                     → Handle MicroBuzz live pop-ups
 *
 * Dependencies:
 *   - db.lowdb.js
 *   - global.onlineUsers map
 *   - node-fetch (for calling /api/meet-suggest)
 * ============================================================
 */

const fetch = require("node-fetch");
const db = require("../db");

function registerMeetSockets(io) {
  io.on("connection", (socket) => {
    console.log("⚡ meet-user connected:", socket.id);

    // ✅ Ensure global online user map exists
    global.onlineUsers = global.onlineUsers || {};

    /* ============================================================
       👤 USER REGISTRATION & PRESENCE
    ============================================================ */

    // Modern clients register with `user:register`
    socket.on("user:register", (userId) => {
      if (!userId) return;

      // Track socket ID for this user
      onlineUsers[userId] = socket.id;
      socket.userId = String(userId);

      // Join personal room so `io.to(userId)` works everywhere
      socket.join(String(userId));

      console.log("✅ Registered user:", userId, "→", socket.id);
    });

    // 🧩 Legacy fallback for older clients still using `register`
    socket.on("register", (userId) => {
      if (!userId) return;
      onlineUsers[userId] = socket.id;
      socket.userId = String(userId);
      socket.join(String(userId));

      console.log("✅ Legacy register:", userId, "→", socket.id);

      // Broadcast online presence globally
      io.emit("presence:online", { userId });
    });

    // 🧹 Clean disconnect handler
    socket.on("disconnect", () => {
      const userId = socket.userId;
      if (userId && onlineUsers[userId]) {
        delete onlineUsers[userId];
        io.emit("presence:offline", { userId });
        console.log("❌ Disconnected:", userId);
      }
    });

    /* ============================================================
       💌 MICROBUZZ — Real-time Nearby Buzz Request
    ============================================================ */
    socket.on("buzz_request", ({ toId, fromId, selfieUrl, name, message }) => {
      if (!toId || !fromId) return;

      // Relay the live buzz popup only if target is online
      if (onlineUsers[toId]) {
        io.to(String(toId)).emit("buzz_request", {
          fromId,
          selfieUrl,
          name,
          message: message || "Someone nearby buzzed you!",
          type: "microbuzz",
        });
        console.log(`📡 buzz_request ${fromId} → ${toId}`);
      }
    });

    /* ============================================================
       💞 MEET-IN-MIDDLE — Realtime Coordination
    ============================================================ */

    // 🔔 Step 1: Send Meet Request
    socket.on("meet:request", async ({ from, to }) => {
      try {
        if (!from || !to) return;
        await db.read();

        const sender =
          db.data.users.find((u) => String(u.id) === String(from)) || { id: from };

        const sid = onlineUsers[to];
        if (sid) {
          io.to(sid).emit("meet:request", { from: sender });
          console.log(`📨 meet:request ${from} → ${to}`);
        }
      } catch (e) {
        console.error("meet:request error", e);
      }
    });

    // 📍 Step 2: Accept Meet & Share Location
    socket.on("meet:accept", async ({ from, to, coords }) => {
      try {
        if (!from || !to || !coords) return;

        await db.read();
        const me = db.data.users.find((u) => String(u.id) === String(from));
        const you = db.data.users.find((u) => String(u.id) === String(to));
        if (!me || !you) return;

        // Save latest location for sender
        me.location = { lat: Number(coords.lat), lng: Number(coords.lng) };
        await db.write();

        // If the other user hasn't shared yet → send mine and wait
        if (!you.location?.lat || !you.location?.lng) {
          const sid = onlineUsers[to];
          if (sid)
            io.to(sid).emit("meet:accept", { from, coords: me.location });
          return;
        }

        // Both shared → Fetch midpoint & nearby places (Google or fallback)
        const resp = await fetch("http://localhost:4000/api/meet-suggest", {
          method: "GET",
          headers: { "Content-Type": "application/json" },
        }).catch(() => null);

        const data = resp ? await resp.json().catch(() => ({})) : {};
        const places = Array.isArray(data.places) ? data.places : [];

        // Build payload for both users
        const payload = {
          from: {
            id: me.id,
            firstName: me.firstName,
            lastName: me.lastName,
          },
          midpoint: {
            lat: (me.location.lat + you.location.lat) / 2,
            lng: (me.location.lng + you.location.lng) / 2,
          },
          places,
        };

        // Notify both participants simultaneously
        [me.id, you.id].forEach((id) => {
          const sid = onlineUsers[id];
          if (sid) io.to(sid).emit("meet:suggest", payload);
        });

        console.log(`📍 meet:suggest → ${me.id}, ${you.id}`);
      } catch (e) {
        console.error("meet:accept error", e);
      }
    });

    // 🚫 Step 3: Decline Meet Request
    socket.on("meet:decline", ({ from, to }) => {
      const sid = onlineUsers[to];
      if (sid) io.to(sid).emit("meet:decline", { from: { id: from } });
      console.log(`❌ meet:decline ${from} → ${to}`);
    });

    // 🏠 Step 4: Confirm Chosen Place
    socket.on("meet:chosen", ({ from, to, place }) => {
      const sid = onlineUsers[to];
      if (sid)
        io.to(sid).emit("meet:place:selected", { from: { id: from }, place });
      console.log(`🏠 meet:chosen ${from} → ${to} (${place?.name || "?"})`);
    });
  });
}

module.exports = { registerMeetSockets };
