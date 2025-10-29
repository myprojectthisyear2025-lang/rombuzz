// src/socket.js
import { io } from "socket.io-client";

//const SOCKET_URL = "http://localhost:4000";
const SOCKET_URL = process.env.REACT_APP_SOCKET_URL || "https://rombuzz-api.onrender.com";

// Single socket instance (reused everywhere)
let socket = null;

function getToken() {
  return (
    localStorage.getItem("token") ||
    sessionStorage.getItem("token") ||
    ""
  );
}

function getUser() {
  try {
    return (
      JSON.parse(localStorage.getItem("user")) ||
      JSON.parse(sessionStorage.getItem("user")) ||
      null
    );
  } catch {
    return null;
  }
}

/**
 * Ensure one authenticated socket connection for the whole app.
 * Safe to call many times; it reuses the same instance.
 */
export function ensureSocketAuth() {
  const token = getToken();

  if (!socket) {
    socket = io(SOCKET_URL, {
      auth: { token },
      transports: ["websocket"],
      autoConnect: true,
      reconnection: true,
      reconnectionAttempts: 9999,
      reconnectionDelay: 1000,
    });

    // Optional (your server supports both auth + register)
   // ✅ Identify user on connect (for Meet-in-Middle + chat)
socket.on("connect", () => {
  const u = getUser();
  if (u?.id || u?._id) {
    socket.emit("user:register", u.id || u._id);
    console.log("🧠 user:register sent for", u.id || u._id);
  }
});


    // Debug + global handlers
    socket.on("connect_error", (e) =>
      console.warn("SOCKET connect_error:", e?.message)
    );
    socket.on("disconnect", (r) => console.log("SOCKET disconnected:", r));

    // ✅ Global real-time notifications listener
    socket.on("notification", (notif) => {
      console.log("🔔 Global notification received:", notif);

      // --- optional: cache for later ---
      try {
        const key = "RBZ:pending:notifications";
        const existing = JSON.parse(localStorage.getItem(key) || "[]");
        existing.unshift(notif);
        localStorage.setItem(key, JSON.stringify(existing));
      } catch {}

      // --- dispatch a DOM event so any page (Navbar, Notifications.jsx) can react ---
      window.dispatchEvent(new CustomEvent("notification:new", { detail: notif }));
    });
// ✅ Real-time comments listener
socket.on("comment:new", (payload) => {
  console.log("💬 comment:new received:", payload);
  // broadcast globally so any open CommentsDrawer can update instantly
  window.dispatchEvent(new CustomEvent("comment:new", { detail: payload }));
});

    // 💞 Meet-in-Middle realtime handlers
    socket.on("meet:request", ({ from }) => {
      console.log("📍 meet:request from", from);
      window.dispatchEvent(new CustomEvent("meet:request", { detail: from }));
    });
    socket.on("meet:accept", (data) => {
      console.log("📍 meet:accept", data);
      window.dispatchEvent(new CustomEvent("meet:accept", { detail: data }));
    });
    socket.on("meet:suggest", (data) => {
      console.log("📍 meet:suggest places", data);
      window.dispatchEvent(new CustomEvent("meet:suggest", { detail: data }));
    });
    socket.on("meet:place:selected", (data) => {
      console.log("📍 meet:place:selected", data);
      window.dispatchEvent(new CustomEvent("meet:place:selected", { detail: data }));
    });

    // ✅ NEW: direct message event (for chat + navbar badges)
    socket.on("direct:message", (msg) => {
      console.log("💬 direct:message received:", msg);

      // 🔔 Broadcast globally so Navbar, Chat.jsx, etc. can update badges
      window.dispatchEvent(new CustomEvent("direct:message", { detail: msg }));

      // --- optional: sound or vibration (if enabled) ---
      try {
        const play = localStorage.getItem("RBZ:GLOBAL:msgSound");
        if (play === "true") {
          const ding = new Audio("data:audio/mp3;base64,//uQZAAAAAAAAAAAA");
          ding.play().catch(() => {});
        }
      } catch {}
    });

      // ✅ Optional badge reset listener
    window.addEventListener("notifications:clear", () => {
      window.dispatchEvent(new CustomEvent("notification:clearBadge"));
    });

       // =======================================================
    // 📞 LIVE CALL EVENTS (voice / video)
    // =======================================================
    socket.on("call:offer", (data) => {
      console.log("📞 call:offer", data);
      window.dispatchEvent(new CustomEvent("call:offer", { detail: data }));
    });

    socket.on("call:answer", (data) => {
      console.log("📞 call:answer", data);
      window.dispatchEvent(new CustomEvent("call:answer", { detail: data }));
    });

    socket.on("call:signal", (data) => {
      console.log("📡 call:signal", data);
      window.dispatchEvent(new CustomEvent("call:signal", { detail: data }));
    });

    socket.on("call:end", (data) => {
      console.log("📞 call:end", data);
      window.dispatchEvent(new CustomEvent("call:end", { detail: data }));
    });


  } else {
    // If token changed (login/logout), update and reconnect
    if (socket.auth?.token !== token) {
      socket.auth = { token };
      try {
        socket.disconnect();
      } catch {}
      socket.connect();
    }
  }

  return socket;
}

export function getSocket() {
  return socket || ensureSocketAuth();
}
