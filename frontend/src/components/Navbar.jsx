// frontend/src/components/Navbar.jsx
import React, { useEffect, useState, useMemo, useRef } from "react";
import { Link, useNavigate, useLocation } from "react-router-dom";

import {
  FaHeart,
  FaComments,
  FaUser,
  FaSignOutAlt,
  FaBell,
  FaBars,
  FaTimes,
} from "react-icons/fa";
import logo from "../assets/logo.png";
import { getSocket } from "../socket";

const UNREAD_MAP_KEY = "RBZ:unread:map"; // { [senderId]: count }
const UNREAD_TOTAL_KEY = "RBZ:unread:total"; // number

export default function Navbar({ user, setUser }) {
  const [isOpen, setIsOpen] = useState(false);
  const [unread, setUnread] = useState(0);
  const [buzzUnread, setBuzzUnread] = useState(0);
  const [chatUnread, setChatUnread] = useState(() =>
    Number(localStorage.getItem(UNREAD_TOTAL_KEY) || "0")
  );
  const navigate = useNavigate();

  // de-dupe guards
  const processedMessages = useRef(new Set());
  const processedNotifs = useRef(new Set());

  const meId = useMemo(() => (user ? String(user.id || user._id) : null), [user]);

  // Keep badge in sync with Chat page's broadcasts (and restore on refresh)
  useEffect(() => {
    const onChatUnread = (e) => {
      const total = Number(e?.detail?.total || 0);
      setChatUnread(total > 0 ? total : 0);
      localStorage.setItem(UNREAD_TOTAL_KEY, String(total > 0 ? total : 0));
    };
    window.addEventListener("rbz:unread", onChatUnread);

    // Let Notifications page clear navbar badges
    const onClear = () => {
      setUnread(0);
      setBuzzUnread(0);
    };
    window.addEventListener("notifications:clear", onClear);

    return () => {
      window.removeEventListener("rbz:unread", onChatUnread);
      window.removeEventListener("notifications:clear", onClear);
    };
  }, []);

  // ✅ NEW: Listen for global notification events broadcasted from socket.js
  useEffect(() => {
    const handleNewNotification = (e) => {
      const n = e.detail;
      if (!n?.id) return;
      if (processedNotifs.current.has(n.id)) return;
      processedNotifs.current.add(n.id);
      setUnread((x) => x + 1);
      if (n.type === "buzz") setBuzzUnread((b) => b + 1);

      // keep set small
      if (processedNotifs.current.size > 150) {
        const first = processedNotifs.current.values().next().value;
        processedNotifs.current.delete(first);
      }
    };

    window.addEventListener("notification:new", handleNewNotification);
    window.addEventListener("notification:clearBadge", () => {
      setUnread(0);
      setBuzzUnread(0);
    });

    return () => {
      window.removeEventListener("notification:new", handleNewNotification);
      window.removeEventListener("notification:clearBadge", () => {
        setUnread(0);
        setBuzzUnread(0);
      });
    };
  }, []);

  // Open the shared authed socket so we can receive direct pings anywhere in the app
  useEffect(() => {
    if (!user) return;
    const socket = getSocket();

    const onConnect = () => {
      try {
        if (meId) socket.emit("register", meId);
      } catch {}
    };

    socket.on("connect", onConnect);

    // System/buzz notifications with de-dupe
    const onNotif = (n) => {
      if (!n?.id) return;
      if (processedNotifs.current.has(n.id)) return;
      processedNotifs.current.add(n.id);
      setUnread((x) => x + 1);
      if (n.type === "buzz") setBuzzUnread((b) => b + 1);

      // keep set small
      if (processedNotifs.current.size > 150) {
        const first = processedNotifs.current.values().next().value;
        processedNotifs.current.delete(first);
      }
    };

    const handleIncomingMessage = (payload) => {
      const fromId = String(payload?.from || payload?.fromId || payload?.senderId || "");
      if (fromId && fromId === meId) return; // ignore my own
      const toId = String(payload?.to || "");
      if (toId !== meId) return;

      const messageId = payload?.id || `${payload?.roomId}_${payload?.time}`;
      if (processedMessages.current.has(messageId)) return;
      processedMessages.current.add(messageId);

      // persist per-sender unread map
      let map;
      try {
        map = JSON.parse(localStorage.getItem(UNREAD_MAP_KEY) || "{}");
      } catch {
        map = {};
      }
      const senderId = fromId || payload?.from;
      if (senderId) map[senderId] = (map[senderId] || 0) + 1;
      localStorage.setItem(UNREAD_MAP_KEY, JSON.stringify(map));

      const nextTotal = Object.values(map).reduce((a, b) => a + b, 0);
      localStorage.setItem(UNREAD_TOTAL_KEY, String(nextTotal));
      setChatUnread(nextTotal);

      // keep set small
      if (processedMessages.current.size > 300) {
        const first = processedMessages.current.values().next().value;
        processedMessages.current.delete(first);
      }
    };

    // Only the specific events we rely on (avoid duplicates)
    socket.on("direct:message", handleIncomingMessage);
    socket.on("notification", onNotif);

    return () => {
      try {
        socket.off("connect", onConnect);
        socket.off("notification", onNotif);
        socket.off("direct:message", handleIncomingMessage);
      } catch {}
    };
  }, [user, meId]);
// Hide navbar on onboarding/public pages
const location = useLocation();
const hideNavbar = ["/login", "/signup", "/register"].includes(location.pathname);
if (hideNavbar) return null;

if (!user && hideNavbar) return null;

  const handleLogout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    sessionStorage.removeItem("token");
    sessionStorage.removeItem("user");
    localStorage.removeItem(UNREAD_MAP_KEY);
    localStorage.removeItem(UNREAD_TOTAL_KEY);
    setUser(null);
    navigate("/");
  };

  const toggleMenu = () => setIsOpen(!isOpen);

  const links = [
    { name: "Let'sBuzz", path: "/letsbuzz", icon: <FaHeart /> },
    { name: "Chat", path: "/chat", icon: <FaComments /> },
    { name: "Notifications", path: "/notifications", icon: <FaBell /> },
    { name: "Profile", path: "/profile", icon: <FaUser /> },
  ];

  return (
    <nav className="fixed top-0 left-0 w-full z-50 bg-gradient-to-r from-pink-500 via-red-500 to-orange-500 text-white shadow-lg h-16"
          style={{ margin: 0, padding: 0, bottom: "auto" }}

    >
      <div className="max-w-7xl mx-auto flex justify-between items-center px-4 md:px-8 h-full">
        {/* Logo */}
        <Link
          to="/home"
          className="flex items-center gap-2 hover:scale-105 transition-transform duration-300"
        >
          <img
            src={logo}
            alt="Rombuzz Logo"
            className="h-8 w-8 animate-pulse-slow drop-shadow-md"
          />
          <span className="text-2xl font-bold tracking-wide hidden sm:inline bg-gradient-to-r from-yellow-200 to-pink-100 bg-clip-text text-transparent">
            Rombuzz
          </span>
        </Link>

        {/* Desktop Links */}
        <div className="hidden md:flex items-center space-x-8">
          {links.map((link) => {
            const isNotif = link.name === "Notifications";
            const isChat = link.name === "Chat";
            return (
              <Link
                key={link.name}
                to={link.path}
                className="relative flex items-center gap-2 hover:text-yellow-200 font-semibold transition-transform hover:scale-105"
                onClick={() => {
                  if (isNotif) {
                    setUnread(0);
                    setBuzzUnread(0);
                  }
                }}
              >
                <span className="text-lg">{link.icon}</span>
                {link.name}
                {/* Chat badge */}
                {isChat && chatUnread > 0 && (
                  <span className="absolute -top-2 -right-3 min-w-[18px] h-[18px] px-1 rounded-full text-[11px] leading-[18px] text-white bg-rose-600 text-center">
                    {chatUnread > 99 ? "99+" : chatUnread}
                  </span>
                )}
                {/* Notifications badge */}
                {isNotif && (unread > 0 || buzzUnread > 0) && (
                  <span className="absolute -top-2 -right-3 min-w-[18px] h-[18px] px-1 rounded-full text-[11px] leading-[18px] text-white bg-rose-600 text-center">
                    {buzzUnread > 0 ? buzzUnread : unread > 99 ? "99+" : unread}
                  </span>
                )}
              </Link>
            );
          })}

          <button
            onClick={handleLogout}
            className="flex items-center gap-2 bg-white text-red-600 px-4 py-1.5 rounded-lg font-semibold hover:bg-red-100 transition"
          >
            <FaSignOutAlt />
            Signout
          </button>
        </div>

        {/* Mobile Menu Button */}
        <div className="md:hidden">
          <button onClick={toggleMenu} className="focus:outline-none">
            {isOpen ? <FaTimes size={24} /> : <FaBars size={24} />}
          </button>
        </div>
      </div>

      {/* Mobile Dropdown */}
      {isOpen && (
        <div className="md:hidden bg-red-600 text-white flex flex-col space-y-3 px-4 py-4 transition-all duration-300">
          {links.map((link) => {
            const isNotif = link.name === "Notifications";
            const isChat = link.name === "Chat";
            return (
              <Link
                key={link.name}
                to={link.path}
                onClick={() => {
                  setIsOpen(false);
                  if (isNotif) {
                    setUnread(0);
                    setBuzzUnread(0);
                  }
                }}
                className="relative flex items-center gap-3 hover:text-yellow-200 font-semibold"
              >
                <span className="text-lg">{link.icon}</span>
                {link.name}
                {isChat && chatUnread > 0 && (
                  <span className="absolute -top-2 -right-3 min-w-[18px] h-[18px] px-1 rounded-full text-[11px] leading-[18px] text-white bg-rose-600 text-center">
                    {chatUnread > 99 ? "99+" : chatUnread}
                  </span>
                )}
                {isNotif && (unread > 0 || buzzUnread > 0) && (
                  <span className="absolute -top-2 -right-3 min-w-[18px] h-[18px] px-1 rounded-full text-[11px] leading-[18px] text-white bg-rose-600 text-center">
                    {buzzUnread > 0 ? buzzUnread : unread > 99 ? "99+" : unread}
                  </span>
                )}
              </Link>
            );
          })}

          <button
            onClick={() => {
              setIsOpen(false);
              handleLogout();
            }}
            className="flex items-center gap-2 bg-white text-red-600 px-4 py-1.5 rounded-lg font-semibold hover:bg-red-100 transition"
          >
            <FaSignOutAlt />
            Signout
          </button>
        </div>
      )}
    </nav>
  );
}

// Add slow pulse animation for logo
const style = document.createElement("style");
style.innerHTML = `
@keyframes pulse-slow {
  0%, 100% { transform: scale(1); filter: drop-shadow(0 0 0px rgba(255,255,255,0.5)); }
  50% { transform: scale(1.08); filter: drop-shadow(0 0 8px rgba(255,255,255,0.8)); }
}
.animate-pulse-slow {
  animation: pulse-slow 2.5s infinite ease-in-out;
}
`;
document.head.appendChild(style);
