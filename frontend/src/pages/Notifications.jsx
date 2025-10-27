// src/pages/Notifications.jsx
import React, { useEffect, useState, useMemo, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { formatDistanceToNow } from "date-fns";
import {
  FaHeart,
  FaComments,
  FaBell,
  FaRobot,
  FaHandshake,
  FaUser,
  FaEllipsisV,
  FaTrash,
  FaBan,
} from "react-icons/fa";
import { ensureSocketAuth } from "../socket";

//const API_BASE = "http://localhost:4000/api";
const API_BASE = "http://localhost:4000/api";

export default function Notifications() {
  const [notifications, setNotifications] = useState([]);
  const [loading, setLoading] = useState(true);
  const [menuOpen, setMenuOpen] = useState(null);
  const [filter, setFilter] = useState("all");
  const [buzzLoading, setBuzzLoading] = useState({});
  const [buzzSent, setBuzzSent] = useState({});
  const navigate = useNavigate();

  const token =
    localStorage.getItem("token") || sessionStorage.getItem("token");

  // 💡 dedupe guard for live events (avoid double inserts)
  const seenIds = useRef(new Set());

  // ---------- Fetch on mount ----------
  useEffect(() => {
    const fetchAll = async () => {
      try {
        const res = await fetch(`${API_BASE}/notifications`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        const data = await res.json();
        if (Array.isArray(data)) {
          data.forEach((n) => seenIds.current.add(n.id));
          setNotifications(
            data.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
          );
        }
      } catch (err) {
        console.error("Fetch notifications failed:", err);
      } finally {
        setLoading(false);
      }
    };
    if (token) fetchAll();
  }, [token]);

  // ---------- Live updates (singleton) ----------
  useEffect(() => {
    if (!token) return;
    const socket = ensureSocketAuth();

    // Clear navbar badge now that this page is open
    window.dispatchEvent(new Event("notifications:clear"));

    const onNotif = (n) => {
      // client-side de-dupe by id
      if (!n?.id) return;
      if (seenIds.current.has(n.id)) return;
      seenIds.current.add(n.id);
      setNotifications((prev) => [n, ...prev]);
    };

    socket.on("notification", onNotif);
    return () => {
      try {
        socket.off("notification", onNotif);
      } catch {}
    };
  }, [token]);

  // ---------- Normalize app routes (stay in-app, avoid homepage) ----------
  const normalizeHref = (raw) => {
    if (!raw) return null;
    try {
      // allow absolute or relative; strip origin if absolute
      const url = new URL(raw, window.location.origin);
      let p = (url.pathname + url.search + url.hash) || "/";

      // normalize to your actual routes (lowercase)
      // backend may send /viewprofile or /viewProfile; we force lowercase
      p = p
        .replace(/^\/viewprofile/i, "/viewprofile")
        .replace(/^\/letsbuzz/i, "/letsbuzz")
        .replace(/^\/notifications$/i, "/notifications");

      if (!p.startsWith("/")) p = "/" + p;
      return p;
    } catch {
      const s = String(raw);
      return s.startsWith("/") ? s : "/" + s;
    }
  };

  // ---------- Deep-link builder ----------
  const resolveHref = (n) => {
    // 1) prefer backend-provided link, normalize it
    if (n?.href) return normalizeHref(n.href);

    // 2) otherwise infer (and still normalize)
    let path = "/notifications";

    switch (n?.type) {
      case "match":
      case "buzz":
      case "like": {
        if (n?.fromId) path = `/viewprofile/${n.fromId}`;
        else path = "/letsbuzz";
        break;
      }
      case "comment":
      case "reaction":
      case "new_post":
      case "share": {
        const owner = n?.postOwnerId || n?.ownerId || n?.fromId;
        const post = n?.postId || n?.entityId || n?.targetId;
        if (owner && post) path = `/viewprofile/${owner}?post=${post}`;
        else if (owner) path = `/viewprofile/${owner}`;
        else path = "/letsbuzz";
        break;
      }
      case "wingman":
        path = "/letsbuzz";
        break;
      default:
        path = "/notifications";
    }

    return normalizeHref(path);
  };

  // ---------- Unread counts (for badges + top counter) ----------
  const unreadCounts = useMemo(() => {
    const c = { all: 0 };
    for (const n of notifications) {
      if (!n.read) {
        c.all++;
        c[n.type] = (c[n.type] || 0) + 1;
      }
    }
    return c;
  }, [notifications]);

  // ---------- Filtered view ----------
  const filteredNotifications = useMemo(() => {
    if (filter === "all") return notifications;
    return notifications.filter((n) => n.type === filter);
  }, [notifications, filter]);

  // ---------- Helpers ----------
  const markAsRead = async (id) => {
    // optimistic UI
    setNotifications((prev) =>
      prev.map((n) => (n.id === id ? { ...n, read: true } : n))
    );

    try {
      await fetch(`${API_BASE}/notifications/${id}/read`, {
        method: "PATCH",
        headers: { Authorization: `Bearer ${token}` },
      });
      // let navbar (or others) know a notif was read
      window.dispatchEvent(
        new CustomEvent("notifications:read", { detail: { id } })
      );
    } catch (err) {
      console.error("markAsRead error:", err);
      // revert if API fails
      setNotifications((prev) =>
        prev.map((n) => (n.id === id ? { ...n, read: false } : n))
      );
    }
  };

  const markAllAsRead = async () => {
    const unread = notifications.filter((n) => !n.read);
    // optimistic
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
    try {
      await Promise.allSettled(
        unread.map((n) =>
          fetch(`${API_BASE}/notifications/${n.id}/read`, {
            method: "PATCH",
            headers: { Authorization: `Bearer ${token}` },
          })
        )
      );
      window.dispatchEvent(new Event("notifications:clear"));
    } catch (err) {
      console.error("markAllAsRead error:", err);
    }
  };

  const deleteNotification = async (id) => {
    try {
      await fetch(`${API_BASE}/notifications/${id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });
      setNotifications((prev) => prev.filter((n) => n.id !== id));
    } catch (err) {
      console.error("deleteNotification error:", err);
    }
  };

  const blockUser = async (userId) => {
    if (!userId) return;
    if (!window.confirm("Block this user from sending future notifications?"))
      return;
    try {
      await fetch(`${API_BASE}/notifications/block/${userId}`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
      setNotifications((prev) => prev.filter((n) => n.fromId !== userId));
    } catch (err) {
      console.error("blockUser error:", err);
    }
  };

  // ---------- Handle click on a notification ----------
  const handleOpen = async (n) => {
    const href = resolveHref(n) || "/notifications";
    // mark as read then navigate
    await markAsRead(n.id);
    navigate(href);
  };

  // ---------- Quick Buzz Back ----------
  const handleQuickBuzzBack = async (fromId, notificationId, e) => {
    if (e) {
      e.preventDefault();
      e.stopPropagation();
    }
    if (!token) return;

    setBuzzLoading((prev) => ({ ...prev, [notificationId]: true }));
    try {
      const r = await fetch(`${API_BASE}/buzz`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ to: fromId }),
      });

      if (!r.ok) {
        const errorData = await r.json().catch(() => ({}));
        if (r.status === 429) {
          const secondsLeft = Math.ceil((errorData.retryInMs || 0) / 1000);
          alert(`Slow down! You can buzz again in ${secondsLeft} seconds. ⏰`);
        } else if (r.status === 409) {
          alert("You need to be matched first!");
        } else {
          alert("Could not buzz right now.");
        }
        return;
      }

      await r.json();
      setBuzzSent((prev) => ({ ...prev, [notificationId]: true }));
      setTimeout(() => {
        setBuzzSent((prev) => ({ ...prev, [notificationId]: false }));
      }, 2000);
    } catch (err) {
      console.error("Quick buzz back error:", err);
      alert("Network error. Please check your connection.");
    } finally {
      setBuzzLoading((prev) => ({ ...prev, [notificationId]: false }));
    }
  };

  // ---------- Accept Match Request ----------
  const handleAcceptMatch = async (fromId, e) => {
    if (e) {
      e.preventDefault();
      e.stopPropagation();
    }
    if (!token) return;

    try {
      const r = await fetch(`${API_BASE}/likes`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ to: fromId }),
      });

      if (!r.ok) {
        const errorData = await r.json().catch(() => ({}));
        if (r.status === 400) {
          alert("You've already matched with this user!");
        } else {
          alert("Could not accept match right now.");
        }
        return;
      }

      const data = await r.json();
      if (data.matched) {
        alert(`💞 It's a match! You can now view their profile and chat!`);
      } else {
        alert("Match request sent! ❤️");
      }
    } catch (err) {
      console.error("Accept match error:", err);
      alert("Network error. Please check your connection.");
    }
  };

  // ---------- View Profile Handler ----------
  const handleViewProfile = (fromId, e) => {
    if (e) {
      e.preventDefault();
      e.stopPropagation();
    }
    if (!fromId) {
      alert("Cannot view profile - user not found");
      return;
    }
    navigate(normalizeHref(`/viewprofile/${fromId}`));
  };

  const iconForType = (t) => {
    switch (t) {
      case "buzz":
        return <span className="text-purple-500 text-2xl">🔔</span>;
      case "like":
        return <FaHeart className="text-rose-500" />;
      case "comment":
        return <FaComments className="text-purple-500" />;
      case "reaction":
        return <FaComments className="text-violet-500" />;
      case "match":
        return <FaHandshake className="text-green-500" />;
      case "wingman":
        return <FaRobot className="text-indigo-500" />;
      case "share":
        return <FaBell className="text-blue-500" />;
      case "new_post":
        return <FaBell className="text-amber-500" />;
      default:
        return <FaUser className="text-gray-500" />;
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen text-gray-500">
        Loading notifications...
      </div>
    );
  }

  const FILTERS = [
    "all",
    "buzz",
    "match",
    "like",
    "comment",
    "reaction",
    "new_post",
    "share",
    "wingman",
  ];

  return (
    <div className="min-h-screen bg-gradient-to-b from-rose-50 to-white p-6">
      <h1 className="text-3xl font-bold text-center text-pink-600 mb-1">
        🔔 Notifications
      </h1>
      <p className="text-center text-sm text-gray-500 mb-4">
        Unread: <span className="font-semibold">{unreadCounts.all || 0}</span>
      </p>

      {/* Toolbar */}
      <div className="max-w-md mx-auto mb-4 flex items-center gap-2">
        <div className="flex gap-2 overflow-x-auto">
          {FILTERS.map((filterType) => (
            <button
              key={filterType}
              onClick={() => setFilter(filterType)}
              className={`px-3 py-1.5 rounded-full text-sm font-medium whitespace-nowrap transition ${
                filter === filterType
                  ? "bg-purple-500 text-white shadow-md"
                  : "bg-white text-gray-600 border border-gray-200 hover:bg-gray-50"
              }`}
            >
              {filterType === "all"
                ? "All"
                : filterType === "buzz"
                ? "Buzz"
                : filterType === "match"
                ? "Matches"
                : filterType === "like"
                ? "Likes"
                : filterType === "comment"
                ? "Comments"
                : filterType === "reaction"
                ? "Reactions"
                : filterType === "new_post"
                ? "New Posts"
                : filterType === "share"
                ? "Shares"
                : "Wingman"}
              {(unreadCounts[filterType] || 0) > 0 && (
                <span className="ml-1 px-1.5 py-0.5 text-xs bg-rose-500 text-white rounded-full">
                  {unreadCounts[filterType]}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* Mark all as read */}
        <button
          onClick={markAllAsRead}
          className="ml-auto px-3 py-1.5 rounded-full text-xs font-semibold bg-gray-100 hover:bg-gray-200 text-gray-600 border border-gray-200"
          title="Mark all as read"
        >
          Mark all read
        </button>
      </div>

      <div className="max-w-md mx-auto bg-white rounded-2xl shadow-lg divide-y">
        {filteredNotifications.map((n) => (
          <div
            key={n.id}
            onClick={() => handleOpen(n)}
            className={`relative flex items-start gap-3 p-4 transition cursor-pointer ${
              n.read ? "bg-white" : "bg-rose-50"
            } hover:bg-rose-100 border-l-4 ${
              n.type === "buzz"
                ? "border-l-purple-500"
                : n.type === "match"
                ? "border-l-green-500"
                : n.type === "like"
                ? "border-l-rose-500"
                : n.type === "comment"
                ? "border-l-purple-500"
                : n.type === "reaction"
                ? "border-l-violet-500"
                : n.type === "new_post"
                ? "border-l-amber-500"
                : n.type === "share"
                ? "border-l-blue-500"
                : n.type === "wingman"
                ? "border-l-indigo-500"
                : "border-l-gray-300"
            }`}
          >
            <div className="text-2xl mt-1">{iconForType(n.type)}</div>

            <div className="flex-1">
              <p className="text-gray-800 text-sm font-medium">{n.message}</p>
              <p className="text-xs text-gray-400 mt-1">
                {formatDistanceToNow(new Date(n.createdAt), {
                  addSuffix: true,
                })}
              </p>

              {/* Enhanced Action Buttons */}
              {n.type === "buzz" && n.fromId && (
                <div className="flex gap-2 mt-2">
                  {/* For Match Requests (unmatched users) */}
                  {n.message?.includes("wants to match") && (
                    <>
                      <button
                        onClick={(e) => handleAcceptMatch(n.fromId, e)}
                        className="text-xs bg-green-100 text-green-700 px-3 py-1 rounded-full hover:bg-green-200 transition"
                      >
                        ✅ Match Back
                      </button>
                      <button
                        onClick={(e) => handleViewProfile(n.fromId, e)}
                        className="text-xs bg-blue-100 text-blue-700 px-3 py-1 rounded-full hover:bg-blue-200 transition"
                      >
                        👀 View Profile
                      </button>
                    </>
                  )}

                  {/* For Regular Buzzes (matched users) */}
                  {n.message?.includes("buzzed you") && (
                    <button
                      onClick={(e) => handleQuickBuzzBack(n.fromId, n.id, e)}
                      disabled={buzzLoading[n.id] || buzzSent[n.id]}
                      className={`text-xs px-3 py-1 rounded-full transition ${
                        buzzSent[n.id]
                          ? "bg-green-100 text-green-700"
                          : buzzLoading[n.id]
                          ? "bg-gray-100 text-gray-500 cursor-not-allowed"
                          : "bg-purple-100 text-purple-700 hover:bg-purple-200"
                      }`}
                    >
                      {buzzLoading[n.id]
                        ? "⏳"
                        : buzzSent[n.id]
                        ? "✅ Buzz Sent!"
                        : "🔔 Buzz Back"}
                    </button>
                  )}
                </div>
              )}
            </div>

            {/* 3-dot menu */}
            <div className="relative">
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  setMenuOpen(menuOpen === n.id ? null : n.id);
                }}
                className="text-gray-500 hover:text-gray-800 p-1 rounded"
              >
                <FaEllipsisV size={16} />
              </button>

              {menuOpen === n.id && (
                <div className="absolute right-0 top-6 bg-white border rounded-lg shadow-lg z-10 w-40">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      markAsRead(n.id);
                      setMenuOpen(null);
                    }}
                    className="flex items-center gap-2 px-3 py-2 w-full text-left text-sm hover:bg-rose-50"
                  >
                    <FaBell className="text-gray-500" /> Mark read
                  </button>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      deleteNotification(n.id);
                      setMenuOpen(null);
                    }}
                    className="flex items-center gap-2 px-3 py-2 w-full text-left text-sm hover:bg-rose-50"
                  >
                    <FaTrash className="text-gray-500" /> Remove
                  </button>
                  {n.fromId && (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        blockUser(n.fromId);
                        setMenuOpen(null);
                      }}
                      className="flex items-center gap-2 px-3 py-2 w-full text-left text-sm text-red-600 hover:bg-rose-50"
                    >
                      <FaBan className="text-red-500" /> Block user
                    </button>
                  )}
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
