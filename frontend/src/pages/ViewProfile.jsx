// src/pages/ViewProfile.jsx
import React, { useEffect, useMemo, useState, useRef } from "react";
import { useParams, useNavigate, useLocation } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import {
  FaCommentDots,
  FaUserLock,
  FaBan,
  FaExclamationTriangle,
  FaMapMarkerAlt,
  FaCircle,
  FaEllipsisV,
  FaHeart,
  FaEdit,
  FaTrash,
  FaReply
} from "react-icons/fa";
import AiWingmanPanel from "../components/AiWingmanPanel";

//const API_BASE = "http://localhost:4000/api";
const API_BASE = process.env.REACT_APP_API_BASE || "https://rombuzz-api.onrender.com/api";

// Reaction emojis for long-press palette
const REACTION_SET = ["❤️", "😂", "😢", "🤗", "😡"];

export default function ViewProfile() {
// 🔗 router hooks
const { userId } = useParams();
const navigate = useNavigate();
const { search } = useLocation();

  const [viewer, setViewer] = useState(null);
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);

  // =========================================
  // 🔔 Listen for MicroBuzz match events
  // =========================================
  useEffect(() => {
    const socket = window?.globalSocket || window?.socket || null;
    if (!socket) return;

    socket.on("buzz_match_open_profile", (payload) => {
      console.log("🔥 MicroBuzz Match Open Profile received:", payload);

      // Save match locally for unlock logic
      const existing = JSON.parse(localStorage.getItem("RBZ:microbuzz:matches") || "[]");
      if (
        !existing.find(
          (m) =>
            (m.a === viewer?.id && m.b === payload.otherUserId) ||
            (m.a === payload.otherUserId && m.b === viewer?.id)
        )
      ) {
        existing.push({ a: viewer?.id, b: payload.otherUserId, createdAt: Date.now() });
        localStorage.setItem("RBZ:microbuzz:matches", JSON.stringify(existing));
      }

      // Optional: auto-refresh if viewing that same profile
      if (payload.otherUserId === userId) {
        window.location.reload();
      }
    });

    return () => socket.off("buzz_match_open_profile");
  }, [viewer?.id, userId]);

// 🔥 MatchStreak state
const [streak, setStreak] = useState(null); // { count, lastBuzz, createdAt } or null
// add these near your other refs/helpers
const commentInputRef = useRef(null);
// 🔗 Auto-open a specific post when linked from notifications
useEffect(() => {
  const params = new URLSearchParams(search);
  const targetId = params.get("openPost") || params.get("post") || params.get("p");
  if (!targetId) return;

  // Ensure posts are loaded first
  if (!profile?.user?.posts || profile.user.posts.length === 0) return;

  // Find the post
  const hasPost = profile.user.posts.some(p => p.id === targetId);
  if (!hasPost) return;

  // Open comment drawer + scroll smoothly
  setActiveCommentPostId(targetId);
  setTimeout(() => {
    const el = document.querySelector(`[data-post-id="${targetId}"]`);
    if (el) el.scrollIntoView({ behavior: "smooth", block: "center" });
  }, 250);
}, [search, profile?.user?.posts]);

const autosizeTextarea = (el) => {
  if (!el) return;
  el.style.height = '0px';
  el.style.height = `${el.scrollHeight}px`;
};


// fetch MatchStreak for this pair (server truth)
const fetchStreak = async () => {
  const t = getToken();
  const me = viewer?.id;
  const other = userId;
  if (!t || !me || !other) return; // ensure both sides exist

  try {
    const r = await fetch(`${API_BASE}/matchstreak/${other}`, {
      headers: { Authorization: `Bearer ${t}` },
    });
    if (!r.ok) return;

    const data = await r.json();
    const next = data?.streak ?? null;
    if (next && typeof next.count === "number") {
      console.debug("MatchStreak hydrate", { me, other, count: next.count });
      setStreak(next);
      saveStreakCache(me, other, next);
    }
  } catch (e) {
    // keep silent in UI, but helpful during dev:
    console.debug("fetchStreak error", e);
  }
};


const [likeBusy, setLikeBusy] = useState(false);
const [menuOpen, setMenuOpen] = useState(false);
const [blocked, setBlocked] = useState(false);

// Fetch block status between viewer and profile user
const checkBlockStatus = async () => {
  const t = getToken();
  if (!t || !userId) return;
  try {
    const r = await fetch(`${API_BASE}/blocks`, {
      headers: { Authorization: `Bearer ${t}` },
    });
    const j = await r.json();
    const blocks = j.blocks || [];
    const isBlocked = blocks.some((b) => b.id === userId);
    setBlocked(isBlocked);
  } catch (err) {
    console.error("block status error", err);
  }
};

const handleBlockToggle = async () => {
  const t = getToken();
  if (!t || !userId) return;
  if (blocked) {
    if (!window.confirm("Unblock this user?")) return;
    await fetch(`${API_BASE}/blocks/${userId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${t}` },
    });
    alert("User unblocked - you can now chat and view their profile.");
    setBlocked(false);
  } else {
    if (!window.confirm("Block this user? They will not be able to message or view you.")) return;
    await fetch(`${API_BASE}/blocks/${userId}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${t}` },
    });
    alert("User blocked - they can no longer contact or view you.");
    setBlocked(true);
  }
};

const [activeTab, setActiveTab] = useState("face");
const [lightbox, setLightbox] = useState(null);
const [showWingman, setShowWingman] = useState(false);

// Enhanced states for reactions and comments
const [activeCommentPostId, setActiveCommentPostId] = useState(null);
const [commentDraft, setCommentDraft] = useState("");
const [showPaletteForPost, setShowPaletteForPost] = useState(null);
const [openMenuForComment, setOpenMenuForComment] = useState(null);
const [reactionDetails, setReactionDetails] = useState(null);
const longPressTimerRef = useRef(null);
const buzzInFlightRef = useRef(false); // NEW

// NEW (comment reactions palette)
const [showPaletteForComment, setShowPaletteForComment] = useState(null); // "postId:commentId"
const commentLongPressRef = useRef(null);

const token = localStorage.getItem("token") || sessionStorage.getItem("token") || "";

// -------- Helpers
const getToken = () => localStorage.getItem("token") || sessionStorage.getItem("token") || "";

// --- MatchStreak cache helpers ---
const streakKey = (me, other) => `streak:${String(me)}->${String(other)}`;


const loadStreakCache = (me, other) => {
  try { return JSON.parse(localStorage.getItem(streakKey(me, other)) || 'null'); }
  catch { return null; }
};

const saveStreakCache = (me, other, s) => {
  try { localStorage.setItem(streakKey(me, other), JSON.stringify(s)); } catch {}
};

const safeJson = async (res) => {
  try {
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
};
// ✅ Refresh posts from server to ensure reactions/comments persist
const refreshProfilePosts = async () => {
  const t = getToken();
  if (!t || !userId) return;
  try {
    const r = await fetch(`${API_BASE}/users/${userId}`, {
      headers: { Authorization: `Bearer ${t}` },
    });
    if (!r.ok) return;
    const data = await r.json();
    setProfile((prev) => ({
      ...prev,
      user: { ...prev.user, posts: data.user?.posts || [] },
    }));
  } catch (e) {
    console.error("refreshProfilePosts failed", e);
  }
};


const age = useMemo(() => {
  const dob = profile?.user?.dob;
  if (!dob) return null;
  const diff = Date.now() - new Date(dob).getTime();
  return Math.floor(diff / (365 * 24 * 3600 * 1000));
}, [profile?.user?.dob]);

const prettyLocation = (() => {
  const loc = profile?.user?.location;
  if (!loc) return null;
  if (typeof loc === "object") {
    if (loc.city || loc.state) {
      return [loc.city, loc.state].filter(Boolean).join(", ");
    }
  }
  return String(loc);
})();

const lastActiveAgo = useMemo(() => {
  const ts = profile?.user?.lastOnline;
  if (!ts) return null;
  const diff = Date.now() - Number(ts);
  const m = Math.floor(diff / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}, [profile?.user?.lastOnline]);

const milesBetween = useMemo(() => {
  const a = viewer?.location;
  const b = profile?.user?.location;
  if (!a || !b || a.lat == null || a.lng == null || b.lat == null || b.lng == null) return null;
  const R = 6371e3;
  const dLat = ((b.lat - a.lat) * Math.PI) / 180;
  const dLon = ((b.lng - a.lng) * Math.PI) / 180;
  const p1 = (a.lat * Math.PI) / 180;
  const p2 = (b.lat * Math.PI) / 180;
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(p1) * Math.cos(p2) * Math.sin(dLon / 2) ** 2;
  const m = R * 2 * Math.atan2(Math.sqrt(h), Math.sqrt(1 - h));
  return Math.round((m / 1609.344) * 10) / 10;
}, [viewer?.location, profile?.user?.location]);

const voiceUrl = useMemo(() => {
  const favs = profile?.user?.favorites || [];
  const raw = favs.find((f) => typeof f === "string" && f.startsWith("voice:"));
  if (!raw) return null;
  return raw.split("voice:")[1] || null;
}, [profile?.user?.favorites]);

// -------- Media buckets
const mediaBuckets = useMemo(() => {
  const all = profile?.user?.media || [];
  const face = [];
  const photo = [];
  const reels = [];
  for (const m of all) {
    const isVideo = String(m.type).toLowerCase() === "video" || (m.url || "").includes("/video/upload/");
    const isFace = String(m.caption || "").toLowerCase().includes("facebuzz") ||
                 String(m.caption || "").toLowerCase().includes("__avatar__") ||
                 (profile?.user?.avatar && m.url === profile.user.avatar);

    if (isVideo) reels.push(m);
    else if (isFace) face.push(m);
    else photo.push(m);
  }
  return { face, photo, reels, counts: { face: face.length, photo: photo.length, reels: reels.length } };
}, [profile?.user?.media, profile?.user?.avatar]);

// -------- Fetch data
useEffect(() => {
  let cancelled = false;
  (async () => {
    setLoading(true);
    try {
      const headers = { Authorization: `Bearer ${token}` };
      const [meRes, profileRes] = await Promise.all([
        fetch(`${API_BASE}/users/me`, { headers }),
        fetch(`${API_BASE}/users/${userId}`, { headers }),
      ]);

      const meData = await safeJson(meRes);
      const status = profileRes.status;
      const profData = status === 403 ? null : await safeJson(profileRes);

      if (!cancelled) {
        setViewer(meData?.id ? meData : meData?.user || null);
        if (status === 403) {
          setProfile({ user: null, matched: false, blocked: true });
        } else {
          setProfile(profData || null);
        }
      }
    } catch (e) {
      if (!cancelled) setProfile(null);
      console.error("ViewProfile fetch error:", e);
    } finally {
      if (!cancelled) setLoading(false);
    }
  })();
  return () => { cancelled = true; };
}, [userId, token]);
useEffect(() => {
  checkBlockStatus();
  // eslint-disable-next-line react-hooks/exhaustive-deps
}, [userId]);


// 🔁 Once profile says we’re matched, show cached streak instantly, then fetch server truth
useEffect(() => {
  if (profile?.matched && viewer?.id && userId) {
    const cached = loadStreakCache(viewer.id, userId);
    if (cached) setStreak(cached);   // show instantly
    fetchStreak();                   // hydrate with server truth
  }
  // no else → do NOT reset streak while loading/route changes
  // eslint-disable-next-line react-hooks/exhaustive-deps
}, [profile?.matched, viewer?.id, userId]);



  // -------- Enhanced Reaction System
  const handleHeartPressStart = (postId, e) => {
    if (e) {
      e.preventDefault();
      e.stopPropagation();
    }
    longPressTimerRef.current = setTimeout(() => {
      setShowPaletteForPost(postId);
    }, 420);
  };

  const handleHeartPressEnd = (postId, e) => {
    if (e) {
      e.preventDefault();
      e.stopPropagation();
    }
    if (longPressTimerRef.current) {
      clearTimeout(longPressTimerRef.current);
      longPressTimerRef.current = null;
    }
  };

  const reactWithEmoji = async (postId, emoji) => {
    const token = getToken();
    if (!token) return;
    try {
      const r = await fetch(`${API_BASE}/posts/${postId}/react-emoji`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ emoji }),
      });
      if (!r.ok) throw new Error("react failed");
      const data = await r.json();
      
      setProfile(prev => ({
        ...prev,
        user: {
          ...prev.user,
          posts: prev.user.posts.map(p => 
            p.id === postId ? { 
              ...p, 
              reactionCounts: data.counts,
              reactors: data.reactors || p.reactors
            } : p
          )
        }
      }));
      } catch (e) {
      console.error(e);
      alert("Could not react");
    } finally {
      setShowPaletteForPost(null);
      refreshProfilePosts(); // ✅ re-hydrate from backend so reactions persist
    }

  };

  const getReactorsForEmoji = (post, emoji) => {
    if (!post.reactors || !post.reactors[emoji]) return [];
    return post.reactors[emoji];
  };

  // -------- Enhanced Comment System
  const openComments = (postId, e) => {
    if (e) {
      e.preventDefault();
      e.stopPropagation();
    }
    setActiveCommentPostId(postId);
    setCommentDraft("");
  };

  const closeComments = (e) => {
    if (e) {
      e.preventDefault();
      e.stopPropagation();
    }
    setActiveCommentPostId(null);
  };

  const createComment = async (postId, e) => {
    if (e) {
      e.preventDefault();
      e.stopPropagation();
    }
    if (!commentDraft.trim()) return;
    const token = getToken();
    if (!token) return;
    try {
      const r = await fetch(`${API_BASE}/posts/${postId}/comment`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ text: commentDraft.trim() }),
      });
      if (!r.ok) throw new Error("comment failed");
      const data = await r.json();
      
      setProfile(prev => ({
        ...prev,
        user: {
          ...prev.user,
          posts: prev.user.posts.map(p => 
            p.id === postId ? { ...p, comments: [...(p.comments || []), data.comment] } : p
          )
        }
      }));
      setCommentDraft("");
    } catch (e) {
      console.error(e);
      alert("Could not add comment");
    }
  };

  const editComment = async (postId, comment) => {
    const next = prompt("Edit your comment:", comment.text) ?? comment.text;
    const token = getToken();
    if (!token) return;
    try {
      const r = await fetch(`${API_BASE}/posts/${postId}/comments/${comment.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ text: next }),
      });
      if (!r.ok) throw new Error("edit failed");
      const data = await r.json();
      
      setProfile(prev => ({
        ...prev,
        user: {
          ...prev.user,
          posts: prev.user.posts.map(p => 
            p.id === postId ? {
              ...p,
              comments: p.comments.map(c => c.id === comment.id ? data.comment : c)
            } : p
          )
        }
      }));
    } catch (e) {
      console.error(e);
      alert("Could not edit comment");
    }
  };

  const deleteComment = async (postId, comment) => {
    if (!window.confirm("Delete this comment?")) return;
    const token = getToken();
    if (!token) return;
    try {
      const r = await fetch(`${API_BASE}/posts/${postId}/comments/${comment.id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!r.ok) throw new Error("delete failed");
      
      setProfile(prev => ({
        ...prev,
        user: {
          ...prev.user,
          posts: prev.user.posts.map(p => 
            p.id === postId ? {
              ...p,
              comments: p.comments.filter(c => c.id !== comment.id)
            } : p
          )
        }
      }));
    } catch (e) {
      console.error(e);
      alert("Could not delete comment");
    }
  };

  const toggleCommentHeart = async (postId, commentId, e) => {
    if (e) {
      e.preventDefault();
      e.stopPropagation();
    }
    const token = getToken();
    if (!token) return;
    try {
      const r = await fetch(`${API_BASE}/posts/${postId}/comments/${commentId}/heart`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await r.json();
      
      setProfile(prev => ({
        ...prev,
        user: {
          ...prev.user,
          posts: prev.user.posts.map(p => 
            p.id === postId ? {
              ...p,
              comments: p.comments.map(c => 
                c.id === commentId ? { ...c, liked: data.liked, likeCount: data.count } : c
              )
            } : p
          )
        }
      }));
    } catch (e) {
      console.error(e);
      alert("Could not react to comment.");
    }
  };

  const replyToComment = (postId, comment, e) => {
  if (e) {
    e.preventDefault();
    e.stopPropagation();
  }
  setActiveCommentPostId(postId);
  setCommentDraft(`@${comment.userId === viewer?.id ? "you" : "them"} `);
};

// ===== NEW: comment long-press reactions =====
const handleCommentPressStart = (postId, commentId, e) => {
  if (e) { e.preventDefault(); e.stopPropagation(); }
  commentLongPressRef.current = setTimeout(() => {
    setShowPaletteForComment(`${postId}:${commentId}`);
  }, 420);
};

const handleCommentPressEnd = (e) => {
  if (e) { e.preventDefault(); e.stopPropagation(); }
  if (commentLongPressRef.current) {
    clearTimeout(commentLongPressRef.current);
    commentLongPressRef.current = null;
  }
};

// POST /posts/:postId/comments/:commentId/react-emoji { emoji }
const reactToCommentEmoji = async (postId, commentId, emoji) => {
  const t = getToken();
  if (!t) return;
  try {
    const r = await fetch(`${API_BASE}/posts/${postId}/comments/${commentId}/react-emoji`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${t}` },
      body: JSON.stringify({ emoji }),
    });
    if (!r.ok) throw new Error("react failed");
    const data = await r.json(); // { counts, reactors, liked?, count? }

    setProfile(prev => ({
      ...prev,
      user: {
        ...prev.user,
        posts: prev.user.posts.map(p =>
          p.id === postId
            ? {
                ...p,
                comments: p.comments.map(c =>
                  c.id === commentId
                    ? {
                        ...c,
                        liked: data.liked ?? c.liked,
                        likeCount: (data.counts?.["❤️"] ?? c.likeCount ?? 0),
                        reactionCounts: data.counts ?? c.reactionCounts ?? {},
                        reactors: data.reactors ?? c.reactors ?? {},
                      }
                    : c
                )
              }
            : p
        )
      }
    }));
  } catch (e) {
    console.error(e);
    alert("Could not react to comment.");
  } finally {
    setShowPaletteForComment(null);
  }
};


// -------- Enhanced Buzz System --------
const handleInitialBuzz = async (e) => {
  if (e) {
    e.preventDefault();
    e.stopPropagation();
  }
  if (!token) return;

  setLikeBusy(true);
  try {
    const r = await fetch(`${API_BASE}/likes`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ to: userId }),
    });
    
    if (!r.ok) {
      const errText = await r.text().catch(() => "");
      console.error("like/buzz failed:", r.status, errText);
      if (r.status === 400) {
        alert("You've already buzzed this user.");
      } else if (r.status === 429) {
        alert("Slow down 🙂 You can buzz again in a bit.");
      } else {
        alert("Could not buzz right now.");
      }
      return;
    }
    
    const data = await r.json();
    setProfile((p) => (p ? { ...p, likedByMe: true, matched: !!data.matched || p.matched } : p));
alert(data.matched ? "Great Choice 💞" : "Match request sent! ❤️");  } catch (err) {
    console.error(err);
    alert("Something went wrong.");
  } finally {
    setLikeBusy(false);
  }
};

const handleMatchedBuzz = async (e) => {
  if (e) {
    e.preventDefault();
    e.stopPropagation();
  }
  if (!token) return;

  if (buzzInFlightRef.current) return; // prevent double-dispatch
  buzzInFlightRef.current = true;
  setLikeBusy(true);

  try {
    const r = await fetch(`${API_BASE}/buzz`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ to: userId }),
    });

    if (r.status === 429) {
      const data = await r.json().catch(() => ({}));
      if (data?.error === "busy") {
        // same-tick duplicate; ignore silently
        return;
      }
      const secondsLeft = Math.ceil((data.retryInMs || 0) / 1000);
      alert(`Slow down! You can buzz again in ${secondsLeft} seconds. ⏰`);
      return;
    }

    if (!r.ok) {
      const errorData = await r.json().catch(() => ({}));
      if (r.status === 409) return alert("You need to be matched with this user first!");
      if (r.status === 403) return alert("You cannot buzz this user (blocked).");
      if (r.status === 400) return alert("Invalid request.");
      return alert(`Could not buzz right now. (Error: ${r.status})`);
    }

    const result = await r.json();
    if (result.success) {
      const serverCount = Number(result.streak || 0);
      const next = {
        users: [String(viewer?.id || ""), String(userId || "")].filter(Boolean).sort(),
        count: serverCount,
        lastBuzz: Date.now(),
        createdAt: streak?.createdAt || null
      };
      setStreak(next);
      if (viewer?.id) saveStreakCache(viewer.id, userId, next);

      // Optional: re-sync from server
      fetchStreak();

      alert(`You buzzed ${profile?.user?.firstName || "them"}! 💖 Streak: ${serverCount}`);
    } else {
      alert("Buzz sent but something went wrong.");
    }
  } catch (err) {
    console.error("Buzz network error:", err);
    alert("Network error. Please check your connection.");
  } finally {
    setLikeBusy(false);
    buzzInFlightRef.current = false;
  }
};


  const handleChat = (e) => {
    if (e) {
      e.preventDefault();
      e.stopPropagation();
    }
    navigate(`/chat?u=${encodeURIComponent(userId)}`);
  };

  const handleBlock = async (e) => {
    if (e) {
      e.preventDefault();
      e.stopPropagation();
    }
    if (!window.confirm("Block this user?")) return;
    try {
      await fetch(`${API_BASE}/block`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ targetId: userId }),
      });
      alert("User blocked.");
      navigate("/");
    } catch (e) {
      console.error(e);
    }
  };

  const handleReport = async (e) => {
    if (e) {
      e.preventDefault();
      e.stopPropagation();
    }
    const reason = window.prompt("Why are you reporting this profile? (required)");
    if (!reason) return;
    try {
      await fetch(`${API_BASE}/report`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ targetId: userId, reason }),
      });
      alert("Report submitted. Thank you.");
    } catch (e) {
      console.error(e);
    }
  };

  const handleUnmatch = async (e) => {
    if (e) {
      e.preventDefault();
      e.stopPropagation();
    }
    const ok = window.confirm("Unmatch this user?");
    if (!ok) return;
    await fetch(`${API_BASE}/unmatch/${userId}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    alert("Unmatched.");
    navigate("/profile");
  };

  // -------- UI Components
  const Section = ({ title, children, pad = true }) => (
    <motion.section
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className={`border-t ${pad ? "p-6" : ""}`}
    >
      <h3 className="text-lg font-semibold text-gray-800 mb-3">{title}</h3>
      {children}
    </motion.section>
  );

  const pill = "px-3 py-1 rounded-full bg-pink-100 text-pink-700 text-sm";

  const DotMenu = ({ open, onClose, children }) => {
    if (!open) return null;
    return (
      <div className="absolute right-0 mt-2 w-44 bg-white border rounded-xl shadow-lg z-20 overflow-hidden">
        <div className="divide-y text-sm">{children}</div>
      </div>
    );
  };

  const DotItem = ({ children, onClick, danger }) => (
    <button
      type="button"
      onClick={(e) => {
        e.preventDefault();
        e.stopPropagation();
        onClick();
      }}
      className={`w-full text-left px-3 py-2 hover:bg-gray-50 ${danger ? "text-red-600" : "text-gray-700"}`}
    >
      {children}
    </button>
  );

  const timeAgo = (ts) => {
    const diff = Date.now() - Number(ts);
    const m = Math.floor(diff / 60000);
    if (m < 60) return `${m}m ago`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h}h ago`;
    const d = Math.floor(h / 24);
    return `${d}d ago`;
  };
// -------- Enhanced PostCard Component
const PostCard = ({ p }) => {
  const counts = p.reactionCounts || {};

  // NEW: isolate comments scroll + pin to bottom
  const commentsScrollRef = useRef(null);
  useEffect(() => {
    if (activeCommentPostId === p.id && commentsScrollRef.current) {
      commentsScrollRef.current.scrollTop = commentsScrollRef.current.scrollHeight;
    }
  }, [activeCommentPostId, p.comments?.length, p.id]);

  const allReactions = REACTION_SET.map(emoji => ({
    emoji,
    count: counts[emoji] || 0,
    reactors: getReactorsForEmoji(p, emoji)
  })).filter(reaction => reaction.count > 0);

  return (
    <div className="post-card border rounded-xl p-4 bg-white shadow-sm">
      <div className="flex items-center justify-between mb-2">
        <div className="font-semibold text-gray-800 flex items-center gap-2">
          {u.firstName} {/* ✅ Now 'u' is available from parent scope */}
          <span className="text-xs text-gray-500">{timeAgo(p.createdAt)}</span>
        </div>
        <span className="text-xs text-gray-500">
          {p.privacy === "private" ? "🔒" : p.privacy === "matches" ? "💞" : "🌍"}
        </span>
      </div>
      
      {p.text && <p className="text-sm text-gray-800 mb-2">{p.text}</p>}
      
      {p.mediaUrl && (
        <div className="mt-2">
          {p.type === "video" ? (
            <video src={p.mediaUrl} controls className="rounded-lg w-full" />
          ) : (
            <img src={p.mediaUrl} alt="" className="rounded-lg w-full object-cover" />
          )}
        </div>
      )}

      {/* Enhanced Reactions & Comments */}
      <div className="flex items-center gap-3 mt-3 text-sm">
        {/* Heart with long-press */}
<button
  type="button"
  className="px-3 py-1 rounded-full bg-rose-50 hover:bg-rose-100 select-none"
  onMouseDown={(e) => handleHeartPressStart(p.id, e)}
  onMouseUp={(e) => handleHeartPressEnd(p.id, e)}
  onMouseLeave={() => {
    if (longPressTimerRef.current) {
      clearTimeout(longPressTimerRef.current);
      longPressTimerRef.current = null;
    }
  }}
  onTouchStart={(e) => handleHeartPressStart(p.id, e)}
  onTouchEnd={(e) => handleHeartPressEnd(p.id, e)}
  onClick={(e) => {
    e.stopPropagation(); // ✅ no preventDefault() here (prevents form submit)
    reactWithEmoji(p.id, "❤️");
  }}
>
  ❤️ {counts["❤️"] > 0 ? counts["❤️"] : ""}
</button>


        {/* Reaction Palette */}
        {showPaletteForPost === p.id && (
          <div className="flex items-center gap-2 bg-white border rounded-full px-2 py-1 shadow">
            {REACTION_SET.map((emoji) => (
              <button
                key={emoji}
                type="button"
                onClick={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  reactWithEmoji(p.id, emoji);
                }}
                className="px-2 py-1 hover:bg-gray-50 rounded-full transition-transform hover:scale-110"
              >
                {emoji} {counts[emoji] || ""}
              </button>
            ))}
          </div>
        )}

        {/* All Reactions Summary */}
        {allReactions.length > 0 && (
          <div className="flex items-center gap-2 text-xs">
            {allReactions.map((reaction, idx) => (
              <button
                key={reaction.emoji}
                type="button"
                onClick={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  setReactionDetails({
                    postId: p.id,
                    emoji: reaction.emoji,
                    reactors: reaction.reactors
                  });
                }}
                className="px-2 py-1 rounded-full bg-gray-100 hover:bg-gray-200 transition-colors"
              >
                {reaction.emoji} {reaction.count}
              </button>
            ))}
          </div>
        )}

        <button
          type="button"
          className="ml-auto text-gray-600 hover:text-gray-800 flex items-center gap-1"
          onClick={(e) => openComments(p.id, e)}
        >
          <FaCommentDots /> {(p.comments || []).length}
        </button>
      </div>

      {/* Enhanced Comments Section */}
     {activeCommentPostId === p.id && (
  <div className="comment-section mt-3 border-t pt-3" style={{ overflowAnchor: "none" }}>
    <div ref={commentsScrollRef} className="space-y-2 max-h-72 overflow-auto pr-1">
      {(p.comments || []).length === 0 && (
        <div className="text-sm text-gray-500">No comments yet. Be the first!</div>
      )}
      ...


            {(p.comments || []).map((c) => {
              const isMine = c.userId === viewer?.id;
              const isOpen = openMenuForComment === `${p.id}-${c.id}`;

              return (
                <div key={c.id} className="bg-gray-50 rounded p-2 text-sm relative">
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="font-semibold flex items-center gap-2">
                        {isMine ? "You" : u.firstName}
                        <span className="text-xs text-gray-500">{timeAgo(c.createdAt)}</span>
                      </div>
                      <div className="mt-1 text-gray-800">{c.text}</div>
                    </div>

                    {/* Comment Menu */}
                    <div className="relative">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.preventDefault();
                          e.stopPropagation();
                          setOpenMenuForComment(isOpen ? null : `${p.id}-${c.id}`);
                        }}
                        className="px-2 py-1 rounded hover:bg-gray-100"
                      >
                        ⋯
                      </button>

                      <DotMenu
                        open={isOpen}
                        onClose={() => setOpenMenuForComment(null)}
                      >
                        {isMine && (
                          <DotItem onClick={() => editComment(p.id, c)}>
                            <FaEdit className="inline mr-2" /> Edit
                          </DotItem>
                        )}
                        <DotItem onClick={() => replyToComment(p.id, c)}>
                          <FaReply className="inline mr-2" /> Reply
                        </DotItem>
                        {(isMine || profile.matched) && (
                          <DotItem danger onClick={() => deleteComment(p.id, c)}>
                            <FaTrash className="inline mr-2" /> Delete
                          </DotItem>
                        )}
                      </DotMenu>
                    </div>
                  </div>

                {/* Comment Reactions */}
<div className="flex items-center gap-3 mt-2 text-xs">
  {/* Single tap = ❤️ toggle, long-press = palette */}
  <button
    type="button"
    className={`relative flex items-center gap-1 px-2 py-1 rounded-full border text-gray-600 hover:bg-pink-50 transition ${
      c.liked ? "bg-pink-100 border-pink-300 text-pink-600" : ""
    }`}
    onMouseDown={(e) => handleCommentPressStart(p.id, c.id, e)}
    onMouseUp={handleCommentPressEnd}
    onMouseLeave={handleCommentPressEnd}
    onTouchStart={(e) => handleCommentPressStart(p.id, c.id, e)}
    onTouchEnd={handleCommentPressEnd}
    onClick={(e) => {
      e.preventDefault();
      e.stopPropagation();
      toggleCommentHeart(p.id, c.id, e);
    }}
  >
    ❤️ {c.likeCount || 0}
  </button>

  {/* Palette on long-press */}
  {showPaletteForComment === `${p.id}:${c.id}` && (
    <div className="flex items-center gap-1 bg-white border rounded-full px-2 py-1 shadow">
      {REACTION_SET.map((emoji) => (
        <button
          key={emoji}
          type="button"
          className="px-2 py-1 rounded-full hover:bg-gray-50 transition-transform hover:scale-110"
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            reactToCommentEmoji(p.id, c.id, emoji);
          }}
        >
          {emoji}{/* optional: show counts if you store c.reactionCounts?.[emoji] */}
        </button>
      ))}
    </div>
  )}

  {/* Summary chips (optional) */}
  {c.reactionCounts && Object.entries(c.reactionCounts)
    .filter(([, n]) => n > 0)
    .map(([emoji, n]) => (
      <span key={emoji} className="px-2 py-1 rounded-full bg-gray-100">
        {emoji} {n}
      </span>
    ))}
</div>

                </div>
              );
            })}
          </div>

         {/* Comment Input (autosizing + stable) */}
<div className="flex gap-2 mt-2">
  <textarea
  ref={commentInputRef}
  className="flex-1 border rounded p-2 leading-5 resize-none max-h-40"
  rows={1}
  placeholder="Write a comment…"
  value={commentDraft}
  onChange={(e) => {
    setCommentDraft(e.target.value);
    autosizeTextarea(commentInputRef.current);
  }}
  onFocus={() => autosizeTextarea(commentInputRef.current)}
onClick={(e) => e.stopPropagation()}


  onKeyDown={(e) => {
    // Enter to send (Shift+Enter makes a new line)
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      e.stopPropagation();
      createComment(p.id);
    }
  }}
/>

  <button
    type="button"
    onClick={(e) => {
      e.preventDefault();
      e.stopPropagation();
      createComment(p.id);
    }}
    className="bg-pink-500 text-white px-4 py-2 rounded"
  >
    Send
  </button>
  <button
    type="button"
    onClick={(e) => {
      e.preventDefault();
      e.stopPropagation();
      closeComments();
    }}
    className="border px-4 py-2 rounded"
  >
    Close
  </button>
</div>

        </div>
      )}
    </div>
  );
};

  const GalleryGrid = ({ items }) => {
    if (!items.length) {
      return <div className="text-sm text-gray-500 italic">Nothing here yet.</div>;
    }
    return (
      <div className="grid grid-cols-3 sm:grid-cols-4 md:grid-cols-5 gap-2">
        {items.map((m) => (
          <div
            key={m.id}
            className="relative group rounded-xl overflow-hidden ring-1 ring-gray-100 hover:ring-rose-200 transition"
          >
            {m.type === "video" ? (
              <video
                src={m.url}
                className="w-full aspect-square object-cover"
                onClick={() => setLightbox({ type: "video", url: m.url })}
              />
            ) : (
              <img
                src={m.url}
                alt={m.caption || ""}
                className="w-full aspect-square object-cover"
                onClick={() => setLightbox({ type: "image", url: m.url })}
              />
            )}
            <div className="absolute inset-0 bg-black/0 group-hover:bg-black/25 transition" />
          </div>
        ))}
      </div>
    );
  };

  // -------- Guards
  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-pulse text-gray-600">Loading profile…</div>
      </div>
    );
  }

if (!profile?.user) {
  const blockedError = profile?.blocked;
  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-gradient-to-br from-rose-100 via-pink-50 to-rose-100">
      <p className="text-gray-800 text-lg font-semibold">
        {blockedError
          ? "⚠️ Cannot view profile."
          : "Profile not found."}
      </p>
      <button
        type="button"
        onClick={() => navigate(-1)}
        className="mt-4 bg-pink-500 text-white px-5 py-2 rounded-full shadow hover:bg-pink-600"
      >
        Go Back
      </button>
    </div>
  );
}


 const isSelf = viewer?.id && profile.user.id === viewer.id;

// ✅ Expanded unlock condition: check local MicroBuzz matches too
const microbuzzMatches = (() => {
  try {
    const stored = JSON.parse(localStorage.getItem("RBZ:microbuzz:matches") || "[]");
    return stored.some(
      (m) =>
        (m.a === viewer?.id && m.b === profile.user.id) ||
        (m.a === profile.user.id && m.b === viewer?.id)
    );
  } catch {
    return false;
  }
})();

if (!isSelf && !profile.matched && !microbuzzMatches) {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-gradient-to-br from-pink-200 via-rose-100 to-pink-200">
      <FaUserLock className="text-rose-600 mb-4" size={44} />
      <div className="text-gray-800 font-semibold text-lg">Profile locked</div>
      <div className="text-gray-600 text-sm mb-4">You can only view profiles after a match.</div>

      <div className="flex gap-3">
        <button
          type="button"
          onClick={() => navigate(-1)}
          className="px-4 py-2 rounded-full bg-white border border-rose-300 text-rose-600 hover:bg-rose-50"
        >
          Go Back
        </button>
        <button
          type="button"
          onClick={handleInitialBuzz}
          disabled={likeBusy}
          className="px-4 py-2 rounded-full bg-gradient-to-r from-pink-500 to-rose-500 text-white hover:opacity-90 transition disabled:opacity-60"
        >
          ❤️ Buzz to Unlock
        </button>
      </div>
    </div>
  );
}


  const u = profile.user;

return (
  <div className="min-h-screen bg-gradient-to-br from-pink-200 via-rose-100 to-pink-200 py-8 px-3">
    {blocked ? (
      <div className="flex flex-col items-center justify-center h-screen text-center text-gray-600">
        <FaBan className="text-5xl mb-4 text-rose-500" />
        <p className="text-lg font-medium">You’ve blocked this user.</p>
        <p className="text-sm text-gray-500 mt-1">
          They can’t message or view your profile.
        </p>
        <button
          onClick={handleBlockToggle}
          className="mt-4 px-5 py-2 bg-rose-500 text-white rounded-full hover:bg-rose-600"
        >
          Unblock
        </button>
      </div>
    ) : (
      <>
        <div className="max-w-5xl mx-auto bg-white rounded-2xl shadow-lg overflow-hidden relative">
     {/* Header */}
        <div className="p-6 bg-gradient-to-r from-pink-100 to-rose-50">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-6">
            <div className="flex items-center gap-4">
              <div className="w-28 h-28 shrink-0 relative">
                <img
                  src={u.avatar || "https://via.placeholder.com/200x200?text=No+Photo"}
                  alt="avatar"
                  className="w-28 h-28 max-w-none rounded-full object-cover ring-4 ring-white shadow-md cursor-pointer"
                  onClick={() => u.avatar && setLightbox({ type: "image", url: u.avatar })}
                />
                {u.lastOnline && Date.now() - Number(u.lastOnline) < 5 * 60 * 1000 && (
                  <FaCircle className="absolute bottom-1 right-1 text-green-500" />
                )}
              </div>

              <div>
              <div className="flex items-center gap-2 flex-wrap">
  <h2 className="text-2xl font-bold text-gray-900">
    {u.firstName} {u.lastName}
  </h2>
  {lastActiveAgo && (
    <span className="text-xs text-gray-500">• active {lastActiveAgo}</span>
  )}

  {/* 🔥 MatchStreak Badge */}
{profile.matched && (
  <div className="relative group ml-1">
    <div className="inline-flex items-center gap-2 rounded-full px-3 py-1
                    bg-gradient-to-r from-amber-100 via-rose-100 to-pink-100
                    ring-1 ring-amber-200/60 shadow-sm">
      <div className="relative h-5 w-5">
        <span className="absolute inset-0 rounded-full ring-2 ring-amber-300/60"></span>
        <span className="absolute inset-[3px] rounded-full bg-white"></span>
        <span className="absolute inset-0 flex items-center justify-center text-[11px] font-bold text-amber-700">🔥</span>
      </div>
      <span className="text-[12px] font-semibold text-amber-700 tracking-wide">
        HotTouch
      </span>
      <span className="text-[12px] font-extrabold text-rose-600">
  {typeof streak?.count === "number" ? streak.count : "-"}
</span>

    </div>

    {/* Enhanced tooltip with last buzz time */}
    <div className="pointer-events-none absolute left-0 mt-2 w-64 rounded-xl bg-white p-3 text-xs text-gray-700
                    shadow-xl ring-1 ring-gray-200 opacity-0 group-hover:opacity-100 transition
                    translate-y-1 group-hover:translate-y-0 z-30">
      <div className="font-semibold mb-1">🔥 Touch Streak: {streak?.count ?? "0"}</div>
      <div className="text-gray-600">
        Keep touching each other to grow your streak!  
        <span className="block mt-1 text-[11px] text-gray-500">
          {streak?.lastBuzz 
            ? `Last buzz: ${timeAgo(streak.lastBuzz)}`
            : 'No buzzes yet - start the streak!'}
        </span>
        <span className="block mt-1 text-[11px] text-gray-400">
  Your streak increases when you tap ❤️ Buzz.
</span>

      </div>
    </div>
  </div>
)}
  
</div>

                <p className="text-xs text-gray-500 flex items-center gap-2 mt-1">
                  <FaMapMarkerAlt className="shrink-0" />
                  {[prettyLocation, age && `${age} yrs`, u.gender, u.orientation, milesBetween != null && `~${milesBetween} mi`]
                    .filter(Boolean)
                    .join(" • ")}
                </p>
              </div>
            </div>

            {/* Actions */}
            <div className="flex items-center gap-2 self-start md:self-auto">
             {!isSelf && !profile.blocked && (
  <>
    {!profile.matched ? (
      <button
        type="button"
        onClick={handleInitialBuzz}
        disabled={likeBusy}
        className="bg-gradient-to-r from-pink-500 to-rose-500 text-white px-5 py-2 rounded-full shadow hover:opacity-90 transition disabled:opacity-60"
      >
        ❤️ Buzz
      </button>
    ) : (
      <>
        <button
          type="button"
          onClick={handleMatchedBuzz}
          disabled={likeBusy}
          className="bg-gradient-to-r from-purple-500 to-pink-500 text-white px-5 py-2 rounded-full shadow hover:opacity-90 transition disabled:opacity-60 animate-pulse"
        >
          🔔 Buzz
        </button>
        <button
          type="button"
          onClick={handleChat}
          className="bg-white border border-pink-400 text-pink-500 px-5 py-2 rounded-full hover:bg-pink-50"
        >
          💬 Chat
        </button>
        <button
          type="button"
          onClick={() => setShowWingman(true)}
          className="bg-white border border-rose-300 text-rose-600 px-5 py-2 rounded-full hover:bg-rose-50"
        >
          🤖 Wingman
        </button>
      </>
    )}
  </>
)}
              <div className="relative">
                <button
                  type="button"
                  onClick={() => setMenuOpen((v) => !v)}
                  className="p-2 rounded-full hover:bg-white/70 border"
                >
                  <FaEllipsisV />
                </button>
                <AnimatePresence>
                  {menuOpen && (
                    <motion.div
                      initial={{ opacity: 0, y: -6 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -6 }}
                      className="absolute right-0 mt-2 bg-white border rounded-xl shadow-lg overflow-hidden z-10"
                    >
                      <button
                        type="button"
                        onClick={(e) => { 
                          e.preventDefault();
                          e.stopPropagation();
                          setMenuOpen(false); 
                          handleBlock(e); 
                        }}
                        className="flex items-center gap-2 px-4 py-2 hover:bg-gray-50 w-full text-left text-sm"
                      >
                        <FaBan className="text-gray-600" /> Block
                      </button>
                      {profile.matched && (
                        <button
                          type="button"
                          onClick={(e) => { 
                            e.preventDefault();
                            e.stopPropagation();
                            setMenuOpen(false); 
                            handleUnmatch(e); 
                          }}
                          className="flex items-center gap-2 px-4 py-2 hover:bg-gray-50 w-full text-left text-sm"
                        >
                          💔 Unmatch
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={(e) => { 
                          e.preventDefault();
                          e.stopPropagation();
                          setMenuOpen(false); 
                          handleReport(e); 
                        }}
                        className="flex items-center gap-2 px-4 py-2 hover:bg-gray-50 w-full text-left text-sm"
                      >
                        <FaExclamationTriangle className="text-red-500" /> Report
                      </button>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </div>
          </div>
        </div>

        {/* About */}
        {(u.bio || voiceUrl || u.city || u.state) && (
          <Section title="About">
            {u.bio && <p className="text-gray-800 text-sm leading-relaxed">{u.bio}</p>}
            {voiceUrl && (
              <div className="mt-3">
                <div className="text-sm font-medium text-gray-700 mb-1">🎧 Voice Intro</div>
                <audio controls src={voiceUrl} className="w-full md:w-1/2" />
              </div>
            )}
            {(u.city || u.state) && (
              <div className="mt-3 text-xs text-gray-600 flex items-center gap-2">
                <FaMapMarkerAlt />
                <span>
                  {[u.city, u.state].filter(Boolean).join(", ")}
                  {milesBetween != null && <> • ~{milesBetween} mi</>}
                </span>
              </div>
            )}
          </Section>
        )}

        {/* Mutuals */}
        {(u.interests?.length || u.hobbies?.length) && (
          <Section title="Shared Vibes">
            <div className="flex flex-wrap gap-2">
              {(u.interests || []).map((i) => (
                <span className={pill} key={`i-${i}`}>#{i}</span>
              ))}
              {(u.hobbies || []).map((h) => (
                <span className={pill} key={`h-${h}`}>{h}</span>
              ))}
            </div>
          </Section>
        )}

        {/* Gallery Tabs */}
        <Section title="Gallery" pad={false}>
          <div className="px-6 pb-6">
            <div className="flex gap-2 mb-4">
              <button
                type="button"
                onClick={() => setActiveTab("face")}
                className={`px-4 py-1.5 rounded-full text-sm border ${
                  activeTab === "face"
                    ? "bg-rose-500 text-white border-rose-500"
                    : "bg-white text-gray-700 border-gray-200 hover:bg-gray-50"
                }`}
              >
                FaceBuzz {mediaBuckets.counts.face ? `(${mediaBuckets.counts.face})` : ""}
              </button>
              <button
                type="button"
                onClick={() => setActiveTab("photo")}
                className={`px-4 py-1.5 rounded-full text-sm border ${
                  activeTab === "photo"
                    ? "bg-rose-500 text-white border-rose-500"
                    : "bg-white text-gray-700 border-gray-200 hover:bg-gray-50"
                }`}
              >
                PhotoBuzz {mediaBuckets.counts.photo ? `(${mediaBuckets.counts.photo})` : ""}
              </button>
              <button
                type="button"
                onClick={() => setActiveTab("reels")}
                className={`px-4 py-1.5 rounded-full text-sm border ${
                  activeTab === "reels"
                    ? "bg-rose-500 text-white border-rose-500"
                    : "bg-white text-gray-700 border-gray-200 hover:bg-gray-50"
                }`}
              >
                ReelsBuzz {mediaBuckets.counts.reels ? `(${mediaBuckets.counts.reels})` : ""}
              </button>
            </div>

            <AnimatePresence mode="wait">
              {activeTab === "face" && (
                <motion.div
                  key="face"
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -6 }}
                >
                  <GalleryGrid items={mediaBuckets.face} />
                </motion.div>
              )}
              {activeTab === "photo" && (
                <motion.div
                  key="photo"
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -6 }}
                >
                  <GalleryGrid items={mediaBuckets.photo} />
                </motion.div>
              )}
              {activeTab === "reels" && (
                <motion.div
                  key="reels"
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -6 }}
                >
                  <GalleryGrid items={mediaBuckets.reels} />
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </Section>

        {/* Enhanced Posts Section */}
        {(u.posts || []).length > 0 && (
          <Section title={isSelf ? "Your Buzz" : "Their Buzz"}>
            <div className="space-y-4">
           {(u.posts || [])
  .filter((p) => p.privacy === "public" || p.visibility === "matches")
  .sort((a, b) => Number(b.createdAt) - Number(a.createdAt))
  .map((p) => (
    <div key={p.id} data-post-id={p.id}>
      <PostCard p={p} />
    </div>
  ))}

            </div>
          </Section>
        )}

        {/* Reaction Details Modal */}
        <AnimatePresence>
          {reactionDetails && (
            <motion.div
              className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setReactionDetails(null)}
            >
              <div 
                className="bg-white rounded-2xl max-w-sm w-full p-4 shadow-2xl"
                onClick={(e) => e.stopPropagation()}
              >
                <div className="flex items-center justify-between mb-3">
                  <h3 className="font-semibold text-lg">
                    {reactionDetails.emoji} Reactions
                  </h3>
                  <button
                    type="button"
                    onClick={() => setReactionDetails(null)}
                    className="text-gray-500 hover:text-gray-700"
                  >
                    ✕
                  </button>
                </div>
                <div className="max-h-60 overflow-y-auto">
                  {reactionDetails.reactors.length === 0 ? (
                    <p className="text-gray-500 text-center py-4">No reactions yet</p>
                  ) : (
                    <div className="space-y-2">
                      {reactionDetails.reactors.map((reactor, index) => (
                        <div key={index} className="flex items-center gap-3 p-2 rounded-lg hover:bg-gray-50">
                          <div className="w-8 h-8 rounded-full bg-pink-100 flex items-center justify-center text-sm">
                            {reactionDetails.emoji}
                          </div>
                          <span className="font-medium">{reactor.userName || `User ${index + 1}`}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Lightbox */}
        <AnimatePresence>
          {lightbox && (
            <motion.div
              className="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setLightbox(null)}
            >
              <div className="max-w-3xl w-full" onClick={(e) => e.stopPropagation()}>
                {lightbox.type === "video" ? (
                  <video src={lightbox.url} controls className="w-full rounded-t-lg" />
                ) : (
                  <img src={lightbox.url} alt="" className="w-full rounded-t-lg" />
                )}
                <div className="bg-white rounded-b-lg p-3 border-t flex justify-center">
                  <button
                    type="button"
                    className="px-3 py-1 rounded-full bg-gray-100"
                    onClick={() => setLightbox(null)}
                  >
                    Close
                  </button>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Wingman Modal */}
        <AnimatePresence>
          {showWingman && (
            <motion.div
              className="fixed inset-0 z-50 bg-black/50 flex items-center justify-center p-4"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
            >
              <div className="bg-white rounded-2xl max-w-lg w-full p-4 shadow-2xl">
                <div className="flex items-center justify-between mb-2">
                  <div className="font-semibold text-gray-800">AI Wingman</div>
                  <button
                    type="button"
                    className="text-sm px-3 py-1 rounded-full bg-gray-100"
                    onClick={() => setShowWingman(false)}
                  >
                    Close
                  </button>
                </div>
                <AiWingmanPanel me={viewer?.user || viewer} them={u} />
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
{/* Floating FABs (mobile) */}
{!isSelf && profile.matched && (
  <div className="fixed bottom-5 right-5 flex flex-col gap-3 md:hidden">
   {/* micro chip */}
    <div className="text-[11px] px-2 py-1 rounded-full bg-white/80 backdrop-blur ring-1 ring-rose-200 text-rose-600 shadow">
      🔥 {streak?.count ?? "-"}
    </div>
    <button
      type="button"
      onClick={handleChat}
      className="rounded-full shadow-lg px-5 py-3 bg-white border border-pink-300 text-pink-600"
    >
      💬 Chat
    </button>
    <button
      type="button"
      onClick={handleMatchedBuzz}  // ✅ FIXED: Changed to handleMatchedBuzz
      disabled={likeBusy}
      className="rounded-full shadow-lg px-5 py-3 text-white bg-gradient-to-r from-purple-500 to-pink-500 disabled:opacity-60 animate-pulse"
    >
      💖 Buzz
    </button>
  </div>
)}
          </>
    )}
  </div>
);

}