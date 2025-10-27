// src/pages/LetsBuzz.jsx
import React, { useEffect, useMemo, useRef, useState, useCallback } from "react";
import {
  FaHeart,
  FaFilter,
  FaBookmark,
  FaPlus,
  FaPlay,
  FaPause,
  FaVolumeMute,
  FaVolumeUp,
  FaEllipsisV,
  FaCommentDots,
} from "react-icons/fa";
import BuzzPost from "../components/BuzzPost";
import CreatePostModal from "../components/CreatePostModal";
import PostFilters from "../components/PostFilters";
import StoriesBar from "../components/StoriesBar";

//const API_BASE = "http://localhost:4000/api";
const API_BASE = import.meta.env.VITE_API_BASE;

// Simple unique-by-id helper
const uniqById = (arr) => {
  const map = new Map();
  for (const item of arr || []) map.set(item.id, item);
  return Array.from(map.values());
};

// Inline Comments Drawer with 3-dot per comment
function CommentsDrawer({
  open,
  onClose,
  post,
  token,
  onChanged,
}) {
  const [loading, setLoading] = useState(false);
  const [list, setList] = useState([]);
  const [text, setText] = useState("");
  const [editingId, setEditingId] = useState(null);
  const [replyTo, setReplyTo] = useState(null); // {id, authorName}

  const load = useCallback(async () => {
    if (!post) return;
    setLoading(true);
    try {
      const r = await fetch(`${API_BASE}/buzz/posts/${post.id}/comments`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const j = await r.json();
      // return as flat list; we will group by parentId locally
      const comments = (j.comments || []).map((c) => ({
        ...c,
        parentId: c.parentId || null,
      }));
      setList(comments);
    } catch (e) {
      console.error("comments load error:", e);
    } finally {
      setLoading(false);
    }
  }, [post, token]);
 // Add real-time comment updates
  useEffect(() => {
    const handleNewComment = (event) => {
      const { postId, comment } = event.detail;
      if (postId === post?.id) {
        // Refresh comments when new comment arrives
        load();
      }
    };

    window.addEventListener("comment:new", handleNewComment);
    return () => window.removeEventListener("comment:new", handleNewComment);
  }, [post?.id]);

  useEffect(() => {
    if (open) load();
  }, [open, load]);

  const thread = useMemo(() => {
    const roots = [];
    const byParent = {};
    for (const c of list) {
      if (c.parentId) {
        byParent[c.parentId] ||= [];
        byParent[c.parentId].push(c);
      } else {
        roots.push(c);
      }
    }
    return { roots, byParent };
  }, [list]);

  const submit = async () => {
    if (!text.trim()) return;
    const body = { text: text.trim() };
    if (replyTo?.id) body.parentId = replyTo.id;
    try {
      const response = await fetch(`${API_BASE}/buzz/posts/${post.id}/comments`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(body),
      });
      
      if (!response.ok) {
        throw new Error('Failed to post comment');
      }

      // First load the new comments
      await load();
      // Then update UI state
      setText("");
      setReplyTo(null);
      onChanged?.();
    } catch (e) {
      console.error("comment add error:", e);
      alert("Failed to post comment. Please try again.");
    }
  };

  const startEdit = (c) => {
    setEditingId(c.id);
    setText(c.text || "");
  };

  const applyEdit = async () => {
    if (!editingId) return;
    try {
      await fetch(
        `${API_BASE}/buzz/posts/${post.id}/comments/${editingId}`,
        {
          method: "PATCH",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({ text }),
        }
      );
      setEditingId(null);
      setText("");
      await load();
      onChanged?.();
    } catch (e) {
      console.error("comment edit error:", e);
    }
  };

  const del = async (c) => {
    try {
      await fetch(
        `${API_BASE}/buzz/posts/${post.id}/comments/${c.id}`,
        { method: "DELETE", headers: { Authorization: `Bearer ${token}` } }
      );
      await load();
      onChanged?.();
    } catch (e) {
      console.error("comment delete error:", e);
    }
  };

const CommentRow = ({ c, depth = 0 }) => {
  const [showReactions, setShowReactions] = useState(false);
  const [myReaction, setMyReaction] = useState(c.myReaction || null);
  const [reactionCounts, setReactionCounts] = useState(c.reactionCounts || {});
  const [totalReactions, setTotalReactions] = useState(c.totalReactions || 0);
  
  const currentUser = JSON.parse(localStorage.getItem("user") || sessionStorage.getItem("user") || "{}");
  const isMyComment = c.userId === currentUser.id;
  const isPostOwner = post?.userId === currentUser.id;

  // Handle comment reaction
  const handleCommentReaction = async (emoji = "❤️") => {
    try {
      if (myReaction === emoji) {
        // Remove reaction
        await fetch(`${API_BASE}/buzz/posts/${post.id}/comments/${c.id}/react`, {
          method: "DELETE",
          headers: { Authorization: `Bearer ${token}` },
        });
        setMyReaction(null);
        setTotalReactions(prev => Math.max(0, prev - 1));
        const newCounts = { ...reactionCounts };
        if (newCounts[emoji]) {
          newCounts[emoji] = Math.max(0, newCounts[emoji] - 1);
          if (newCounts[emoji] === 0) delete newCounts[emoji];
        }
        setReactionCounts(newCounts);
      } else {
        // Add reaction
        const res = await fetch(`${API_BASE}/buzz/posts/${post.id}/comments/${c.id}/react`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({ emoji }),
        });
        const data = await res.json();
        if (data.success) {
          setMyReaction(emoji);
          setReactionCounts(data.reactionCounts || {});
          setTotalReactions(data.totalReactions || 0);
        }
      }
      setShowReactions(false);
    } catch (error) {
      console.error("Comment reaction error:", error);
    }
  };

  // Navigate to profile
  const handleProfileClick = () => {
    window.location.href = `/viewProfile/${c.userId}`;
  };

  return (
    <div className={`flex gap-3 ${depth ? "ml-10" : ""}`}>
      {/* Clickable Profile Avatar */}
      <div 
        className="cursor-pointer hover:opacity-80 transition-opacity"
        onClick={handleProfileClick}
        title={`View ${c.author?.firstName}'s profile`}
      >
        <img
          src={c.author?.avatar || "https://via.placeholder.com/48"}
          alt=""
          className="w-8 h-8 rounded-full object-cover mt-1"
        />
      </div>
      
      <div className="flex-1 bg-white border rounded-2xl p-3 mb-2">
        <div className="flex items-start justify-between">
          <div className="flex-1">
            {/* Clickable Name */}
            <div 
              className="font-semibold text-sm cursor-pointer hover:underline inline-block"
              onClick={handleProfileClick}
            >
              {c.author?.firstName || "User"}
            </div>
            <div className="text-sm mt-1">{c.text}</div>
            
            {/* Comment Reactions */}
            <div className="flex items-center gap-3 mt-2">
              {/* Heart Reaction Button */}
              <div className="relative">
                <button
                  onClick={() => handleCommentReaction("❤️")}
                  className={`flex items-center gap-1 text-sm ${
                    myReaction === "❤️" ? "text-pink-500" : "text-gray-500 hover:text-pink-500"
                  } transition-colors`}
                >
                  <FaHeart className={myReaction === "❤️" ? "fill-current" : ""} />
                  <span>{reactionCounts["❤️"] || 0}</span>
                </button>
                
                {/* Reaction Picker (Optional - for more emojis) */}
                {showReactions && (
                  <div className="absolute bottom-6 left-0 bg-white border rounded-full shadow-lg p-2 flex gap-1 z-20">
                    {["❤️", "😂", "😮", "😢", "🔥"].map((emoji) => (
                      <button
                        key={emoji}
                        onClick={() => handleCommentReaction(emoji)}
                        className="text-sm hover:scale-125 transition-transform"
                      >
                        {emoji}
                      </button>
                    ))}
                  </div>
                )}
              </div>
              
              {/* Reply Button */}
              <button
                onClick={() => setReplyTo({ id: c.id, authorName: c.author?.firstName || "User" })}
                className="text-sm text-gray-500 hover:text-gray-700"
              >
                Reply
              </button>
              
              {/* Total Reactions Count */}
              {totalReactions > 0 && (
                <button
                  onClick={() => setShowReactions(!showReactions)}
                  className="text-xs text-gray-400 hover:text-gray-600"
                >
                  {totalReactions} reaction{totalReactions !== 1 ? 's' : ''}
                </button>
              )}
            </div>
          </div>

          {/* 3-Dot Menu - Conditional based on user role */}
          <div className="relative">
            <details className="group">
              <summary className="list-none cursor-pointer text-gray-500 hover:text-gray-700 p-1 rounded">
                <FaEllipsisV />
              </summary>
              <div className="absolute right-0 mt-1 bg-white border rounded-lg shadow-lg min-w-36 z-10">
                {/* Always show Reply */}
                <button
                  className="block w-full text-left px-3 py-2 hover:bg-gray-50 text-sm"
                  onClick={() => setReplyTo({ id: c.id, authorName: c.author?.firstName || "User" })}
                >
                  Reply
                </button>
                
                {/* Show Edit/Delete only for comment author */}
                {isMyComment && (
                  <>
                    <button
                      className="block w-full text-left px-3 py-2 hover:bg-gray-50 text-sm"
                      onClick={() => startEdit(c)}
                    >
                      Edit
                    </button>
                    <button
                      className="block w-full text-left px-3 py-2 hover:bg-red-50 text-red-600 text-sm"
                      onClick={() => del(c)}
                    >
                      Delete
                    </button>
                  </>
                )}
                
                {/* Show Delete for post owner (even if not comment author) */}
                {!isMyComment && isPostOwner && (
                  <button
                    className="block w-full text-left px-3 py-2 hover:bg-red-50 text-red-600 text-sm"
                    onClick={() => del(c)}
                  >
                    Delete
                  </button>
                )}
              </div>
            </details>
          </div>
        </div>

        {/* Render children replies */}
        {(thread.byParent[c.id] || []).map((child) => (
          <CommentRow key={child.id} c={child} depth={depth + 1} />
        ))}
      </div>
    </div>
  );
};

  if (!open) return null;
  return (
    <div className="fixed inset-0 bg-black/30 z-50 flex">
      <div className="m-auto w-full max-w-2xl bg-white rounded-2xl shadow-2xl p-5 max-h-[80vh] overflow-auto">
        <div className="flex items-center justify-between mb-3">
          <div className="font-semibold text-lg">Comments</div>
          <button
            onClick={onClose}
            className="text-sm px-3 py-1 rounded-full border hover:bg-gray-50"
          >
            Close
          </button>
        </div>

        {loading ? (
          <div className="text-gray-500">Loading comments…</div>
        ) : thread.roots.length === 0 ? (
          <div className="text-gray-400">No comments yet.</div>
        ) : (
          thread.roots.map((c) => <CommentRow key={c.id} c={c} />)
        )}

        <div className="mt-4 border-t pt-3">
          {replyTo ? (
            <div className="text-xs text-gray-500 mb-1">
              Replying to <b>{replyTo.authorName}</b>{" "}
              <button
                className="ml-2 underline"
                onClick={() => setReplyTo(null)}
              >
                cancel
              </button>
            </div>
          ) : null}
          <div className="flex gap-2">
            <input
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder={editingId ? "Edit your comment…" : replyTo ? "Write a reply…" : "Write a comment…"}
              className="flex-1 border rounded-xl px-3 py-2"
            />
            {!editingId ? (
              <button
                onClick={submit}
                className="bg-pink-500 text-white px-4 py-2 rounded-xl"
              >
                Post
              </button>
            ) : (
              <button
                onClick={applyEdit}
                className="bg-pink-500 text-white px-4 py-2 rounded-xl"
              >
                Save
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
// TikTok-style Reel Card Component
function ReelCard({ post, token, onLike, onComment, isActive, reels = [], index = 0 }) {
  const videoRef = useRef(null);
 const [playing, setPlaying] = useState(isActive);
const [muted, setMuted] = useState(true);
const [liked, setLiked] = useState(false);
const [showHeart, setShowHeart] = useState(false);
const [likeCount, setLikeCount] = useState(post.likes?.length || 0);
const [loadFailed, setLoadFailed] = useState(false);

// ❤️ Persist like state on reload
useEffect(() => {
  const me =
    JSON.parse(localStorage.getItem("user") ||
      sessionStorage.getItem("user") ||
      "{}");
  if (Array.isArray(post.likes) && me?.id) {
    setLiked(post.likes.some((l) => l.userId === me.id));
  }
}, [post.likes]);

  // Auto-play when in view
  useEffect(() => {
    const video = videoRef.current;
    if (!video) return;

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting && entry.intersectionRatio > 0.7) {
            video.play().then(() => setPlaying(true)).catch(console.error);
          } else {
            video.pause();
            setPlaying(false);
          }
        });
      },
      { threshold: [0.7] }
    );

    observer.observe(video);
    return () => observer.disconnect();
  }, []);

  // Handle double tap for like
  const [tapCount, setTapCount] = useState(0);
  const handleDoubleTap = useCallback(async () => {
    setTapCount(prev => prev + 1);
    
    if (tapCount === 0) {
      setTimeout(() => setTapCount(0), 300);
      return;
    }

    // Double tap detected
    if (!liked) {
      await handleLike();
    }
    setShowHeart(true);
    setTimeout(() => setShowHeart(false), 1000);
    setTapCount(0);
  }, [tapCount, liked]);

// ❤️ Unified like using BuzzPost reaction API with animation & instant update
const handleLike = async () => {
  if (liked) {
    // Unlike immediately on UI
    setLiked(false);
    setLikeCount((prev) => Math.max(0, prev - 1));
    setShowHeart(true);
    setTimeout(() => setShowHeart(false), 400);

    try {
      await fetch(`${API_BASE}/buzz/posts/${post.id}/react`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });
    } catch (err) {
      console.error("Unlike error:", err);
    }
    return;
  }

  // Like immediately on UI
  setLiked(true);
  setLikeCount((prev) => prev + 1);
  setShowHeart(true);
  setTimeout(() => setShowHeart(false), 700);

  try {
    await fetch(`${API_BASE}/buzz/posts/${post.id}/react`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ emoji: "❤️" }),
    });
  } catch (err) {
    console.error("Like error:", err);
  }
};




  const togglePlay = () => {
    if (!videoRef.current) return;
    if (playing) {
      videoRef.current.pause();
      setPlaying(false);
    } else {
      videoRef.current.play();
      setPlaying(true);
    }
  };

  const toggleMute = () => {
    if (!videoRef.current) return;
    videoRef.current.muted = !videoRef.current.muted;
    setMuted(videoRef.current.muted);
  };

  return (
    <div className="snap-start relative w-full h-screen bg-black flex items-center justify-center">
      {/* Video */}
      <div 
        className="relative w-full h-full max-w-md mx-auto"
        onDoubleClick={handleDoubleTap}
      >
{(() => {
  const url = post.mediaUrl || "";
  const looksLikeVideo =
    /\.(mp4|webm|ogg|mov)$/i.test(url) ||
    /\/video\/upload\//i.test(url);

  const safeSrc = url.includes("/upload/")
    ? url.replace(
        "/upload/",
        "/upload/f_auto,q_auto:eco,vc_auto,w_720,h_1280,c_fill,g_auto/"
      )
    : url;

 if (looksLikeVideo && !loadFailed) {
  return (
    <video
      ref={videoRef}
      className="w-full h-full object-cover"
      src={safeSrc}
      autoPlay
      muted
      playsInline
      loop
      preload="auto"
      onLoadedData={(e) => {
        const v = e.currentTarget;
        // try playing once loaded
        v.muted = true;
        v.play().catch(() => {});
      }}
      onClick={togglePlay}
      onError={() => {
        console.error("🎥 Video load failed, switching to image:", safeSrc);
        setLoadFailed(true);
      }}
    >
      <source src={safeSrc} type="video/mp4" />
      <source src={safeSrc} type="video/webm" />
      <p className="text-white text-center">Your browser doesn’t support videos.</p>
    </video>
  );
}


  return (
    <img
      src={
        safeSrc ||
        "https://via.placeholder.com/720x1280?text=Media+Unavailable"
      }
      alt="Reel thumbnail"
      className="w-full h-full object-cover"
    />
  );
})()}

        {/* Double-tap Heart Animation */}
       {showHeart && (
  <div className="absolute inset-0 flex items-center justify-center">
    <FaHeart
      className={`text-8xl ${
        liked ? "text-pink-500 scale-125" : "text-white scale-100"
      } transition-all duration-300 drop-shadow-2xl`}
      style={{ animation: "popHeart 0.6s ease-out" }}
    />
  </div>
)}


        {/* Play/Pause Overlay */}
        {!playing && (
          <div 
            className="absolute inset-0 flex items-center justify-center bg-black/30 cursor-pointer"
            onClick={togglePlay}
          >
            <div className="bg-black/50 rounded-full p-4">
              <FaPlay className="text-white text-4xl" />
            </div>
          </div>
        )}
      </div>

      {/* Right Action Bar */}
      <div className="absolute right-4 bottom-32 flex flex-col items-center gap-6 text-white">
      {/* Profile */}
<div className="flex flex-col items-center">
  <div
    className="w-14 h-14 rounded-full bg-gradient-to-r from-pink-500 to-rose-500 p-0.5 cursor-pointer hover:scale-105 transition-transform"
    onClick={() => window.location.href = `/viewProfile/${post.userId}`}
    title={`View ${post.user?.firstName || "User"}'s profile`}
  >
    <img
      src={post.user?.avatar || "https://via.placeholder.com/64"}
      alt=""
      className="w-full h-full rounded-full object-cover border-2 border-black"
    />
  </div>
</div>


        {/* Like Button */}
        <div className="flex flex-col items-center">
          <button
            onClick={handleLike}
            className="bg-black/40 rounded-full p-3 hover:bg-black/60 transition-all duration-200 active:scale-95"
          >
            <FaHeart 
              className={`text-2xl transition-all duration-200 ${
                liked ? "text-pink-500 fill-pink-500 scale-110" : "text-white"
              }`} 
            />
          </button>
          <span className="text-sm mt-1 font-semibold">{likeCount}</span>
        </div>

        {/* Comment Button */}
        <div className="flex flex-col items-center">
          <button
            onClick={onComment}
            className="bg-black/40 rounded-full p-3 hover:bg-black/60 transition-all duration-200 active:scale-95"
          >
            <FaCommentDots className="text-2xl" />
          </button>
          <span className="text-sm mt-1 font-semibold">{post.comments?.length || 0}</span>
        </div>


        {/* Music/Sound */}
        <div className="flex flex-col items-center">
          <button
            onClick={toggleMute}
            className="bg-black/40 rounded-full p-3 hover:bg-black/60 transition-all duration-200 active:scale-95"
          >
            {muted ? (
              <FaVolumeMute className="text-2xl" />
            ) : (
              <FaVolumeUp className="text-2xl" />
            )}
          </button>
        </div>
      </div>

      {/* Bottom Info Section */}
      <div className="absolute left-4 bottom-8 right-20 text-white">
        <div className="flex items-center gap-3 mb-3">
          <div className="text-sm font-semibold">@{post.user?.firstName?.toLowerCase() || "user"}</div>
        </div>
        
        {post.text && (
          <p className="text-sm mb-3 line-clamp-2">{post.text}</p>
        )}

        {/* Music */}
        <div className="flex items-center gap-2 text-xs opacity-90">
          <div className="w-4 h-4 bg-pink-500 rounded animate-pulse"></div>
          <span>Original Sound - {post.user?.firstName || "User"}</span>
        </div>
      </div>

      {/* Progress Bar at Bottom */}
      <div className="absolute bottom-4 left-1/2 transform -translate-x-1/2 flex gap-1">
        {reels.map((_, i) => (
          <div
            key={i}
            className={`h-1 rounded-full transition-all duration-300 ${
              i === index ? "bg-white w-8" : "bg-white/30 w-2"
            }`}
          />
        ))}
      </div>
    </div>
  );
}

export default function LetsBuzz() {
  const [activeTab, setActiveTab] = useState("feed"); // 'feed' | 'reels' | 'saved'
  const [feed, setFeed] = useState([]);
  const [reels, setReels] = useState([]);
  const [bookmarks, setBookmarks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showFilters, setShowFilters] = useState(false);
  const [filters, setFilters] = useState({ type: "all", search: "", sort: "newest" });
 const [hasMore, setHasMore] = useState(true);
const [offset, setOffset] = useState(0);

// Comments Drawer
const [commentPost, setCommentPost] = useState(null);
  // file pickers for quick create
  const storyInputRef = useRef(null);
  const postInputRef = useRef(null);

// --- QuickCreate fallback (photo/video) ---
const [quickUploading, setQuickUploading] = useState(false);

// --- Stories ---
const [stories, setStories] = useState([]);           // flat stories (mine + matches)
const [storyOpen, setStoryOpen] = useState(null);     // { index } or null


  const token =
    localStorage.getItem("token") || sessionStorage.getItem("token");

  // Keep tab in URL ?tab=reels
  useEffect(() => {
    const sp = new URLSearchParams(window.location.search);
    const t = sp.get("tab");
    if (t && ["feed", "reels", "saved"].includes(t)) setActiveTab(t);
  }, []);
  useEffect(() => {
    const sp = new URLSearchParams(window.location.search);
    sp.set("tab", activeTab);
    const next = `${window.location.pathname}?${sp.toString()}`;
    window.history.replaceState(null, "", next);
  }, [activeTab]);

  // Lifecycle for data
  useEffect(() => {
  if (activeTab === "feed") {
    setOffset(0);
    fetchFeed(0, true);
    fetchStories();
  } else if (activeTab === "saved") {
    fetchBookmarks();
  } else if (activeTab === "reels") {
    fetchReels(true);
  }
  // eslint-disable-next-line react-hooks/exhaustive-deps
}, [activeTab, filters]);
// 🔁 Auto-refresh reels every 15 seconds while on Reels tab
useEffect(() => {
  if (activeTab !== "reels") return;
  const timer = setInterval(() => {
    fetchReels(false);
  }, 15000);
  return () => clearInterval(timer);
}, [activeTab]);


// FEED
// ✅ Unified feed: load matched users' posts & reels
async function fetchFeed(newOffset = 0, reset = false) {
  setLoading(true);
  try {
    const res = await fetch(`${API_BASE}/feed`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const data = await res.json();

    // Get current user ID to exclude own posts
    const userData =
      JSON.parse(localStorage.getItem("user") || sessionStorage.getItem("user") || "{}");
    const currentUserId = userData.id;

  // ✅ Only include photo/text posts in feed (exclude reels/videos)
const visible = (data.posts || []).filter(
  (p) =>
    p.userId !== currentUserId &&
    !(
      p.type === "reel" ||
      p.type === "video" ||
      /\.(mp4|mov|webm|ogg)$/i.test(p.mediaUrl || "")
    )
);
visible.sort((a, b) => b.createdAt - a.createdAt);

    if (reset) setFeed(visible);
    else setFeed((prev) => [...prev, ...visible]);

    setHasMore(false); // feed already returns all
  } catch (err) {
    console.error("Feed fetch error:", err);
    setFeed([]);
  } finally {
    setLoading(false);
  }
}

 // REELS (only show reels/videos from other users)
async function fetchReels(reset = false) {
  setLoading(true);
  try {
    const base = new URLSearchParams({
      ...filters,
      type: "reel",
      limit: "20",
      offset: "0",
    });
    const r1 = await fetch(`${API_BASE}/buzz/feed?${base}`, {
      headers: { Authorization: `Bearer ${token}` },
    }).then((r) => r.json());

    const r2 = await fetch(
      `${API_BASE}/buzz/feed?${new URLSearchParams({
        ...filters,
        type: "video",
        limit: "20",
        offset: "0",
      })}`,
      { headers: { Authorization: `Bearer ${token}` } }
    ).then((r) => r.json());

    // Get current user ID to filter out own reels
    const userData = JSON.parse(localStorage.getItem('user') || sessionStorage.getItem('user') || '{}');
    const currentUserId = userData.id;

   const onlyVideoish = (arr) =>
  (arr || []).filter(
    (p) =>
      (p.type === "reel" ||
        p.type === "video" ||
        /\.(mp4|mov|webm|ogg)$/i.test(p.mediaUrl || "") ||
        /\/video\/upload\//i.test(p.mediaUrl || "")) &&
      p.userId !== currentUserId
  ).map((p) => {
    // ✅ Apply Cloudinary transform for videos (9:16)
   if (p.mediaUrl?.includes("/upload/")) {
  // ✅ Only apply transform for images; leave videos raw
  if (!/\.(mp4|mov|webm|ogg)$/i.test(p.mediaUrl) && !/\/video\/upload\//i.test(p.mediaUrl)) {
    p.mediaUrl = p.mediaUrl.replace(
      "/upload/",
      "/upload/f_auto,q_auto:eco,c_fill,w_720,h_1280/"
    );
  }
}

    return p;
  });


    const merged = uniqById([
      ...onlyVideoish(r1.posts || []),
      ...onlyVideoish(r2.posts || []),
    ]);

    setReels(merged);
    setHasMore(false); // we load a slab; you can paginate later if needed
  } catch (e) {
    console.error("Reels fetch error:", e);
  } finally {
    setLoading(false);
  }
}
  // SAVED
  async function fetchBookmarks() {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/buzz/bookmarks`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      setBookmarks(data.posts || []);
    } catch (err) {
      console.error("Bookmarks fetch error:", err);
    } finally {
      setLoading(false);
    }
  }

  function inferPostTypeFromUrl(url) {
  const u = (url || "").toLowerCase();
  if (/\.(mp4|mov|webm|ogg)$/.test(u) || u.includes("/video/upload/")) return "reel";
  return "photo";
}
async function compressImage(file, maxW = 1080, maxH = 1350, quality = 0.8) {
  const img = await new Promise((res, rej) => {
    const i = new Image();
    i.onload = () => res(i);
    i.onerror = rej;
    i.src = URL.createObjectURL(file);
  });

  let { width, height } = img;
  const scale = Math.min(maxW / width, maxH / height, 1);
  const w = Math.round(width * scale);
  const h = Math.round(height * scale);

  const canvas = document.createElement("canvas");
  canvas.width = w;
  canvas.height = h;
  const ctx = canvas.getContext("2d");
  ctx.drawImage(img, 0, 0, w, h);

  const blob = await new Promise((res) =>
    canvas.toBlob(res, "image/webp", quality)
  );
  return new File([blob], (file.name || "photo") + ".webp", { type: "image/webp" });
}



async function fetchStories() {
  try {
    const r = await fetch(`${API_BASE}/stories`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const data = await r.json();
    setStories(data.stories || []);
  } catch (e) {
    console.error("Stories fetch error:", e);
  }
}


  const handleLoadMore = () => {
    if (!loading && hasMore) {
      fetchFeed(offset, false);
    }
  };

  const handlePostCreated = () => {
    setShowCreateModal(false);
    setOffset(0);
    fetchFeed(0, true);
  };

  const handleFiltersChange = (newFilters) => {
    setFilters(newFilters);
  };

  const onViewed3s = () => {
    // no-op for now; server increments viewCount
  };
    async function quickCreateFromFile(file, kind = "auto") {
  if (!file) return;
  setQuickUploading(true);
  try {
    // compress images client-side
    let upFile = file;
    const isImage = file.type?.startsWith("image/");
    const isVideo = file.type?.startsWith("video/");
    if (isImage) {
      upFile = await compressImage(file, 1080, 1350, 0.8);
    }

    // 1) Upload to backend -> Cloudinary
    const fd = new FormData();
    fd.append("file", upFile);
    const upRes = await fetch(`${API_BASE}/upload-media-file`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: fd,
    });
    const up = await upRes.json();
    if (!upRes.ok || !up?.ok || !up?.url) {
      const reason = up?.error || `HTTP ${upRes.status}`;
      throw new Error(`media upload failed: ${reason}`);
    }

    // 2) Decide the post type
    const postType =
      kind === "story" ? "story" :
      isVideo ? "reel" : "photo";

 // 3) Create story OR post (never both)
if (postType === "story") {
  // Directly create a Story (24h lifespan)
  const sRes = await fetch(`${API_BASE}/stories`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ mediaUrl: up.url }),
  });

  if (!sRes.ok) {
    const errText = await sRes.text();
    console.error("Story upload failed:", errText);
    throw new Error("Story creation failed");
  }

  await fetchStories(); // refresh UI
} else {
  // Normal photo/reel post
  const cpRes = await fetch(`${API_BASE}/buzz/posts`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      text: "",
      mediaUrl: up.url,
      type: postType, // photo/reel
      privacy: "matches",
    }),
  });

  const cp = await cpRes.json();
  if (!cpRes.ok || !(cp?.post || cp?.success)) {
    throw new Error(cp?.error || "create post failed");
  }

  if (postType === "reel") {
    setActiveTab("reels");
    await fetchReels(true);
  } else {
    setActiveTab("feed");
    setOffset(0);
    await fetchFeed(0, true);
  }
}


  } catch (e) {
    console.error("QuickCreate error:", e);
    alert(`Upload failed. ${e?.message || ""}`.trim());
  } finally {
    setQuickUploading(false);
    postInputRef.current && (postInputRef.current.value = "");
    storyInputRef.current && (storyInputRef.current.value = "");
  }
}


  return (
    <div className="min-h-screen bg-gradient-to-br from-rose-50 to-pink-100 p-4">
      {/* Header */}
          

      <div className="flex justify-between items-center mb-6">
        {/* Left: Logo spot */}
        <div className="flex items-center gap-2">
          <img
            src="/assets/logo.png"
            alt="RomBuzz"
            className="w-8 h-8 rounded"
          />
          <h1 className="text-2xl font-bold text-pink-600">LetsBuzz </h1>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setShowFilters(!showFilters)}
            className="p-2 bg-white rounded-full shadow-md hover:bg-pink-50 transition"
            title="Filters"
          >
            <FaFilter className="text-pink-500" />
          </button>
     <button
  onClick={() => postInputRef.current?.click()}
  title="Create photo/reel"
  className="flex items-center gap-2 bg-pink-500 text-white px-4 py-2 rounded-full hover:bg-pink-600 transition"
>
  <FaPlus /> Create Buzz
</button>

        </div>
      </div>



      {/* Filters */}
      {showFilters && (
        <PostFilters
          filters={filters}
          onChange={handleFiltersChange}
          onClose={() => setShowFilters(false)}
        />
      )}
  {/* Stories Bar */}
<StoriesBar onCreateStory={() => storyInputRef.current?.click()} />
      {/* Tabs: Feed · Reels · Saved */}
      <div className="flex justify-around mb-6 bg-white rounded-2xl p-1 shadow-md">
        <button
          onClick={() => setActiveTab("feed")}
          className={`flex-1 py-3 rounded-xl font-semibold transition ${
            activeTab === "feed"
              ? "bg-pink-500 text-white shadow-md"
              : "text-gray-600 hover:bg-pink-50"
          }`}
        >
          <FaHeart className="inline mr-2" /> Feed
        </button>

        <button
          onClick={() => setActiveTab("reels")}
          className={`flex-1 py-3 rounded-xl font-semibold transition ${
            activeTab === "reels"
              ? "bg-pink-500 text-white shadow-md"
              : "text-gray-600 hover:bg-pink-50"
          }`}
        >
          <FaPlay className="inline mr-2" /> Reels
        </button>

        <button
          onClick={() => setActiveTab("saved")}
          className={`flex-1 py-3 rounded-xl font-semibold transition ${
            activeTab === "saved"
              ? "bg-pink-500 text-white shadow-md"
              : "text-gray-600 hover:bg-pink-50"
          }`}
        >
          <FaBookmark className="inline mr-2" /> Saved
        </button>
      </div>

      {/* FEED */}
      {activeTab === "feed" && (
        <div>
          {feed.length === 0 && !loading ? (
            <div className="text-center py-12">
              <div className="text-6xl mb-4">🐝</div>
              <p className="text-gray-500 text-lg mb-2">No buzzes yet</p>
              <p className="text-gray-400 mb-4">
                Be the first to start the conversation!
              </p>

            </div>
          ) : (
            <>
              {feed.map((post) => (
               <BuzzPost
                  key={post.id}
                  post={post}
                  token={token}
                  hideShare
                  onOpenComments={() => setCommentPost(post)}
                  onUpdate={() => fetchFeed(0, true)}
                />

              ))}
              {hasMore && (
                <div className="text-center mt-6">
                  <button
                    onClick={handleLoadMore}
                    disabled={loading}
                    className="bg-white text-pink-500 px-6 py-2 rounded-full border border-pink-300 hover:bg-pink-50 disabled:opacity-50 transition"
                  >
                    {loading ? "Loading..." : "Load More"}
                  </button>
                </div>
              )}
            </>
          )}
        </div>
      )}

     {/* REELS */}
{activeTab === "reels" && (
  <div
    className="relative w-full h-[calc(100vh-80px)] overflow-y-scroll snap-y snap-mandatory no-scrollbar bg-black"
    onScroll={(e) => {
      const cards = e.currentTarget.querySelectorAll("[data-reel-index]");
      const vh = window.innerHeight;
      cards.forEach((card, idx) => {
        const rect = card.getBoundingClientRect();
        const isVisible = rect.top >= 0 && rect.bottom <= vh * 1.1;
        const video = card.querySelector("video");
        if (video) {
          if (isVisible) video.play().catch(() => {});
          else video.pause();
        }
      });
    }}
  >
    {loading ? (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-pink-500"></div>
      </div>
    ) : reels.length === 0 ? (
      <div className="flex flex-col items-center justify-center h-full text-white">
        <FaPlay className="text-4xl text-gray-400 mb-4" />
        <p className="text-gray-400">No reels yet</p>
        <p className="text-gray-500 text-sm mt-2">You will see the reels of your matched users once they post!</p>
      </div>
    ) : (
      reels.map((post, index) => (
        <div
          key={post.id}
          data-reel-index={index}
          className="snap-start h-[100vh] w-full flex-shrink-0 relative"
        >
          <ReelCard
            post={post}
            token={token}
            reels={reels}
            index={index}
            onLike={() => fetchReels(true)}
            onComment={() => setCommentPost(post)}
            isActive={index === 0}
          />
        </div>
      ))
    )}
  </div>
)}

      {/* SAVED */}
      {activeTab === "saved" && (
        <div>
          {loading ? (
            <p className="text-center text-gray-500 mt-6">
              Loading saved posts…
            </p>
          ) : bookmarks.length === 0 ? (
            <div className="text-center py-12">
              <FaBookmark className="text-4xl text-gray-400 mx-auto mb-4" />
              <p className="text-gray-500">No saved posts yet</p>
              <p className="text-gray-400 text-sm mt-2">
                Bookmark posts you love to find them later
              </p>
            </div>
          ) : (
            bookmarks.map((post) => (
             <BuzzPost
                key={post.id}
                post={post}
                token={token}
                hideShare
                onOpenComments={() => setCommentPost(post)}
                onUpdate={fetchBookmarks}
              />

            ))
          )}
        </div>
      )}
{/* Hidden input for QuickCreate (photo/video). Hold to make Story */}



{quickUploading && (
  <div className="fixed bottom-4 right-4 bg-white shadow-lg rounded-full px-4 py-2 text-sm">
    Uploading…
  </div>
)}
{/* Hidden inputs for QuickCreate */}
<input
  ref={storyInputRef}
  type="file"
  accept="image/*,video/*"
  className="hidden"
  onChange={(e) => {
    const f = e.target.files?.[0];
    if (f) quickCreateFromFile(f, "story");
  }}
/>

<input
  ref={postInputRef}
  type="file"
  accept="image/*,video/*"
  className="hidden"
  onChange={(e) => {
    const f = e.target.files?.[0];
    if (f) quickCreateFromFile(f, "post");
  }}
/>

      {/* Create Post Modal */}
      {showCreateModal && (
        <CreatePostModal
          onClose={() => setShowCreateModal(false)}
          onPostCreated={handlePostCreated}
          token={token}
        />
      )}
{/* Story Viewer */}
{storyOpen && stories[storyOpen.index] && (
  <div className="fixed inset-0 bg-black/90 z-50 flex">
    <div className="m-auto w-full max-w-md relative">
      {/* Top bar */}
      <div className="absolute top-3 left-3 right-3 flex items-center justify-between z-10">
        <div className="flex items-center gap-2">
          <img
            src={stories[storyOpen.index].user?.avatar || "https://via.placeholder.com/64"}
            alt=""
            className="w-8 h-8 rounded-full"
          />
          <div className="text-white text-sm font-semibold">
            {stories[storyOpen.index].user?.firstName || "User"}
          </div>
        </div>
        <button
          onClick={() => setStoryOpen(null)}
          className="text-white/80 hover:text-white text-xl"
        >
          ✕
        </button>
      </div>

      {/* Media */}
      <div className="relative bg-black rounded-2xl overflow-hidden">
        {/\.(mp4|mov|webm|ogg)$/i.test(stories[storyOpen.index].mediaUrl || "") ||
         (stories[storyOpen.index].type === "reel" || stories[storyOpen.index].type === "video") ? (
          <video
            src={stories[storyOpen.index].mediaUrl}
            className="w-[90vw] max-w-md h-[80vh] object-contain"
            autoPlay
            muted
            playsInline
            onEnded={() => setStoryOpen(({ index }) => {
              const next = index + 1;
              return next < stories.length ? { index: next } : null;
            })}
          />
        ) : (
          <img
            src={stories[storyOpen.index].mediaUrl}
            alt=""
            className="w-[90vw] max-w-md h-[80vh] object-contain"
            onLoad={() => {
              // auto-advance after 5s for images
              setTimeout(() => {
                setStoryOpen((cur) => {
                  if (!cur) return null;
                  const next = cur.index + 1;
                  return next < stories.length ? { index: next } : null;
                });
              }, 5000);
            }}
          />
        )}
      </div>

      {/* Tappable areas for prev/next */}
      <div className="absolute inset-0 flex">
        <div
          className="flex-1"
          onClick={() =>
            setStoryOpen(({ index }) => ({ index: Math.max(0, index - 1) }))
          }
        />
        <div
          className="flex-1"
          onClick={() =>
            setStoryOpen(({ index }) => {
              const next = index + 1;
              return next < stories.length ? { index: next } : null;
            })
          }
        />
      </div>
    </div>
  </div>
)}

      {/* Centralized Comments Drawer with 3-dot actions */}
      <CommentsDrawer
        open={!!commentPost}
        onClose={() => setCommentPost(null)}
        post={commentPost}
        token={token}
                onChanged={() => {
            if (activeTab === "saved") fetchBookmarks();
            else if (activeTab === "reels") fetchReels(true);
            else fetchFeed(0, true);
          }}

      />
    </div>
  );
}
