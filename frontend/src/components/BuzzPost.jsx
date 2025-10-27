// src/components/BuzzPost.jsx
import React, { useEffect, useRef, useState } from "react";
import {
  FaComment,
  FaBookmark,
  FaEllipsisH,
  FaTrash,
  FaEye,
  FaEdit,
  FaReply,
} from "react-icons/fa";

const API_BASE = "https://rombuzz-api.onrender.com/api";

const EMOJIS = ["❤️", "😂", "😮", "😢", "🤗", "🔥", "👏", "🎉"];
// Cloudinary transform helper (no-op if not a Cloudinary URL)
function transformMedia(url, type = "photo") {
  if (!url) return url;
  try {
    const u = new URL(url);
    // only transform Cloudinary delivery URLs: /image/upload/ or /video/upload/
    const isCloudinary = /res\.cloudinary\.com|cloudinary\.com/.test(u.host);
    const isUploadPath = /\/(image|video)\/upload\//.test(u.pathname);
    if (!isCloudinary || !isUploadPath) return url;

    // choose preset per type
    // photos: 4:5 portrait-ish, videos(reels): 9:16
    const preset =
      type === "reel" || type === "video"
        ? "c_fill,ar_9:16,w_540,q_auto,f_auto"
        : "c_fill,ar_4:5,w_720,q_auto,f_auto";

    // inject transform segment right after ".../upload/"
    u.pathname = u.pathname.replace("/upload/", `/upload/${preset}/`);
    return u.toString();
  } catch {
    return url;
  }
}

export default function BuzzPost({
  post,
  token,
  onUpdate,
  onOpenComments,
  hideShare = true,
  compact = false,
}) {
  const [comment, setComment] = useState("");
  const [showComments, setShowComments] = useState(false);
    const [reacting, setReacting] = useState(false);
  const [comments, setComments] = useState([]);
const [showReactions, setShowReactions] = useState(false);
const reactionWrapRef = useRef(null);

// closes reaction popover on outside click
useEffect(() => {
  if (!showReactions) return;
  const onDocClick = (e) => {
    if (!reactionWrapRef.current) return;
    if (!reactionWrapRef.current.contains(e.target)) setShowReactions(false);
  };
  document.addEventListener("mousedown", onDocClick);
  return () => document.removeEventListener("mousedown", onDocClick);
}, [showReactions]);
  const [showMenu, setShowMenu] = useState(false);
  const [showReactionList, setShowReactionList] = useState(false);
// 🎥 Video / Reels playback controls
const videoRef = useRef(null);
const [isMuted, setIsMuted] = useState(true);

  // --- Local reaction UI state (so updates show instantly)
const [myReaction, setMyReaction] = useState(post.myReaction || null);
const [rc, setRc] = useState(null); // reactionCounts override: {emoji: count}
const [totalReacts, setTotalReacts] = useState(Object.keys(post.reactions || {}).length);

// re-init when post changes
useEffect(() => {
  setMyReaction(post.myReaction || null);
  const baseCounts = {};
  Object.values(post.reactions || {}).forEach((e) => {
    baseCounts[e] = (baseCounts[e] || 0) + 1;
  });
  setRc(baseCounts);
  const sum = Object.values(baseCounts).reduce((a, b) => a + b, 0);
  setTotalReacts(sum);
  // eslint-disable-next-line react-hooks/exhaustive-deps
}, [post.id]);


  // per-comment UI state
  const [menuFor, setMenuFor] = useState(null); // commentId for which menu is open
  const [editingId, setEditingId] = useState(null);
  const [editingText, setEditingText] = useState("");
  const [replyingId, setReplyingId] = useState(null);
  const [replyText, setReplyText] = useState("");

  const user =
    JSON.parse(localStorage.getItem("user") || sessionStorage.getItem("user") || "{}") || {};

  // ---- Helpers ----
  const formatTime = (timestamp) => {
    const now = Date.now();
    const diff = now - timestamp;
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);
    if (minutes < 1) return "Just now";
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    return `${days}d ago`;
  };
// Build a nested tree: [{...comment, replies: []}]
function buildCommentTree(list) {
  const map = new Map();
  const roots = [];
  (list || []).forEach((c) => map.set(c.id, { ...c, replies: [] }));
  (list || []).forEach((c) => {
    const node = map.get(c.id);
    if (c.parentId && map.has(c.parentId)) {
      map.get(c.parentId).replies.push(node);
    } else {
      roots.push(node);
    }
  });
  return roots;
}

// Single comment renderer (recursive)
function CommentItem({ c, depth = 0 }) {
  const isMine = c.userId === user.id || c.author?.id === user.id;
  const isEditing = editingId === c.id;
  const isReplying = replyingId === c.id;

  return (
    <div className="flex items-start gap-2" style={{ marginLeft: depth * 16 }}>
      <img
        src={c.author?.avatar || "https://via.placeholder.com/32"}
        alt={c.author?.firstName}
        className="w-6 h-6 rounded-full mt-1"
      />
      <div className="flex-1 bg-gray-50 rounded-lg p-2">
        <div className="flex justify-between items-start">
          <div className="flex items-center gap-2">
            <p className="font-medium text-sm">
              {c.author?.firstName} {c.author?.lastName}
            </p>
            <span className="text-xs text-gray-400">
              {formatTime(c.createdAt)}
            </span>
          </div>

          {/* comment menu */}
          <div className="relative">
            <button
              onClick={() => setMenuFor(menuFor === c.id ? null : c.id)}
              className="text-gray-400 hover:text-gray-600 p-1 rounded hover:bg-gray-100"
              aria-label="Comment menu"
            >
              <FaEllipsisH />
            </button>
            {menuFor === c.id && (
              <div className="absolute right-0 top-6 bg-white border rounded-lg shadow-md z-10 w-40">
                <button
                  onClick={() => {
                    setReplyingId(c.id);
                    setReplyText("");
                    setMenuFor(null);
                  }}
                  className="flex items-center gap-2 w-full text-left text-sm px-3 py-2 hover:bg-gray-50"
                >
                  <FaReply /> Reply
                </button>
                {isMine && (
                  <>
                    <button
                      onClick={() => {
                        setEditingId(c.id);
                        setEditingText(c.text);
                        setMenuFor(null);
                      }}
                      className="flex items-center gap-2 w-full text-left text-sm px-3 py-2 hover:bg-gray-50"
                    >
                      <FaEdit /> Edit
                    </button>
                    <button
                      onClick={async () => {
                        setMenuFor(null);
                        if (!window.confirm("Delete this comment?")) return;
                        try {
                          await deleteComment(c.id);
                          await loadComments();
                          onUpdate?.();
                        } catch (e) {
                          console.error("Delete comment failed:", e);
                          alert("Could not delete comment.");
                        }
                      }}
                      className="flex items-center gap-2 w-full text-left text-sm px-3 py-2 text-red-600 hover:bg-red-50"
                    >
                      <FaTrash /> Delete
                    </button>
                  </>
                )}
              </div>
            )}
          </div>
        </div>

        {/* body / edit */}
        {!isEditing ? (
          <p className="text-sm text-gray-700">{c.text}</p>
        ) : (
          <div className="mt-2 flex gap-2">
            <input
              value={editingText}
              onChange={(e) => setEditingText(e.target.value)}
              className="flex-1 border border-gray-300 rounded px-2 py-1 text-sm"
            />
            <button
              onClick={async () => {
                if (!editingText.trim()) return;
                try {
                  await patchComment(c.id, editingText.trim());
                  setEditingId(null);
                  setEditingText("");
                  await loadComments();
                  onUpdate?.();
                } catch (e) {
                  console.error("Edit comment failed:", e);
                  alert("Could not edit comment.");
                }
              }}
              className="px-3 py-1 rounded text-white bg-pink-500 hover:bg-pink-600 text-sm"
            >
              Save
            </button>
            <button
              onClick={() => {
                setEditingId(null);
                setEditingText("");
              }}
              className="px-3 py-1 rounded text-sm bg-gray-100 hover:bg-gray-200"
            >
              Cancel
            </button>
          </div>
        )}

        {/* reply box */}
        {isReplying && (
          <div className="mt-2 flex gap-2">
            <input
              value={replyText}
              onChange={(e) => setReplyText(e.target.value)}
              placeholder="Write a reply..."
              className="flex-1 border border-gray-300 rounded px-2 py-1 text-sm"
              onKeyDown={(e) => {
                if (e.key === "Enter" && replyText.trim()) {
                  addComment(replyText, c.id);
                  setReplyingId(null);
                  setReplyText("");
                }
              }}
            />
            <button
              onClick={() => {
                if (!replyText.trim()) return;
                addComment(replyText, c.id);
                setReplyingId(null);
                setReplyText("");
              }}
              className="px-3 py-1 rounded text-white bg-pink-500 hover:bg-pink-600 text-sm"
            >
              Reply
            </button>
            <button
              onClick={() => {
                setReplyingId(null);
                setReplyText("");
              }}
              className="px-3 py-1 rounded text-sm bg-gray-100 hover:bg-gray-200"
            >
              Cancel
            </button>
          </div>
        )}

        {/* children */}
        {Array.isArray(c.replies) && c.replies.length > 0 && (
          <div className="mt-2 space-y-2">
            {c.replies.map((child) => (
              <CommentItem key={child.id} c={child} depth={depth + 1} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

 // Prefer local override if present
const reactionCounts = rc || {};
const topReactions = Object.entries(reactionCounts)
  .sort(([, a], [, b]) => b - a)
  .slice(0, 3);

  // ---- Comments API ----
  const loadComments = async () => {
    try {
      const res = await fetch(`${API_BASE}/buzz/posts/${post.id}/comments`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      setComments(data.comments || []);
    } catch (err) {
      console.error("Load comments error:", err);
    }
  };

  const toggleComments = async () => {
  if (typeof onOpenComments === "function") {
    onOpenComments(post);
    return;
  }
  if (!showComments) {
    await loadComments(); // load when opening
  }
  setShowComments((s) => !s);
};

  const addComment = async (text, parentId = null) => {
    if (!text?.trim()) return;
    try {
      await fetch(`${API_BASE}/buzz/posts/${post.id}/comments`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ text: text.trim(), parentId }),
      });
      await loadComments();
      onUpdate?.();
    } catch (err) {
      console.error("Add comment error:", err);
    }
  };

  const patchComment = async (commentId, text) => {
    await fetch(`${API_BASE}/buzz/posts/${post.id}/comments/${commentId}`, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ text }),
    });
  };

  const deleteComment = async (commentId) => {
    await fetch(`${API_BASE}/buzz/posts/${post.id}/comments/${commentId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}` },
    });
  };

  // ---- Reactions API ----
 const handleReaction = async (emoji) => {
  try {
    const res = await fetch(`${API_BASE}/buzz/posts/${post.id}/react`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ emoji }),
    });
    const data = await res.json();
    // API returns: { success, myReaction, reactionCounts, totalReactions }
    setMyReaction(data.myReaction || emoji);
    if (data.reactionCounts) setRc(data.reactionCounts);
    if (typeof data.totalReactions === "number") setTotalReacts(data.totalReactions);
    setShowReactions(false);
    onUpdate?.(); // let parent refresh if it wants
  } catch (err) {
    console.error("Reaction error:", err);
  }
};


 const removeReaction = async () => {
  try {
    await fetch(`${API_BASE}/buzz/posts/${post.id}/react`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}` },
    });
    // optimistic local update
    if (myReaction) {
      const next = { ...(rc || {}) };
      if (next[myReaction]) {
        next[myReaction] = Math.max(0, next[myReaction] - 1);
        if (next[myReaction] === 0) delete next[myReaction];
      }
      setRc(next);
      setTotalReacts(Math.max(0, (totalReacts || 0) - 1));
    }
    setMyReaction(null);
    onUpdate?.();
  } catch (err) {
    console.error("Remove reaction error:", err);
  }
};


  // ---- Bookmark ----
  const toggleBookmark = async () => {
    try {
      if (post.hasBookmarked) {
        await fetch(`${API_BASE}/buzz/posts/${post.id}/bookmark`, {
          method: "DELETE",
          headers: { Authorization: `Bearer ${token}` },
        });
      } else {
        await fetch(`${API_BASE}/buzz/posts/${post.id}/bookmark`, {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
        });
      }
      onUpdate?.();
    } catch (err) {
      console.error("Bookmark error:", err);
    }
  };

  // ---- Post delete ----
  const deletePost = async () => {
    if (!window.confirm("Are you sure you want to delete this post?")) return;
    try {
      await fetch(`${API_BASE}/buzz/posts/${post.id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });
      onUpdate?.();
    } catch (err) {
      console.error("Delete post error:", err);
    }
  };

  return (
    <div className={`bg-white rounded-2xl shadow-md ${compact ? "p-3 mb-3" : "p-4 mb-4"}`}>
      {/* Header */}
      <div className="flex justify-between items-start mb-3">
        <div className="flex items-center space-x-3">
          <img
            src={post.user?.avatar || "https://via.placeholder.com/40"}
            alt={post.user?.firstName}
            className="w-10 h-10 rounded-full object-cover"
          />
          <div>
            <p className="font-semibold text-gray-800">
              {post.user?.firstName} {post.user?.lastName}
            </p>
            <div className="flex items-center gap-2 text-xs text-gray-500">
              <span>
                {formatTime(post.createdAt)}
              </span>
              {post.type !== "text" && <span className="capitalize">• {post.type}</span>}
              {post.expiresAt && (
                <span className="text-orange-500">• Expires {formatTime(post.expiresAt)}</span>
              )}
            </div>
          </div>
        </div>

        {/* Post menu */}
        <div className="relative">
          <button
            onClick={() => setShowMenu(!showMenu)}
            className="p-1 text-gray-400 hover:text-gray-600 rounded-full hover:bg-gray-100"
            aria-label="Post menu"
          >
            <FaEllipsisH />
          </button>

          {showMenu && (
            <div className="absolute right-0 top-8 bg-white border rounded-lg shadow-lg z-10 w-48">
              {post.userId === user.id && (
                <button
                  onClick={deletePost}
                  className="flex items-center gap-2 px-3 py-2 w-full text-left text-sm text-red-600 hover:bg-red-50"
                >
                  <FaTrash /> Delete Post
                </button>
              )}
              <button
                onClick={toggleBookmark}
                className="flex items-center gap-2 px-3 py-2 w-full text-left text-sm hover:bg-gray-50"
              >
                <FaBookmark /> {post.hasBookmarked ? "Remove Bookmark" : "Save Post"}
              </button>
              <button
                onClick={() => setShowMenu(false)}
                className="flex items-center gap-2 px-3 py-2 w-full text-left text-sm hover:bg-gray-50"
              >
                <FaEye /> Hide Post
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Text */}
      {post.text ? <p className="text-gray-800 mb-3 whitespace-pre-line">{post.text}</p> : null}

      {/* Media */}
  {post.mediaUrl && (
  <div className="mb-3">
    {/* derive a lighter, sized URL for Cloudinary assets */}
    {(() => {
      const isVid = post.type === "reel" || post.type === "video";
      const cld = (url, type) => {
        if (!url || !url.includes("/upload/")) return url;
        // images: 1080x1350 portrait, videos: 720x1280 9:16
        const t =
          type === "video"
            ? "f_auto,q_auto:eco,vc_auto,w_720,h_1280,c_fill,g_auto"
            : "f_auto,q_auto:good,w_1080,h_1350,c_fill,g_auto";
        return url.replace("/upload/", `/upload/${t}/`);
      };
      const mediaUrl = cld(post.mediaUrl, isVid ? "video" : "image");

      if (!isVid) {
        // PHOTO: keep IG-style 4:5 box
        return (
          <div className="relative w-full max-w-[640px] mx-auto aspect-[4/5] overflow-hidden rounded-xl">
            <img
              src={mediaUrl}
              alt="Post media"
              className="absolute inset-0 h-full w-full object-cover"
              loading="lazy"
            />
          </div>
        );
      }

      // REEL/VIDEO: strict 9:16 like IG/TikTok
      return (
        <div className="relative w-full max-w-[420px] mx-auto aspect-[9/16] overflow-hidden rounded-xl">
         {/* ✅ Smart autoplay + mute control for reels */}
<video
  ref={videoRef}
  src={post.mediaUrl}
  className="w-full rounded-lg bg-black"
  playsInline
  muted={isMuted}
  loop
  preload="metadata"
  onClick={() => {
    const v = videoRef.current;
    if (!v) return;
    if (v.paused) v.play();
    else v.pause();
  }}
  onLoadedData={() => {
    const v = videoRef.current;
    if (v) {
      // try auto-play silently
      v.play().catch(() => {});
    }
  }}
/>
+
+ {/* 🔈 Mute / Unmute toggle */}
+ <button
  onClick={() => setIsMuted(!isMuted)}
  className="absolute bottom-3 right-3 bg-black/50 text-white rounded-full p-2 text-xs hover:bg-black/70"
   title={isMuted ? "Unmute" : "Mute"}
 >
   {isMuted ? "🔇" : "🔊"}
 </button>


        </div>
      );
    })()}
  </div>
)}


      {/* Tags */}
      {post.tags?.length ? (
        <div className="flex flex-wrap gap-1 mb-3">
          {post.tags.map((tag) => (
            <span key={tag} className="px-2 py-1 bg-pink-100 text-pink-600 text-xs rounded-full">
              #{tag}
            </span>
          ))}
        </div>
      ) : null}

      {/* Stats */}
      <div className="flex justify-between items-center text-sm text-gray-500 mb-3">
       <button
  onClick={() => setShowReactionList(true)}
  className="flex items-center gap-1 hover:text-gray-700"
  aria-label="Show reactions"
>
  {totalReacts > 0 ? (
    <>
      <span>{topReactions.map(([e]) => e).join("")}</span>
      <span>{totalReacts}</span>
    </>
  ) : (
    <span className="text-gray-400">React</span>
  )}
</button>


        <button onClick={toggleComments} className="hover:text-gray-700" aria-label="Open comments">
          {post.commentCount || 0} comments
        </button>
      </div>

      {/* Actions */}
      <div className="flex justify-between border-t border-b border-gray-100 py-2 mb-3">
    {/* React */}
<div className="relative flex-1" ref={reactionWrapRef}>
  <button
    onClick={() => setShowReactions((s) => !s)}
   className={`flex items-center justify-center gap-1 w-full py-1 rounded-lg transition ${
  myReaction ? "text-pink-500 bg-pink-50" : "text-gray-500 hover:bg-gray-50"
}`}
title={myReaction ? "Change reaction" : "React"}

  >
    <span>{myReaction || "❤️"}</span>
    <span>React</span>
  </button>

  {showReactions && (
    <div
      className="absolute bottom-10 left-0 bg-white border rounded-full shadow-lg p-2 flex gap-1 z-20"
      role="dialog"
      aria-label="Reactions"
    >
      {EMOJIS.map((emoji) => (
        <button
          key={emoji}
          onClick={() => {
            handleReaction(emoji);
            setShowReactions(false);
          }}
          className="text-xl hover:scale-125 transition-transform"
          title={`React ${emoji}`}
        >
          {emoji}
        </button>
      ))}
   {myReaction && (
  <button
    onClick={() => {
      removeReaction();
      setShowReactions(false);
    }}
    className="ml-2 text-xs px-2 py-1 rounded-full bg-gray-100 hover:bg-gray-200"
  >
    Remove
  </button>
)}

    </div>
  )}
</div>


        {/* Comment */}
        <button
          onClick={toggleComments}
          className="flex-1 flex items-center justify-center gap-1 py-1 text-gray-500 hover:bg-gray-50 rounded-lg transition"
          title="Comments"
        >
          <FaComment />
          <span>Comment</span>
        </button>

        {/* Share (intentionally removed) */}
        {!hideShare ? <div className="flex-1" /> : null}

        {/* Save */}
        <button
          onClick={toggleBookmark}
          className={`flex-1 flex items-center justify-center gap-1 py-1 rounded-lg transition ${
            post.hasBookmarked ? "text-pink-500 bg-pink-50" : "text-gray-500 hover:bg-gray-50"
          }`}
          title={post.hasBookmarked ? "Saved" : "Save"}
        >
          <FaBookmark />
          <span>Save</span>
        </button>
      </div>

      {/* Inline Comments (when not using external drawer) */}
      {showComments && typeof onOpenComments !== "function" && (
        <div className="space-y-3">
          {/* New comment */}
          <div className="flex items-center gap-2">
            <img
              src={user.avatar || "https://via.placeholder.com/32"}
              alt="You"
              className="w-8 h-8 rounded-full"
            />
            <div className="flex-1 flex gap-2">
              <input
                value={comment}
                onChange={(e) => setComment(e.target.value)}
                placeholder="Write a comment..."
                className="flex-1 border border-gray-300 rounded-full px-3 py-2 text-sm focus:border-pink-500 focus:ring-1 focus:ring-pink-500"
                onKeyDown={(e) => e.key === "Enter" && addComment(comment)}
              />
              <button
                onClick={() => {
                  addComment(comment);
                  setComment("");
                }}
                disabled={!comment.trim()}
                className="bg-pink-500 text-white rounded-full px-4 py-2 text-sm hover:bg-pink-600 disabled:opacity-50 disabled:cursor-not-allowed transition"
              >
                Send
              </button>
            </div>
          </div>

          {/* List */}
          <div className="space-y-2 max-h-60 overflow-y-auto">
            {comments.map((c) => {
            const isMine = c.userId === user.id || c.author?.id === user.id;
              const isEditing = editingId === c.id;
              const isReplying = replyingId === c.id;

              return (
                <div key={c.id} className="flex items-start gap-2">
                  <img
                    src={c.author?.avatar || "https://via.placeholder.com/32"}
                    alt={c.author?.firstName}
                    className="w-6 h-6 rounded-full mt-1"
                  />
                  <div className="flex-1 bg-gray-50 rounded-lg p-2">
                    <div className="flex justify-between items-start">
                      <div className="flex items-center gap-2">
                        <p className="font-medium text-sm">
                          {c.author?.firstName} {c.author?.lastName}
                        </p>
                        <span className="text-xs text-gray-400">
                          {formatTime(c.createdAt)}
                        </span>
                      </div>

                      {/* comment menu */}
                      <div className="relative">
                        <button
                          onClick={() => setMenuFor(menuFor === c.id ? null : c.id)}
                          className="text-gray-400 hover:text-gray-600 p-1 rounded hover:bg-gray-100"
                          aria-label="Comment menu"
                        >
                          <FaEllipsisH />
                        </button>
                        {menuFor === c.id && (
                          <div className="absolute right-0 top-6 bg-white border rounded-lg shadow-md z-10 w-40">
                            <button
                              onClick={() => {
                                setReplyingId(c.id);
                                setReplyText("");
                                setMenuFor(null);
                              }}
                              className="flex items-center gap-2 w-full text-left text-sm px-3 py-2 hover:bg-gray-50"
                            >
                              <FaReply /> Reply
                            </button>
                            {isMine && (
                              <>
                                <button
                                  onClick={() => {
                                    setEditingId(c.id);
                                    setEditingText(c.text);
                                    setMenuFor(null);
                                  }}
                                  className="flex items-center gap-2 w-full text-left text-sm px-3 py-2 hover:bg-gray-50"
                                >
                                  <FaEdit /> Edit
                                </button>
                                <button
                                 onClick={async () => {
                                    setMenuFor(null);
                                    if (!window.confirm("Delete this comment?")) return;
                                    try {
                                      await deleteComment(c.id);
                                      await loadComments();
                                      onUpdate?.();
                                    } catch (e) {
                                      console.error("Delete comment failed:", e);
                                      alert("Could not delete comment.");
                                    }
                                  }}

                                  className="flex items-center gap-2 w-full text-left text-sm px-3 py-2 text-red-600 hover:bg-red-50"
                                >
                                  <FaTrash /> Delete
                                </button>
                              </>
                            )}
                          </div>
                        )}
                      </div>
                    </div>

                    {/* body / edit */}
                    {!isEditing ? (
                      <p className="text-sm text-gray-700">{c.text}</p>
                    ) : (
                      <div className="mt-2 flex gap-2">
                        <input
                          value={editingText}
                          onChange={(e) => setEditingText(e.target.value)}
                          className="flex-1 border border-gray-300 rounded px-2 py-1 text-sm"
                        />
                        <button
                         onClick={async () => {
                            if (!editingText.trim()) return;
                            try {
                              await patchComment(c.id, editingText.trim());
                              setEditingId(null);
                              setEditingText("");
                              await loadComments();
                              onUpdate?.();
                            } catch (e) {
                              console.error("Edit comment failed:", e);
                              alert("Could not edit comment.");
                            }
                          }}

                          className="px-3 py-1 rounded text-white bg-pink-500 hover:bg-pink-600 text-sm"
                        >
                          Save
                        </button>
                        <button
                          onClick={() => {
                            setEditingId(null);
                            setEditingText("");
                          }}
                          className="px-3 py-1 rounded text-sm bg-gray-100 hover:bg-gray-200"
                        >
                          Cancel
                        </button>
                      </div>
                    )}

                    {/* reply box */}
                    {isReplying && (
                      <div className="mt-2 flex gap-2">
                        <input
                          value={replyText}
                          onChange={(e) => setReplyText(e.target.value)}
                          placeholder="Write a reply..."
                          className="flex-1 border border-gray-300 rounded px-2 py-1 text-sm"
                          onKeyDown={(e) => {
                            if (e.key === "Enter" && replyText.trim()) {
                              addComment(replyText, c.id);
                              setReplyingId(null);
                              setReplyText("");
                            }
                          }}
                        />
                        <button
                          onClick={() => {
                            if (!replyText.trim()) return;
                            addComment(replyText, c.id);
                            setReplyingId(null);
                            setReplyText("");
                          }}
                          className="px-3 py-1 rounded text-white bg-pink-500 hover:bg-pink-600 text-sm"
                        >
                          Reply
                        </button>
                        <button
                          onClick={() => {
                            setReplyingId(null);
                            setReplyText("");
                          }}
                          className="px-3 py-1 rounded text-sm bg-gray-100 hover:bg-gray-200"
                        >
                          Cancel
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Reaction List Modal */}
      {showReactionList && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-2xl p-6 w-full max-w-sm">
            <div className="flex justify-between items-center mb-4">
              <h3 className="font-semibold">Reactions</h3>
              <button
                onClick={() => setShowReactionList(false)}
                className="text-gray-500 hover:text-gray-700"
              >
                ✕
              </button>
            </div>
            <div className="space-y-2 max-h-60 overflow-y-auto">
              {Object.entries(reactionCounts).map(([emoji, count]) => (
                <div key={emoji} className="flex justify-between items-center p-2 hover:bg-gray-50 rounded">
                  <span className="text-xl">{emoji}</span>
                  <span className="text-gray-600">{count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
