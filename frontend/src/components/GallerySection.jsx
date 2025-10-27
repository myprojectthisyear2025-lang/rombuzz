// src/components/GallerySection.jsx
import React, { useEffect, useState } from "react";

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
      onClick={onClick}
      className={`w-full text-left px-3 py-2 hover:bg-gray-50 ${danger ? "text-red-600" : "text-gray-700"}`}
    >
      {children}
    </button>
  );
export default function GallerySection({
  faceBuzz,
  photoBuzz,
  reelsBuzz,
  editMediaCaption,
  toggleMediaPrivacy,
  deleteMedia,
}) {
  const [activeTab, setActiveTab] = useState(null); // which box is open
  const [activeMedia, setActiveMedia] = useState(null);
  const [openMenuForMedia, setOpenMenuForMedia] = useState(null);
const [showComments, setShowComments] = useState(false);
const [commentText, setCommentText] = useState("");
const [openCommentMenu, setOpenCommentMenu] = useState(null);
const [replyTo, setReplyTo] = useState(null);

// ✅ Mock local like/comment handlers (backend-ready)
const handleLike = (id) => {
  setActiveMedia((prev) => ({
    ...prev,
    likes: prev.likes?.includes("You")
      ? prev.likes.filter((n) => n !== "You")
      : [...(prev.likes || []), "You"],
  }));
};

const handleDeleteComment = (idx) => {
  setActiveMedia((prev) => ({
    ...prev,
    comments: prev.comments.filter((_, i) => i !== idx),
  }));
};

const handleLikeComment = (idx) => {
  setActiveMedia((prev) => ({
    ...prev,
    comments: prev.comments.map((c, i) =>
      i === idx
        ? {
            ...c,
            likes: c.likes?.includes("You")
              ? c.likes.filter((n) => n !== "You")
              : [...(c.likes || []), "You"],
          }
        : c
    ),
  }));
};

const handleAddComment = (id, text) => {
  if (!text.trim()) return;
  setActiveMedia((prev) => ({
    ...prev,
    comments: [...(prev.comments || []), { user: "You", text }],
  }));
};

  // ✅ force re-render when new uploads arrive
  useEffect(() => {}, [faceBuzz, photoBuzz, reelsBuzz]);

  const buckets = [
    { key: "face", label: "FaceBuzz", data: faceBuzz, color: "text-pink-600" },
    { key: "photo", label: "PhotoBuzz", data: photoBuzz, color: "text-rose-600" },
    { key: "reels", label: "ReelsBuzz", data: reelsBuzz, color: "text-red-600" },
  ];

  const openBucket = buckets.find((b) => b.key === activeTab);

  return (
    <div className="mt-6">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {buckets.map((bucket) => (
          <div
            key={bucket.key}
            onClick={() => setActiveTab(bucket.key)}
            className="bg-white border rounded-2xl shadow p-4 flex flex-col cursor-pointer hover:shadow-md transition"
          >
            <h4
              className={`font-semibold ${bucket.color} mb-2 flex items-center justify-between`}
            >
              <span>{bucket.label}</span>
              <span className="text-xs text-gray-400">
                {bucket.data.length} item(s)
              </span>
            </h4>
            <div className="flex-1 flex items-center justify-center mt-4">
  {bucket.data.length === 0 ? (
    <p className="text-gray-400 text-sm italic">
      No {bucket.label} items yet
    </p>
  ) : (
    <>
      {bucket.data[0].type === "video" ? (
        <video
          src={bucket.data[0].url}
          className="w-32 h-32 object-cover rounded-xl shadow-md"
          muted
          loop
          autoPlay
        />
      ) : (
        <img
          src={bucket.data[0].url}
          alt=""
          className="w-32 h-32 object-cover rounded-xl shadow-md"
        />
      )}
    </>
  )}
</div>

          </div>
        ))}
      </div>

      {/* Modal for selected bucket */}
      {openBucket && (
        <div
          className="fixed inset-0 bg-black/60 flex items-center justify-center z-50"
          onClick={() => setActiveTab(null)}
        >
          <div
            className="bg-white rounded-2xl shadow-xl max-w-3xl w-full p-6 relative"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              className="absolute top-4 right-4 text-gray-500 hover:text-gray-700"
              onClick={() => setActiveTab(null)}
            >
              ✕
            </button>
            <h3
              className={`font-semibold text-lg mb-4 ${openBucket.color} flex items-center justify-between`}
            >
              {openBucket.label}
              <span className="text-xs text-gray-400">
                {openBucket.data.length} item(s)
              </span>
            </h3>

            {openBucket.data.length === 0 ? (
              <p className="text-gray-400 text-center py-10">
                No {openBucket.label} items yet
              </p>
            ) : (
             <div className="flex overflow-x-auto gap-4 p-2 snap-x snap-mandatory scrollbar-thin scrollbar-thumb-pink-400/60">
  {openBucket.data.map((m, idx) => (
    <div
      key={m.id}
      className="relative flex-shrink-0 w-60 h-72 snap-center cursor-pointer rounded-2xl overflow-hidden shadow-md hover:shadow-lg transition-all"
      onClick={() => setActiveMedia({ ...m, index: idx })}
    >
      {m.type === "video" ? (
        <video
          src={m.url}
          className="w-full h-full object-cover"
          muted
          loop
          autoPlay
        />
      ) : (
        <img src={m.url} alt="" className="w-full h-full object-cover" />
      )}
      <div className="absolute inset-0 bg-gradient-to-t from-black/40 via-transparent to-transparent opacity-0 hover:opacity-100 transition-all flex flex-col justify-end p-3 text-white">
        <p className="truncate text-sm">{m.caption || "No caption"}</p>
      </div>
    </div>
  ))}
</div>

            )}
          </div>
        </div>
      )}

      {/* Full-screen preview */}
      {activeMedia && (
        <div
          className="fixed inset-0 bg-black/70 flex items-center justify-center z-[60]"
          onClick={() => setActiveMedia(null)}
        >
          <div
            className="bg-white rounded-2xl p-4 max-w-lg w-full relative shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
              
            {/* Navigation arrows */}
<button
  onClick={() =>
    setActiveMedia((prev) => {
      const list = openBucket.data;
      const next = (prev.index - 1 + list.length) % list.length;
      return { ...list[next], index: next };
    })
  }
  className="absolute left-4 top-1/2 -translate-y-1/2 text-white bg-black/40 hover:bg-pink-500 p-3 rounded-full shadow-lg transition-all text-xl"
>
  ‹
</button>

<button
  onClick={() =>
    setActiveMedia((prev) => {
      const list = openBucket.data;
      const next = (prev.index + 1) % list.length;
      return { ...list[next], index: next };
    })
  }
  className="absolute right-4 top-1/2 -translate-y-1/2 text-white bg-black/40 hover:bg-pink-500 p-3 rounded-full shadow-lg transition-all text-xl"
>
  ›
</button>

            {activeMedia.type === "video" ? (
              <video
                src={activeMedia.url}
                controls
                className="rounded-lg w-full max-h-[70vh] object-contain"
              />
            ) : (
              <img
                src={activeMedia.url}
                className="rounded-lg w-full max-h-[70vh] object-contain"
                alt=""
              />
            )}
            {/* --- Likes + Comments under the media --- */}
<div className="mt-4 flex flex-col items-center text-white">
  <div className="flex gap-6 mb-2">
    <button
      onClick={() => handleLike(activeMedia.id)}
      className="flex items-center gap-2 bg-pink-600/20 hover:bg-pink-600/40 rounded-full px-4 py-2 transition"
    >
      ❤️ <span>{activeMedia.likes?.length || 0}</span>
    </button>
    <button
      onClick={() => setShowComments((v) => !v)}
      className="flex items-center gap-2 bg-pink-600/20 hover:bg-pink-600/40 rounded-full px-4 py-2 transition"
    >
      💬 <span>{activeMedia.comments?.length || 0}</span>
    </button>
  </div>

  {showComments && (
    <div className="w-full max-w-md bg-white/10 rounded-xl p-3 max-h-40 overflow-y-auto">
    {activeMedia.comments?.length > 0 ? (
  activeMedia.comments.map((c, i) => (
    <div
      key={i}
      className="relative bg-gray-100 rounded-lg px-3 py-2 mb-2 flex justify-between items-start"
    >
      <div className="flex-1">
        <p className="text-sm text-black">
          <span className="font-semibold text-pink-600">{c.user}: </span>
          {c.text}
        </p>

        {/* ❤️ Likes count */}
        {c.likes?.length > 0 && (
          <p className="text-xs text-gray-500 mt-1">
            ❤️ {c.likes.length} like{c.likes.length > 1 ? "s" : ""}
          </p>
        )}
      </div>

      {/* ❤️ Like + 3 dots */}
      <div className="flex items-center gap-1 ml-2">
        <button
          onClick={() => handleLikeComment(i)}
          className="text-pink-500 hover:text-pink-600 text-sm"
        >
          ❤️
        </button>

        <button
          onClick={() =>
            setOpenCommentMenu(openCommentMenu === i ? null : i)
          }
          className="text-gray-500 hover:text-gray-700 text-lg"
        >
          ⋯
        </button>

        {/* 3-dot menu */}
        {openCommentMenu === i && (
          <div className="absolute right-0 top-8 bg-white border rounded-xl shadow-lg z-20 text-sm">
            {/* Owner menu (author of post) */}
            {true && ( // 🔥 replace with condition: if user owns the post
              <>
                <button
                  onClick={() => {
                    setReplyTo(c.user);
                    setOpenCommentMenu(null);
                  }}
className="block px-4 py-2 w-full text-left text-gray-800 font-medium hover:bg-pink-100 hover:text-pink-600 transition"
                >
                  Reply
                </button>
                <button
                  onClick={() => {
                    handleDeleteComment(i);
                    setOpenCommentMenu(null);
                  }}
                  className="block px-4 py-2 hover:bg-gray-50 w-full text-left text-red-600"
                >
                  Delete
                </button>
              </>
            )}
            {/* Matched user menu example */}
            {false && ( // 🔥 replace with actual match condition
              <>
                <button
                  onClick={() => {
                    // future edit logic
                    setOpenCommentMenu(null);
                  }}
                  className="block px-4 py-2 hover:bg-gray-50 w-full text-left"
                >
                  Edit
                </button>
                <button
                  onClick={() => {
                    setReplyTo(c.user);
                    setOpenCommentMenu(null);
                  }}
                  className="block px-4 py-2 hover:bg-gray-50 w-full text-left"
                >
                  Reply
                </button>
                <button
                  onClick={() => {
                    handleDeleteComment(i);
                    setOpenCommentMenu(null);
                  }}
                  className="block px-4 py-2 hover:bg-gray-50 w-full text-left text-red-600"
                >
                  Delete
                </button>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  ))
) : (

        <p className="text-gray-400 text-sm italic">No comments yet</p>
      )}
    </div>
  )}

  <form
    onSubmit={(e) => {
      e.preventDefault();
      handleAddComment(activeMedia.id, commentText);
      setCommentText("");
    }}
    className="flex items-center gap-3 mt-3 w-full max-w-md"
  >
    {replyTo && (
  <p className="text-xs text-gray-500 mb-1">
    Replying to <span className="font-semibold text-pink-600">{replyTo}</span>
  </p>
)}

    <input
      type="text"
      value={commentText}
      onChange={(e) => setCommentText(e.target.value)}
      placeholder="Add a comment..."
className="flex-1 bg-white text-black text-sm rounded-full px-3 py-2 outline-none placeholder-gray-500 border border-gray-300 focus:border-pink-400 shadow-sm"
    />
    <button
      type="submit"
      className="text-pink-400 hover:text-pink-500 font-semibold text-sm"
    >
      Post
    </button>
  </form>
</div>

            <div className="mt-3 text-sm">
              <p className="font-semibold">
                {activeMedia.caption || "No caption"}
              </p>
              <p className="text-gray-500 text-xs">
                {activeMedia.privacy === "private" ? "Private" : "Public"}
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
