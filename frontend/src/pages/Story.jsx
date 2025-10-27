// src/pages/Store.jsx
import React, { useEffect, useState, useRef } from "react";
import { FaPlus, FaChevronRight, FaChevronLeft } from "react-icons/fa";

const API_BASE = "http://localhost:4000/api";

export default function Store() {
  const [stories, setStories] = useState([]);
  const [storyOpen, setStoryOpen] = useState(null);
  const [viewedIds, setViewedIds] = useState(() =>
    JSON.parse(localStorage.getItem("RBZ:viewedStories") || "[]")
  );
  const token =
    localStorage.getItem("token") || sessionStorage.getItem("token");
  const scrollRef = useRef();

  // ---------- Fetch stories ----------
  useEffect(() => {
    (async () => {
      try {
        const res = await fetch(`${API_BASE}/buzz/feed?type=story&limit=50`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        const data = await res.json();
        const list = Array.isArray(data.posts) ? data.posts : [];
        setStories(
          list.filter(
            (s) =>
              s.isActive !== false &&
              (!s.expiresAt || s.expiresAt > Date.now())
          )
        );
      } catch (e) {
        console.error("Stories load error:", e);
      }
    })();
  }, [token]);

  // ---------- Scroll buttons ----------
  const scroll = (dir) => {
    if (!scrollRef.current) return;
    const offset = dir === "left" ? -300 : 300;
    scrollRef.current.scrollBy({ left: offset, behavior: "smooth" });
  };

  // ---------- Mark viewed ----------
  const markViewed = (id) => {
    if (!viewedIds.includes(id)) {
      const next = [...viewedIds, id];
      setViewedIds(next);
      localStorage.setItem("RBZ:viewedStories", JSON.stringify(next));
    }
  };

  // ---------- Handle auto-advance ----------
  useEffect(() => {
    if (!storyOpen) return;
    const s = stories[storyOpen.index];
    if (!s) return;
    markViewed(s.id);

    let timer;
    const el = document.getElementById("activeStoryMedia");
    if (!el) return;

    if (/\.(mp4|mov|webm|ogg)$/i.test(s.mediaUrl || "")) {
      // video → 30s max or actual duration
      el.onloadedmetadata = () => {
        const dur = Math.min(el.duration * 1000 || 30000, 30000);
        timer = setTimeout(() => nextStory(), dur);
      };
    } else {
      // image → 5s
      timer = setTimeout(() => nextStory(), 5000);
    }
    return () => clearTimeout(timer);
  }, [storyOpen]);

  const nextStory = () =>
    setStoryOpen((cur) => {
      if (!cur) return null;
      const next = cur.index + 1;
      return next < stories.length ? { index: next } : null;
    });

  const prevStory = () =>
    setStoryOpen((cur) => {
      if (!cur) return null;
      const prev = cur.index - 1;
      return prev >= 0 ? { index: prev } : cur;
    });

  return (
    <div className="min-h-screen bg-gradient-to-br from-rose-50 to-pink-100 p-4">
      {/* Header */}
      <div className="flex justify-between items-center mb-5">
        <h1 className="text-2xl font-bold text-pink-600">Stories</h1>
        <div className="flex gap-2">
          <button
            onClick={() => scroll("left")}
            className="bg-white rounded-full shadow p-2 hover:bg-pink-50"
          >
            <FaChevronLeft className="text-pink-500" />
          </button>
          <button
            onClick={() => scroll("right")}
            className="bg-white rounded-full shadow p-2 hover:bg-pink-50"
          >
            <FaChevronRight className="text-pink-500" />
          </button>
        </div>
      </div>

      {/* Horizontal Story Bar */}
      <div
        ref={scrollRef}
        className="flex gap-3 overflow-x-auto no-scrollbar pb-4"
      >
        {/* Create Story */}
        <button
          className="flex-shrink-0 w-28 h-48 bg-white rounded-xl shadow relative group"
          onClick={() => alert('Open story upload')}
        >
          <div className="absolute inset-0 rounded-xl overflow-hidden">
            <img
              src="/assets/story_placeholder.jpg"
              alt=""
              className="object-cover w-full h-full"
            />
            <div className="absolute inset-0 bg-black/20 group-hover:bg-black/10 transition" />
          </div>
          <div className="absolute bottom-3 left-0 right-0 text-center">
            <div className="bg-pink-500 text-white w-8 h-8 rounded-full flex items-center justify-center mx-auto mb-1">
              <FaPlus />
            </div>
            <div className="text-xs font-semibold text-gray-700">
              Create story
            </div>
          </div>
        </button>

        {/* Matched users’ stories */}
        {stories.map((s, i) => {
          const isViewed = viewedIds.includes(s.id);
          return (
            <div
              key={s.id}
              className="flex-shrink-0 w-28 h-48 bg-white rounded-xl shadow relative overflow-hidden hover:scale-[1.02] transition cursor-pointer"
            >
              {/* Story preview */}
              <div
                onClick={() => setStoryOpen({ index: i })}
                className="absolute inset-0"
              >
                <img
                  src={s.mediaUrl || s.user?.avatar || "https://via.placeholder.com/150"}
                  alt=""
                  className="object-cover w-full h-full"
                />
                <div className="absolute inset-0 bg-gradient-to-t from-black/60 via-transparent to-transparent" />
              </div>

              {/* Avatar ring */}
              <div className="absolute bottom-2 left-2 flex items-center gap-1 z-10">
                <div
                  onClick={(e) => {
                    e.stopPropagation();
                    window.location.href = `/viewProfile/${s.userId}`;
                  }}
                  className={`p-[2px] rounded-full ${
                    isViewed
                      ? "bg-gray-300"
                      : "bg-gradient-to-tr from-pink-500 to-rose-400"
                  }`}
                >
                  <img
                    src={s.user?.avatar || "https://via.placeholder.com/64"}
                    alt=""
                    className="w-8 h-8 rounded-full border-2 border-white object-cover cursor-pointer hover:scale-105 transition"
                    title={`View ${s.user?.firstName || "User"}'s profile`}
                  />
                </div>
                <div
                  onClick={(e) => {
                    e.stopPropagation();
                    window.location.href = `/viewProfile/${s.userId}`;
                  }}
                  className="text-xs text-white font-semibold drop-shadow cursor-pointer hover:underline"
                >
                  {s.user?.firstName || "User"}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Story Viewer */}
      {storyOpen && stories[storyOpen.index] && (
        <div className="fixed inset-0 bg-black/90 z-50 flex items-center justify-center">
          <div className="relative w-full max-w-md mx-auto">
            {/* Top bar */}
            <div className="absolute top-3 left-3 right-3 flex items-center justify-between z-10">
              <div className="flex items-center gap-2">
                <img
                  src={
                    stories[storyOpen.index].user?.avatar ||
                    "https://via.placeholder.com/64"
                  }
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

            {/* Story media */}
            <div className="bg-black rounded-xl overflow-hidden relative">
              {/\.(mp4|mov|webm|ogg)$/i.test(
                stories[storyOpen.index].mediaUrl || ""
              ) ? (
                <video
                  id="activeStoryMedia"
                  src={stories[storyOpen.index].mediaUrl}
                  className="w-[90vw] max-w-md h-[80vh] object-contain"
                  autoPlay
                  muted
                  playsInline
                />
              ) : (
                <img
                  id="activeStoryMedia"
                  src={stories[storyOpen.index].mediaUrl}
                  alt=""
                  className="w-[90vw] max-w-md h-[80vh] object-contain"
                />
              )}

              {/* Tap zones */}
              <div
                className="absolute inset-0 flex"
                onClick={(e) => {
                  const x = e.nativeEvent.offsetX;
                  const w = e.currentTarget.offsetWidth;
                  if (x < w / 2) prevStory();
                  else nextStory();
                }}
              >
                <div className="flex-1" />
                <div className="flex-1" />
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
