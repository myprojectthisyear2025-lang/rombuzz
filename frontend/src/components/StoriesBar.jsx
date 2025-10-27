import React, { useEffect, useRef, useState } from "react";
import { FaPlus, FaChevronLeft, FaChevronRight } from "react-icons/fa";

//const API_BASE = "http://localhost:4000/api";
const API_BASE = "http://localhost:4000/api";

export default function StoriesBar({ onCreateStory }) {
  const [stories, setStories] = useState([]);
  const [viewedIds, setViewedIds] = useState(
    JSON.parse(localStorage.getItem("RBZ:viewedStories") || "[]")
  );
  const [storyOpen, setStoryOpen] = useState(null);
  const [progress, setProgress] = useState(0);
  const token =
    localStorage.getItem("token") || sessionStorage.getItem("token");
  const scrollRef = useRef();
  const intervalRef = useRef();

  // === Fetch stories ===
  useEffect(() => {
    (async () => {
      try {
const res = await fetch(`${API_BASE}/stories`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        const data = await res.json();
const list = Array.isArray(data.stories) ? data.stories : [];
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

  // === Scroll arrows ===
  const scroll = (dir) => {
    if (!scrollRef.current) return;
    scrollRef.current.scrollBy({
      left: dir === "left" ? -300 : 300,
      behavior: "smooth",
    });
  };

  // === Mark viewed ===
  const markViewed = (id) => {
    if (!viewedIds.includes(id)) {
      const next = [...viewedIds, id];
      setViewedIds(next);
      localStorage.setItem("RBZ:viewedStories", JSON.stringify(next));
    }
  };

  // === Story navigation ===
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

  // === Handle playback + dynamic progress bar ===
  useEffect(() => {
    if (!storyOpen) return;

    const s = stories[storyOpen.index];
    if (!s) return;

    markViewed(s.id);
    setProgress(0);
    clearInterval(intervalRef.current);

    const el = document.getElementById("activeStoryMedia");
    let durationMs = 5000; // default 5s for image
    let timer;

    const startProgress = (dur) => {
      durationMs = Math.min(dur, 30000); // cap at 30s
      const startTime = Date.now();
      intervalRef.current = setInterval(() => {
        const elapsed = Date.now() - startTime;
        const pct = Math.min((elapsed / durationMs) * 100, 100);
        setProgress(pct);
        if (pct >= 100) {
          clearInterval(intervalRef.current);
          nextStory();
        }
      }, 100);
    };

    // If video, wait for metadata
    if (el && /\.(mp4|mov|webm|ogg)$/i.test(s.mediaUrl || "")) {
      el.onloadedmetadata = () => {
        const dur = el.duration * 1000 || 5000;
        startProgress(dur);
      };
    } else {
      startProgress(durationMs);
    }

    return () => clearInterval(intervalRef.current);
  }, [storyOpen]);

  // === Render ===
  return (
    <>
      {/* Horizontal story bubbles */}
      <div className="relative mb-4">
        <div className="flex justify-between px-2">
          <button
            onClick={() => scroll("left")}
            className="text-pink-500 hover:text-pink-600"
          >
            <FaChevronLeft />
          </button>
          <button
            onClick={() => scroll("right")}
            className="text-pink-500 hover:text-pink-600"
          >
            <FaChevronRight />
          </button>
        </div>

        <div
          ref={scrollRef}
          className="flex items-center gap-3 overflow-x-auto no-scrollbar p-2"
        >
          {/* Create Story */}
          <button
            className="flex flex-col items-center justify-center w-16"
onClick={onCreateStory}
          >
            <div className="w-14 h-14 rounded-full bg-gradient-to-br from-pink-400 to-rose-500 p-[2px]">
              <div className="w-full h-full rounded-full bg-white flex items-center justify-center">
                <span className="text-pink-500 text-2xl">+</span>
              </div>
            </div>
            <span className="text-xs mt-1 text-pink-600">Your Story</span>
          </button>

          {/* User stories */}
          {stories.map((s, i) => {
            const viewed = viewedIds.includes(s.id);
            return (
              <button
                key={s.id}
                onClick={() => setStoryOpen({ index: i })}
                className="flex flex-col items-center w-16"
              >
                <div
                  className={`w-14 h-14 rounded-full p-[2px] ${
                    viewed
                      ? "bg-gray-300"
                      : "bg-gradient-to-tr from-pink-500 to-rose-400"
                  }`}
                >
                  <img
                    src={
                      s.user?.avatar ||
                      "https://via.placeholder.com/64?text=User"
                    }
                    alt=""
                    className="w-full h-full rounded-full object-cover border-2 border-white"
                  />
                </div>
                <span className="text-[11px] mt-1 text-gray-700 truncate max-w-14">
                  {s.user?.firstName || "User"}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* === Story Viewer Modal === */}
      {storyOpen && stories[storyOpen.index] && (
        <div className="fixed inset-0 bg-black/90 z-50 flex items-center justify-center">
          <div className="relative w-full max-w-md mx-auto overflow-hidden rounded-2xl shadow-2xl">

            {/* Dynamic progress bar */}
            <div className="absolute top-0 left-0 right-0 h-1 bg-white/20">
              <div
                className="h-1 bg-white transition-all duration-100 ease-linear"
                style={{ width: `${progress}%` }}
              />
            </div>

            {/* Top header */}
            <div className="absolute top-3 left-3 right-3 flex items-center justify-between z-10">
              <div className="flex items-center gap-2">
                <img
                  src={
                    stories[storyOpen.index].user?.avatar ||
                    "https://via.placeholder.com/64"
                  }
                  alt="avatar"
                  className="w-8 h-8 rounded-full cursor-pointer border border-white/50"
                  onClick={() =>
                    (window.location.href = `/viewProfile/${stories[storyOpen.index].userId}`)
                  }
                />
                <div className="text-white text-sm font-semibold">
                  {(stories[storyOpen.index].user?.firstName || "") +
                    " " +
                    (stories[storyOpen.index].user?.lastName || "")}
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
            <div className="bg-black rounded-2xl overflow-hidden relative flex justify-center items-center">
              {/\.(mp4|mov|webm|ogg)$/i.test(
                stories[storyOpen.index].mediaUrl || ""
              ) ? (
                <video
                  id="activeStoryMedia"
                  src={stories[storyOpen.index].mediaUrl}
                  className="w-full h-[80vh] object-contain"
                  autoPlay
                  muted
                  playsInline
                />
              ) : (
                <img
                  id="activeStoryMedia"
                  src={stories[storyOpen.index].mediaUrl}
                  alt=""
                  className="w-full h-[80vh] object-contain"
                />
              )}

              {/* Prev/Next buttons */}
              <div className="absolute inset-0 flex justify-between items-center px-2">
                <button
                  onClick={prevStory}
                  className="text-white/70 hover:text-white bg-black/30 rounded-full p-2 transition"
                  title="Previous"
                >
                  <FaChevronLeft size={22} />
                </button>
                <button
                  onClick={nextStory}
                  className="text-white/70 hover:text-white bg-black/30 rounded-full p-2 transition"
                  title="Next"
                >
                  <FaChevronRight size={22} />
                </button>
              </div>
            </div>

            {/* Bottom gradient */}
            <div className="absolute bottom-0 left-0 right-0 h-32 bg-gradient-to-t from-black/70 via-black/20 to-transparent" />
          </div>
        </div>
      )}
    </>
  );
}
