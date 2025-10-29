// src/pages/ProfilePreview.jsx
import React, { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams, useLocation } from "react-router-dom";
import {
  FaArrowLeft,
  FaLock,
  FaHeart,
  FaTimes,
  FaMapMarkerAlt,
  FaHeadphones,
  FaCheckCircle,
  FaBan,
} from "react-icons/fa";

//const API_BASE = "http://localhost:4000/api";
const API_BASE = process.env.REACT_APP_API_BASE || "https://rombuzz-api.onrender.com/api";

const token = () =>
  localStorage.getItem("token") || sessionStorage.getItem("token") || "";

function calcAge(dob) {
  if (!dob) return null;
  try {
    const d = new Date(dob);
    if (Number.isNaN(d.getTime())) return null;
    const today = new Date();
    let age = today.getFullYear() - d.getFullYear();
    const hasHadBirthday =
      today.getMonth() > d.getMonth() ||
      (today.getMonth() === d.getMonth() && today.getDate() >= d.getDate());
    if (!hasHadBirthday) age -= 1;
    return age;
  } catch {
    return null;
  }
}

function formatHeight(h) {
  if (!h && h !== 0) return null;
  if (typeof h === "string") return h;
  if (typeof h === "number") {
    if (h > 100) return `${h} cm`;
    return `${h} in`;
  }
  return null;
}

function Chunk({ title, children }) {
  if (!children) return null;
  const empty =
    (typeof children === "string" && children.trim() === "") ||
    (Array.isArray(children) && children.length === 0);
  if (empty) return null;
  return (
    <div className="p-4 rounded-2xl bg-white/80 backdrop-blur border shadow-sm">
      <div className="text-sm font-semibold text-gray-800 mb-2">{title}</div>
      <div className="text-sm text-gray-700">{children}</div>
    </div>
  );
}

function TagList({ items = [] }) {
  if (!items || items.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-2">
      {items.slice(0, 12).map((x, i) => (
        <span
          key={`${x}-${i}`}
          className="px-2.5 py-1 rounded-full text-xs bg-rose-50 text-rose-700 border"
        >
          {String(x)}
        </span>
      ))}
    </div>
  );
}

function canShowField(previewObj, key, matched) {
  const vis = previewObj?.user?.fieldVisibility?.[key] || "public";
  if (vis === "public") return true;
  if (vis === "matches") return !!matched;
  return false;
}

export default function ProfilePreview() {
  const { id } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const fallback = location.state?.previewFromDiscover || null;

  const [loading, setLoading] = useState(true);
  const [preview, setPreview] = useState(null);
  const [error, setError] = useState("");
  const [buzzing, setBuzzing] = useState(false);
  const [blocked, setBlocked] = useState(false);

  const fetchUser = async () => {
    setLoading(true);
    setError("");
    try {
      const res = await fetch(`${API_BASE}/users/${id}`, {
        headers: { Authorization: `Bearer ${token()}` },
      });
      if (res.status === 403) {
        if (fallback) {
          setPreview({
            user: fallback,
            matched: false,
            likedByMe: false,
            likedMe: false,
            preview: true,
          });
          return;
        }
        const body = await res.json().catch(() => ({}));
        setError(body?.error || "Profile requires a match to view.");
        return;
      }
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error || "failed");
      setPreview({
        user: data.user || null,
        matched: !!data.matched,
        likedByMe: !!data.likedByMe,
        likedMe: !!data.likedMe,
        preview: data.preview === true || !data.matched,
      });
    } catch (e) {
      console.error(e);
      setError("Unable to load profile.");
    } finally {
      setLoading(false);
    }
  };

  const checkBlockStatus = async () => {
    const t =
      localStorage.getItem("token") || sessionStorage.getItem("token") || "";
    if (!t || !id) return;
    try {
      const r = await fetch(`${API_BASE}/api/blocks`, {
        headers: { Authorization: `Bearer ${t}` },
      });
      const j = await r.json();
      const myBlocks = j.blocks || [];
      const isBlocked = myBlocks.some((b) => b.id === id);
      setBlocked(isBlocked);
    } catch (err) {
      console.error("block check error:", err);
    }
  };

  useEffect(() => {
    checkBlockStatus();
    fetchUser();
  }, [id]);

  const u = preview?.user || null;
  const matched = !!preview?.matched;
  const isPreview = !matched && (u?.visibilityMode !== "full");

  const canShow = (fieldKey) => {
    const rule = u?.fieldVisibility?.[fieldKey] || "public";
    if (rule === "hidden") return false;
    if (rule === "matches") return matched;
    return true;
  };

  const media3 = useMemo(() => {
    if (!u) return [];
    const list = [];
    if (u.avatar)
      list.push({ id: "avatar", url: u.avatar, type: "image", privacy: "public" });
    const candidates = Array.isArray(u.media)
      ? u.media.filter((m) => m?.url && m.privacy !== "private")
      : [];
    const faceFirst = candidates.sort((a, b) => {
      const aFace = (a.caption || "").toLowerCase().includes("facebuzz") ? 1 : 0;
      const bFace = (b.caption || "").toLowerCase().includes("facebuzz") ? 1 : 0;
      return bFace - aFace;
    });
    for (const m of faceFirst) {
      if (list.length >= 3) break;
      list.push(m);
    }
    return list.slice(0, 3);
  }, [u]);

  const age = useMemo(() => calcAge(u?.dob), [u?.dob]);
  const heightStr = useMemo(() => formatHeight(u?.height), [u?.height]);
  const city = useMemo(() => u?.city || null, [u?.city]);

  const lookingFor = u?.intent || u?.vibe || "";
  const orientation = u?.orientation || "";
  const interests = Array.isArray(u?.interests) ? u.interests : [];
  const hobbies = Array.isArray(u?.hobbies) ? u.hobbies : [];
  const favorites = Array.isArray(u?.favorites) ? u.favorites : [];
  const likes = favorites
    .filter((f) => String(f).toLowerCase().startsWith("like:"))
    .map((x) => x.slice(5));
  const dislikes = favorites
    .filter((f) => String(f).toLowerCase().startsWith("dislike:"))
    .map((x) => x.slice(8));
  const genericFavs = favorites.filter(
    (f) =>
      !String(f).toLowerCase().startsWith("like:") &&
      !String(f).toLowerCase().startsWith("dislike:")
  );

  const doBuzz = async () => {
    if (!u?.id) return;
    setBuzzing(true);
    try {
      const res = await fetch(`${API_BASE}/likes`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token()}`,
        },
        body: JSON.stringify({ to: u.id }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error || "Failed to like");
      if (data.matched) {
        navigate(`/view/${u.id}`, { replace: true });
      } else {
        setPreview((p) =>
          p
            ? { ...p, likedByMe: true }
            : {
                user: u,
                preview: true,
                matched: false,
                likedByMe: true,
                likedMe: false,
              }
        );
      }
    } catch (e) {
      alert(e.message || "Something went wrong");
    } finally {
      setBuzzing(false);
    }
  };

  const doSkip = () => navigate(-1);

  return (
    <div className="min-h-screen bg-gradient-to-br from-pink-50 via-rose-50 to-red-50">
      {blocked ? (
        <div className="flex flex-col items-center justify-center h-screen text-center text-gray-600">
          <FaBan className="text-5xl mb-4 text-rose-500" />
          <p className="text-lg font-medium">You’ve blocked this user.</p>
          <p className="text-sm text-gray-500 mt-1">
            They can’t message or view your profile.
          </p>
          <button
            onClick={async () => {
              const t =
                localStorage.getItem("token") ||
                sessionStorage.getItem("token") ||
                "";
              if (!window.confirm("Unblock this user?")) return;
              await fetch(`${API_BASE}/api/blocks/${id}`, {
                method: "DELETE",
                headers: { Authorization: `Bearer ${t}` },
              });
              alert("User unblocked successfully.");
              setBlocked(false);
            }}
            className="mt-4 px-5 py-2 bg-rose-500 text-white rounded-full hover:bg-rose-600"
          >
            Unblock
          </button>
        </div>
      ) : (
        <div className="max-w-3xl mx-auto px-4 py-6">
          {/* Top bar */}
          <div className="flex items-center gap-3 mb-4">
            <button
              onClick={() => navigate(-1)}
              className="p-2 rounded-full bg-white border shadow hover:bg-gray-50"
              title="Back"
            >
              <FaArrowLeft />
            </button>
            <div className="text-lg font-semibold text-gray-900">
              {matched ? "Profile" : "Limited Profile Preview"}
            </div>
            {u?.verified && (
              <div className="ml-auto text-emerald-700 flex items-center gap-1 text-sm">
                <FaCheckCircle /> Verified
              </div>
            )}
          </div>

          {/* Lock banner if preview */}
          {isPreview && u?.visibilityMode !== "full" && (
            <div className="mb-4 p-3 rounded-xl bg-white/80 backdrop-blur border text-rose-700 flex items-center gap-2 shadow-sm">
              <FaLock />
              <span className="text-sm">
                This is a limited preview. Buzz each other to unlock full profiles.
              </span>
            </div>
          )}

          {/* Error */}
          {error && (
            <div className="mb-6 p-4 rounded-xl bg-rose-100 text-rose-800 border">
              {error}
            </div>
          )}

          {/* Media strip (up to 3) */}
          <div className="grid grid-cols-3 gap-3 mb-5">
            {canShowField(preview, "photos", matched) && media3.length > 0 ? (
              media3.map((m) => (
                <div
                  key={m.id}
                  className="h-40 rounded-2xl overflow-hidden bg-gray-200 shadow"
                >
                  <img
                    src={m.url}
                    alt="preview"
                    className="w-full h-full object-cover"
                    draggable={false}
                  />
                </div>
              ))
            ) : (
              <div className="col-span-3 h-40 rounded-2xl bg-gray-100 border grid place-items-center text-gray-500">
                {matched ? "No photos" : "Photos hidden in preview"}
              </div>
            )}
          </div>

          {/* Name + quick facts */}
          <div className="bg-white rounded-2xl shadow p-4 mb-5">
            <div className="flex flex-wrap items-center gap-2">
              <div className="text-2xl font-semibold text-gray-900">
                {u?.firstName} {u?.lastName}
              </div>
              {age != null && canShow("age") && (
                <span className="text-sm px-2 py-0.5 rounded-full bg-gray-100 border text-gray-700">
                  {age}
                </span>
              )}
              {u?.gender && (
                <span className="text-sm px-2 py-0.5 rounded-full bg-gray-100 border text-gray-700">
                  {u.gender}
                </span>
              )}
              {heightStr && canShow("height") && (
                <span className="text-sm px-2 py-0.5 rounded-full bg-gray-100 border text-gray-700">
                  {heightStr}
                </span>
              )}
              {orientation && canShow("orientation") && (
                <span className="text-sm px-2 py-0.5 rounded-full bg-gray-100 border text-gray-700">
                  {orientation}
                </span>
              )}
              {u?.zodiac && (
                <span className="text-sm px-2 py-0.5 rounded-full bg-gray-100 border text-gray-700">
                  {u.zodiac}
                </span>
              )}
            </div>

            {/* Location hint */}
            <div className="mt-2 text-xs text-gray-600 flex items-center gap-1">
              <FaMapMarkerAlt />
              {canShow("city") ? (
                city ? (
                  <span>{city}</span>
                ) : typeof u?.distanceMeters === "number" ? (
                  <span>
                    ~{Math.round(u.distanceMeters)} m from you (approx.)
                  </span>
                ) : (
                  <span>Nearby (approximate)</span>
                )
              ) : (
                <span>Location hidden</span>
              )}
            </div>

            {/* Bio */}
            {u?.bio && (
              <div className="mt-3 text-sm text-gray-700">
                {isPreview
                  ? u.bio.length > 160
                    ? `${u.bio.slice(0, 160)}…`
                    : u.bio
                  : u.bio}
              </div>
            )}
          </div>

          {/* Blocks */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {canShow("lookingFor") && (
              <Chunk title="Looking for">
                {lookingFor ? (
                  <span className="px-2.5 py-1 rounded-full text-xs bg-rose-50 text-rose-700 border">
                    {lookingFor}
                  </span>
                ) : (
                  <span className="text-gray-500">Not shared</span>
                )}
              </Chunk>
            )}

            <Chunk title="Interests">
              {canShowField(preview, "interests", matched) ? (
                interests.length ? (
                  <TagList items={interests} />
                ) : (
                  <span className="text-gray-500">Not shared</span>
                )
              ) : (
                <span className="text-gray-400 italic">Hidden</span>
              )}
            </Chunk>

            <Chunk title="Hobbies">
              {canShowField(preview, "hobbies", matched) ? (
                hobbies.length ? (
                  <TagList items={hobbies} />
                ) : (
                  <span className="text-gray-500">Not shared</span>
                )
              ) : (
                <span className="text-gray-400 italic">Hidden</span>
              )}
            </Chunk>

            <Chunk title="Likes">
              {canShowField(preview, "likes", matched) ? (
                likes.length ? (
                  <TagList items={likes} />
                ) : genericFavs.length ? (
                  <TagList items={genericFavs} />
                ) : (
                  <span className="text-gray-500">Not shared</span>
                )
              ) : (
                <span className="text-gray-400 italic">Hidden</span>
              )}
            </Chunk>

            <Chunk title="Dislikes">
              {canShowField(preview, "dislikes", matched) ? (
                dislikes.length ? (
                  <TagList items={dislikes} />
                ) : (
                  <span className="text-gray-500">Not shared</span>
                )
              ) : (
                <span className="text-gray-400 italic">Hidden</span>
              )}
            </Chunk>

            <Chunk title="Voice intro">
              {canShowField(preview, "voiceIntro", matched) ? (
                u?.voiceIntro ? (
                  <button
                    onClick={() => new Audio(u.voiceIntro).play().catch(() => {})}
                    className="px-3 py-2 rounded-full bg-white border shadow text-gray-700 flex items-center gap-2"
                  >
                    <FaHeadphones /> Play intro
                  </button>
                ) : (
                  <span className="text-gray-500">No voice intro</span>
                )
              ) : (
                <span className="text-gray-400 italic">Hidden</span>
              )}
            </Chunk>
          </div>

          {/* Controls */}
          {!matched && (
            <div className="mt-6 flex items-center justify-center gap-6">
              <button
                onClick={doSkip}
                className="w-14 h-14 rounded-full bg-white shadow hover:shadow-md border border-gray-200 flex items-center justify-center text-gray-600 hover:scale-105 transition"
                title="Back"
              >
                <FaTimes size={20} />
              </button>

              <button
                onClick={doBuzz}
                disabled={buzzing}
                title="Like to connect"
                className={`w-20 h-20 rounded-full relative overflow-hidden transition hover:scale-105 group
                bg-gradient-to-br from-rose-400 to-pink-500 text-white shadow-lg disabled:opacity-60`}
              >
                <span className="pointer-events-none absolute inset-0 opacity-0 group-hover:opacity-100 transition">
                  <span className="absolute -inset-10 rotate-45 bg-white/15 blur-2xl" />
                </span>
                <FaHeart size={26} className="mx-auto" />
              </button>
            </div>
          )}

          {/* Footer note */}
          <div className="mt-6 text-xs text-gray-500 text-center">
            Profiles unlock fully once you both like each other.
          </div>
        </div>
      )}
    </div>
  );
}
