// src/pages/Profile.jsx
import React, { useEffect, useMemo, useRef, useState } from "react";
// === Icons & helpers ===
import {
  FaEllipsisV,
  FaHeart,
  FaReply,
  FaTrash,
  FaEdit,
  FaLock,
  FaUnlock,
} from "react-icons/fa";

import { useNavigate } from "react-router-dom";
import SocialSection from "../components/SocialSection";
import GallerySection from "../components/GallerySection";
import BuzzStreak from "../components/BuzzStreak";



/**
 * =============================================================
 * Rombuzz — Profile.jsx (Full page)
 * =============================================================
 */

//const API_BASE = "http://localhost:4000/api";
const API_BASE = "http://localhost:4000/api";

// Cloudinary (unsigned) — 
const CLOUD_NAME ="drcxu0mks";
const UPLOAD_PRESET ="rombuzz_unsigned";

// Reaction palette (long-press on heart)
const REACTION_SET = ["❤️", "😂", "😢", "🤗", "😡"];

// Chip options
const INTEREST_OPTIONS = [
  "Music",
  "Travel",
  "Movies",
  "Foodie",
  "Sports",
  "Art",
  "Books",
  "Gaming",
  "Fitness",
  "Pets",
];
const HOBBY_OPTIONS = [
  "Hiking",
  "Cooking",
  "Photography",
  "Dancing",
  "Yoga",
  "Coding",
  "Board Games",
  "Gardening",
  "Cycling",
  "Volunteering",
];

// Helpers
const getToken = () =>
  localStorage.getItem("token") || sessionStorage.getItem("token") || "";

const saveUserToStorage = (user) => {
  if (localStorage.getItem("token")) {
    localStorage.setItem("user", JSON.stringify(user));
  } else {
    sessionStorage.setItem("user", JSON.stringify(user));
  }
};

const loadUserFromStorage = () => {
  const saved = localStorage.getItem("user") || sessionStorage.getItem("user");
  return saved ? JSON.parse(saved) : null;
};

// Parse a "voice:<url>" entry from favorites
const extractVoiceFromFavorites = (favorites = []) => {
  for (const item of favorites) {
    if (typeof item === "string" && item.startsWith("voice:")) {
      return item.slice("voice:".length);
    }
  }
  return "";
};

// Parse a "blur:<mode>" entry from favorites (mode: "clear" | "blurred")
const extractBlurMode = (favorites = []) => {
  for (const item of favorites) {
    if (typeof item === "string" && item.startsWith("blur:")) {
      const mode = item.slice("blur:".length);
      if (mode === "clear" || mode === "blurred") return mode;
    }
  }
  return "blurred"; // default safer choice
};

// Format "how long ago"
const timeAgo = (ts) => {
  const diff = Date.now() - (ts || Date.now());
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d < 7) return `${d}d ago`;
  const w = Math.floor(d / 7);
  if (w < 5) return `${w}w ago`;
  const mo = Math.floor(d / 30);
  if (mo < 12) return `${mo}mo ago`;
  const y = Math.floor(d / 365);
  return `${y}y ago`;
};

// Decide bucket (folder) for gallery media
const bucketForMedia = (m) => {
  // FaceBuzz: any media with caption 'facebuzz' (we'll set it when avatar changes)
  if ((m.caption || "").toLowerCase().includes("facebuzz")) return "face";
  if (m.type === "video") return "reels";
  // everything else goes to PhotoBuzz
  return "photos";
};

// Privacy label utility (server stores m.privacy or post.privacy)
const privacyLabel = (v) => (v === "private" ? "Private" : "Public");
// === Visibility controls (global + per-field) ===
const VISIBILITY_MODES = [
  { key: "auto", label: "Auto (blur until match)" },
  { key: "limited", label: "Limited preview" },
  { key: "full", label: "Full (except items you mark Matches-only)" },
  { key: "hidden", label: "Hidden (not in Discover)" },
];

const FIELD_KEYS = [
  { key: "age", label: "Age" },
  { key: "height", label: "Height" },
  { key: "city", label: "City" },
  { key: "orientation", label: "Orientation" },
  { key: "interests", label: "Interests" },
  { key: "hobbies", label: "Hobbies" },
  { key: "likes", label: "Likes" },
  { key: "dislikes", label: "Dislikes" },
  { key: "lookingFor", label: "Looking for" },
  { key: "voiceIntro", label: "Voice intro" },
  { key: "photos", label: "Photos" },
];

const FieldAudienceRow = ({ k, label, value, onChange, disabled }) => (
  <div className="flex items-center justify-between py-1.5">
    <div className="text-sm text-gray-700">{label}</div>
    <div className="flex gap-2">
      {["public", "matches", "hidden"].map((opt) => (
        <button
          key={opt}
          type="button"
          disabled={disabled}
          onClick={() => onChange(k, opt)}
          className={`px-2.5 py-1 rounded-full text-xs border ${
            value === opt
              ? "bg-rose-500 text-white border-rose-500"
              : "bg-white text-gray-700 border-gray-300 hover:border-rose-300"
          } ${disabled ? "opacity-50 cursor-not-allowed" : ""}`}
        >
          {opt === "public" ? "Public" : opt === "matches" ? "Matches only" : "Hidden"}
        </button>
      ))}
    </div>
  </div>
);

// ------------------------------------------------------------------
// Main Component
// ------------------------------------------------------------------
export default function Profile({ user: propUser, setUser }) {
  const navigate = useNavigate();

  // Base user
  const [loading, setLoading] = useState(true);
  const [user, setLocalUser] = useState(null);
  // 🔥 BuzzStreak state (for current streak info)
  const [streak, setStreak] = useState({ count: 0, nextReward: null });
// === BuzzStreak click handler ===
const handleBuzzStreak = async (targetId) => {
  const token = getToken();
  if (!token) return alert("Login required");

  try {
    const res = await fetch(`${API_BASE}/matchstreak/${targetId}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Failed");

    // ✅ Save streak & next reward to local state
    setStreak({
      ...data.streak,
      nextReward: data.nextReward || null,
    });

    console.log("✅ BuzzStreak registered:", data.streak);
    alert(
      data.nextReward
        ? `🔥 BuzzStreak Day ${data.streak.count}! Next → ${data.nextReward.reward} (Day ${data.nextReward.day})`
        : `🔥 BuzzStreak Day ${data.streak.count}! All rewards unlocked!`
    );
  } catch (err) {
    console.error("BuzzStreak error", err);
    alert("Could not buzz.");
  }
};
// --- BuzzStreak reward tiers ---
const BUZZSTREAK_REWARDS = [
 
];

// --- Subcomponent: shows upcoming milestones ---
function BuzzStreakRewards({ currentDay }) {
  const next = BUZZSTREAK_REWARDS.find(r => r.day > currentDay);
  return (
    <div className="mt-2 text-sm bg-white/60 backdrop-blur p-3 rounded-xl shadow">
      
      <ul className="space-y-1 text-gray-700">
        {BUZZSTREAK_REWARDS.map((r) => (
          <li
            key={r.day}
            className={`flex justify-between items-center ${
              r.day === next?.day ? "font-bold text-rose-600" : ""
            }`}
          >
            <span>Day {r.day}</span>
            <span>{r.reward}</span>
          </li>
        ))}
      </ul>
      {next ? (
        <div className="mt-2 text-xs text-gray-500">
          Next: Reach Day {next.day} to unlock <b>{next.reward}</b>
        </div>
      ) : (
        <div className="mt-2 text-xs text-green-600 font-semibold">
          🎉 Check In everyday to keep your streak blazing!
        </div>
      )}
    </div>
  );
}


  // Tabs: info | gallery | posts (renamed to MyBuzz visually)
  const [tab, setTab] = useState("info");

  // Edit profile
  const [editMode, setEditMode] = useState(false);
  const [form, setForm] = useState({
  firstName: "",
  lastName: "",
  bio: "",
  gender: "",
  dob: "",
  location: "",
  interests: [],
  hobbies: [],
  favorites: [], // stores: "voice:<url>", "blur:<clear|blurred>" (legacy)
  orientation: "",

  // NEW: smart visibility
  visibilityMode: "auto", // "auto" | "limited" | "full" | "hidden"
  fieldVisibility: {
    age: "public",
    height: "public",
    city: "public",
    orientation: "public",
    interests: "public",
    hobbies: "public",
    likes: "public",
    dislikes: "public",
    lookingFor: "public",
    voiceIntro: "public",
    photos: "matches",
  },
});


  // Derived fields
  const fullName = useMemo(
    () => [user?.firstName, user?.lastName].filter(Boolean).join(" "),
    [user]
  );

  // Avatar
  const avatarInputRef = useRef(null);
  const [avatarPreview, setAvatarPreview] = useState(null);
  const [avatarUploading, setAvatarUploading] = useState(false);
const [avatarUrl, setAvatarUrl] = useState("");

useEffect(() => {
  setAvatarUrl(avatarPreview || user?.avatar || "");
}, [avatarPreview, user?.avatar]);
  // Voice Intro
  const [voiceUrl, setVoiceUrl] = useState(""); // current voice intro URL
  const [recorder, setRecorder] = useState(null);
  const [recording, setRecording] = useState(false);
  const [recordChunks, setRecordChunks] = useState([]);
  const [recordElapsed, setRecordElapsed] = useState(0);
  const recordTimerRef = useRef(null);
  const [voiceUploading, setVoiceUploading] = useState(false);

  // Gallery
  const mediaInputRef = useRef(null);
  const [media, setMedia] = useState([]); // stored from server
  // 🩷 Gallery modal
const [activeMedia, setActiveMedia] = useState(null);

  const [mediaUploading, setMediaUploading] = useState(false);
  const [mediaCaption, setMediaCaption] = useState("");

  // Gallery filter buckets
  const faceBuzz = useMemo(() => media.filter((m) => bucketForMedia(m) === "face"), [media]);
  const photoBuzz = useMemo(() => media.filter((m) => bucketForMedia(m) === "photos"), [media]);
  const reelsBuzz = useMemo(() => media.filter((m) => bucketForMedia(m) === "reels"), [media]);


  // Three-dot menus state
const [openMenuForMedia, setOpenMenuForMedia] = useState(null);
const [openMenuForPost, setOpenMenuForPost] = useState(null);
const [openMenuForComment, setOpenMenuForComment] = useState(null); // ⬅️ add this
  // Expand/collapse state for "Who can see each item?"
  const [showAudience, setShowAudience] = useState(false);
  // Expand/collapse state for "Profile visibility"
  const [showVisibility, setShowVisibility] = useState(false);

  // Posts (MyBuzz)
  const [postText, setPostText] = useState("");
  const [postFile, setPostFile] = useState(null);
  const [postCaption, setPostCaption] = useState(""); // caption for media attached to post
  const [posting, setPosting] = useState(false);
  const [posts, setPosts] = useState([]);

  // Reactions & comments UI
  const [activeCommentPostId, setActiveCommentPostId] = useState(null);
  const [commentDraft, setCommentDraft] = useState("");
  const [showPaletteForPost, setShowPaletteForPost] = useState(null); // postId
  const longPressTimerRef = useRef(null);



  // --------------------------------------------------------------
  // Init
  // --------------------------------------------------------------
  useEffect(() => {
    (async () => {
      let u = propUser || loadUserFromStorage();
      if (!u) {
        const token = getToken();
        if (token) {
          const r = await fetch(`${API_BASE}/profile/full`, { headers: { Authorization: `Bearer ${token}` } });
          const data = await r.json();
          u = data.user || null;
        }
      }
      if (u) {
        setLocalUser(u);
        setUser?.(u);
        saveUserToStorage(u);
        setFormFromUser(u);
        setVoiceUrl(extractVoiceFromFavorites(u.favorites || []));
        setMedia(Array.isArray(u.media) ? u.media : []);
        fetchMyPosts();
        fetchSocial();
      }
      setLoading(false);
    })();
  }, [propUser, setUser]);

  // --------------------------------------------------------------
  // Helper: set form from user
  // --------------------------------------------------------------
  const setFormFromUser = (u) => {
  setForm({
    firstName: u.firstName || "",
    lastName: u.lastName || "",
    bio: u.bio || "",
    gender: u.gender || "",
    dob: u.dob || "",
    location: u.location && (u.location.lat || u.location.lng) ? "" : u.location || "",
    interests: u.interests || [],
    hobbies: u.hobbies || [],
    favorites: Array.isArray(u.favorites) ? u.favorites : [],
    orientation: u.orientation || "",

    // NEW
    visibilityMode: u.visibilityMode || "auto",
    fieldVisibility: {
      age: u.fieldVisibility?.age || "public",
      height: u.fieldVisibility?.height || "public",
      city: u.fieldVisibility?.city || "public",
      orientation: u.fieldVisibility?.orientation || "public",
      interests: u.fieldVisibility?.interests || "public",
      hobbies: u.fieldVisibility?.hobbies || "public",
      likes: u.fieldVisibility?.likes || "public",
      dislikes: u.fieldVisibility?.dislikes || "public",
      lookingFor: u.fieldVisibility?.lookingFor || "public",
      voiceIntro: u.fieldVisibility?.voiceIntro || "public",
      photos: u.fieldVisibility?.photos || "matches",
    },
  });
};


  // --------------------------------------------------------------
  // Fetch social stats + posts
  // --------------------------------------------------------------
   const [social, setSocial] = useState({ likedCount: 0, likedYouCount: 0, matchCount: 0 });

  const fetchSocial = async () => {
  const token = getToken();
  if (!token) return;
  try {
    const r = await fetch(`${API_BASE}/users/social-stats`, {  // ✅ Correct endpoint
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!r.ok) {
      console.error("Social stats fetch failed:", r.status);
      return;
    }
    const data = await r.json();
    console.log("Social stats data:", data); // Debug log
    setSocial({
      likedCount: data.likedCount || 0,
      likedYouCount: data.likedYouCount || 0,
      matchCount: data.matchCount || 0,
    });
  } catch (err) {
    console.error("fetchSocial failed", err);
  }
};


  const normalizePost = (p) => ({
    ...p,
    reactions: p.reactions || {}, // { userId: emoji }
    comments: Array.isArray(p.comments) ? p.comments : [],
  });

  const fetchMyPosts = async () => {
    const token = getToken();
    if (!token) return;
    try {
      const r = await fetch(`${API_BASE}/posts/me`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!r.ok) return;
      const data = await r.json();
      setPosts(Array.isArray(data.posts) ? data.posts.map(normalizePost) : []);
    } catch {
      // ignore
    }
  };

  // ✅ simplified reloadMe: use /users/me instead of /profile/full (fixes 404)
const reloadMe = async () => {
  const token = getToken();
  if (!token) return;
  try {
    const r = await fetch(`${API_BASE}/profile/full`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const data = await r.json();
    if (data.user) {
      setLocalUser(data.user);
      setUser?.(data.user);
      saveUserToStorage(data.user);
      setMedia(Array.isArray(data.user.media) ? data.user.media : []);
     
      setVoiceUrl(extractVoiceFromFavorites(data.user.favorites || []));

    }
  } catch (e) {
    console.error("reloadMe failed:", e);
  }
};
useEffect(() => {
  reloadMe();// runs when the profile page first loads
  fetchSocial(); 
}, []);
// 👇 Handles closing post 3-dot menus when clicking anywhere else
useEffect(() => {
  const handleClickOutside = (e) => {
    if (openMenuForPost) {
      const postMenu = document.querySelector(".post-dotmenu-open");
      if (postMenu && !postMenu.contains(e.target)) {
        setOpenMenuForPost(null);
      }
    }
  };

  document.addEventListener("mousedown", handleClickOutside);
  return () => document.removeEventListener("mousedown", handleClickOutside);
}, [openMenuForPost]);
// collapse "Who can see each item?" when clicking elsewhere
useEffect(() => {
  const handleOutsideClick = (e) => {
    const section = document.querySelector(".audience-section");
    if (section && !section.contains(e.target)) {
      setShowAudience(false);
    }
  };
  document.addEventListener("mousedown", handleOutsideClick);
  return () => document.removeEventListener("mousedown", handleOutsideClick);
}, []);
// collapse "Profile visibility" when clicking elsewhere
useEffect(() => {
  const handleOutsideClick = (e) => {
    const section = document.querySelector(".visibility-section");
    if (section && !section.contains(e.target)) {
      setShowVisibility(false);
    }
  };
  document.addEventListener("mousedown", handleOutsideClick);
  return () => document.removeEventListener("mousedown", handleOutsideClick);
}, []);



// 👇 Add this right here — handles closing 3-dot menus when clicking outside
useEffect(() => {
  const handleClickOutside = (e) => {
    if (openMenuForComment) {
      const menuEl = document.querySelector(".dotmenu-open");
      if (menuEl && !menuEl.contains(e.target)) {
        setOpenMenuForComment(null);
      }
    }
  };

  document.addEventListener("mousedown", handleClickOutside);
  return () => document.removeEventListener("mousedown", handleClickOutside);
}, [openMenuForComment]);

// visibility mode (auto-save)
const setVisibilityMode = async (mode) => {
  setForm((p) => ({ ...p, visibilityMode: mode }));

  const token = getToken();
  if (token) {
    try {
      const r = await fetch(`${API_BASE}/users/me`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ visibilityMode: mode }),
      });
      const data = await r.json();
      if (data.user) {
        setLocalUser(data.user);
        setUser?.(data.user);
        saveUserToStorage(data.user);
      }
    } catch (e) {
      console.error("Save visibilityMode failed", e);
    }
  }

  if (mode === "hidden") setHidden(true);
  else if (user?.visibility === "invisible") setHidden(false);
};

// per-field audience (auto-save)
const setFieldAudience = async (key, audience) => {
  const next = { ...(form.fieldVisibility || {}), [key]: audience };
  setForm((p) => ({ ...p, fieldVisibility: next }));

  const token = getToken();
  if (token) {
    try {
      const r = await fetch(`${API_BASE}/users/me`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ fieldVisibility: next }),
      });
      const data = await r.json();
      if (data.user) {
        setLocalUser(data.user);
        setUser?.(data.user);
        saveUserToStorage(data.user);
      }
    } catch (e) {
      console.error("Save fieldVisibility failed", e);
    }
  }
};


  // --------------------------------------------------------------
  // Form handlers
  // --------------------------------------------------------------
  const handleChange = (e) => {
    const { name, value } = e.target;
    setForm((p) => ({ ...p, [name]: value }));
  };

  const toggleChip = (key, value, max = 5) => {
    setForm((prev) => {
      const arr = Array.isArray(prev[key]) ? [...prev[key]] : [];
      const idx = arr.indexOf(value);
      if (idx >= 0) arr.splice(idx, 1);
      else {
        if (arr.length >= max) return prev;
        arr.push(value);
      }
      return { ...prev, [key]: arr };
    });
  };

  // Save profile (includes interests/hobbies/orientation and favorites)
 const handleSave = async () => {
  const token = getToken();
  if (!token) return;
  try {
    const res = await fetch(`${API_BASE}/users/me`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(form),
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Failed to update");
    const updatedUser = data.user || data;
    setLocalUser(updatedUser);
    setUser?.(updatedUser);
    saveUserToStorage(updatedUser);
    setEditMode(false);
    alert("Profile updated ✅");
  } catch (e) {
    console.error(e);
    alert("Could not update profile");
  }
};



   

  // --------------------------------------------------------------
  // Cloudinary upload helpers
  // --------------------------------------------------------------
  const uploadToCloudinary = async (file) => {
    const fd = new FormData();
    fd.append("file", file);
    fd.append("upload_preset", UPLOAD_PRESET);
    const res = await fetch(`https://api.cloudinary.com/v1_1/${CLOUD_NAME}/upload`, { method: "POST", body: fd });
    if (!res.ok) throw new Error("Cloudinary upload failed");
    return res.json();
  };

  const isVideoOver60s = (file) =>
    new Promise((resolve) => {
      try {
        const url = URL.createObjectURL(file);
        const v = document.createElement("video");
        v.preload = "metadata";
        v.onloadedmetadata = () => {
          URL.revokeObjectURL(url);
          resolve(v.duration > 60);
        };
        v.src = url;
      } catch {
        resolve(false);
      }
    });

  // --------------------------------------------------------------
  // Avatar change → also drop it into FaceBuzz (caption: "facebuzz")
  // --------------------------------------------------------------
  const handleAvatarSelect = async (file) => {
    if (!file) return;
    setAvatarPreview(URL.createObjectURL(file));
    setAvatarUploading(true);
    try {
      const uploaded = await uploadToCloudinary(file);
      if (uploaded.secure_url) {
        const token = getToken();

        // 1) Update avatar field
        const res = await fetch(`${API_BASE}/users/me`, {
          method: "PUT",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
          body: JSON.stringify({ avatar: uploaded.secure_url }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "Avatar update failed");

        // 2) Save into gallery as FaceBuzz
        await fetch(`${API_BASE}/upload-media`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
          body: JSON.stringify({
            fileUrl: uploaded.secure_url,
            type: "image",
            caption: "facebuzz",
          }),
        }).catch(() => {});
        // 3) Auto-create MyBuzz post for avatar change
try {
  await fetch(`${API_BASE}/posts`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      text: `${fullName || "Someone"} changed their FaceBuzz picture.`,
      mediaUrl: uploaded.secure_url,
      type: "image",
      privacy: "public", // default visibility
    }),
  });
} catch (err) {
  console.error("Auto-post avatar update failed:", err);
}


        await reloadMe();
        setAvatarPreview(null);
        setAvatarUrl(uploaded.secure_url); // ✅ reflect instantly

      }
    } catch (err) {
      console.error(err);
      alert("Avatar upload failed");
      setAvatarPreview(null);
    } finally {
      setAvatarUploading(false);
    }
  };

  // --------------------------------------------------------------
  // Voice Intro (≤60s) — stored in favorites as "voice:<url>"
  // --------------------------------------------------------------
  const startRecording = async () => {
    if (recording) return;
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const rec = new MediaRecorder(stream);
      const chunks = [];
      rec.ondataavailable = (e) => {
        if (e.data && e.data.size > 0) {
          chunks.push(e.data);
        }
      };
      rec.onstop = async () => {
        clearInterval(recordTimerRef.current);
        setRecordTimer(0);
        setRecordChunks(chunks);
        // auto-preview
        const blob = new Blob(chunks, { type: "audio/webm" });
        const url = URL.createObjectURL(blob);
        setVoiceUrl(url); // local preview until uploaded
      };
      rec.start(100); // gather small chunks

      // 60s guard
      let elapsed = 0;
      recordTimerRef.current = setInterval(() => {
        elapsed += 1;
        setRecordElapsed(elapsed);
        if (elapsed >= 60) stopRecording();
      }, 1000);

      setRecorder(rec);
      setRecording(true);
      setRecordChunks([]);
      setRecordElapsed(0);
    } catch (e) {
      console.error(e);
      alert("Microphone permission is required to record.");
    }
  };

  const stopRecording = () => {
    if (!recorder) return;
    recorder.stream.getTracks().forEach((t) => t.stop());
    recorder.stop();
    setRecording(false);
  };

  const deleteVoiceIntro = async () => {
    // Clear current voiceUrl and remove from favorites
    setVoiceUrl("");
    const nextFav = (form.favorites || []).filter((f) => !(typeof f === "string" && f.startsWith("voice:")));
    setForm((p) => ({ ...p, favorites: nextFav }));
    // Persist to backend
    const token = getToken();
    if (token) {
      await fetch(`${API_BASE}/users/me`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ favorites: nextFav }),
      }).catch(() => {});
      await reloadMe();
    }
  };

  const uploadVoiceIntro = async () => {
    if (!recordChunks.length) {
      // nothing to upload; maybe user recorded previously and wants to keep preview link
      if (!voiceUrl || voiceUrl.startsWith("blob:")) {
        alert("Record something first.");
        return;
      }
    }
    try {
      setVoiceUploading(true);
      let finalUrl = voiceUrl;

      if (recordChunks.length) {
        const blob = new Blob(recordChunks, { type: "audio/webm" });
        const file = new File([blob], "voiceIntro.webm", { type: "audio/webm" });
        const up = await uploadToCloudinary(file);
        finalUrl = up.secure_url;
      }

      // Store in favorites as "voice:<url>"
      const nextFav = [
        ...(form.favorites || []).filter((f) => !(typeof f === "string" && f.startsWith("voice:"))),
        `voice:${finalUrl}`,
      ];
      setForm((p) => ({ ...p, favorites: nextFav }));

      const token = getToken();
      if (token) {
        const res = await fetch(`${API_BASE}/users/me`, {
          method: "PUT",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
          body: JSON.stringify({ favorites: nextFav }),
        });
        await res.json();
        await reloadMe();
      }
      alert("Voice intro saved ✅");
    } catch (e) {
      console.error(e);
      alert("Voice upload failed");
    } finally {
      setVoiceUploading(false);
      setRecordChunks([]);
    }
  };

  const setRecordTimer = (n) => setRecordElapsed(n);

  // --------------------------------------------------------------
  // Gallery: upload & actions
  // --------------------------------------------------------------
  const handleMediaUpload = async (file) => {
    if (!file) return;
    if (file.type.startsWith("video")) {
      const tooLong = await isVideoOver60s(file);
      if (tooLong) {
        alert("Please upload a video of 60 seconds or less.");
        return;
      }
    }
    setMediaUploading(true);
    try {
      const uploaded = await uploadToCloudinary(file);
      if (uploaded.secure_url) {
        const token = getToken();
        const res = await fetch(`${API_BASE}/upload-media`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
          body: JSON.stringify({
            fileUrl: uploaded.secure_url,
            type: file.type.startsWith("video") ? "video" : "image",
            caption: mediaCaption || "",
          }),
        });
        if (!res.ok) throw new Error("Upload failed");
        await reloadMe();
        setMediaCaption("");
      }
    } catch (e) {
      console.error(e);
      alert("Media upload failed");
    } finally {
      setMediaUploading(false);
    }
  };

  const toggleMediaPrivacy = async (mediaId) => {
    const token = getToken();
    if (!token) return;
    try {
      const m = media.find((x) => x.id === mediaId);
      if (!m) return;
      const next = m.privacy === "private" ? "public" : "private";
      const r = await fetch(`${API_BASE}/media/${mediaId}/privacy`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ privacy: next }),
      });
      if (!r.ok) throw new Error("privacy failed");
      await reloadMe();
    } catch (e) {
      console.error(e);
      alert("Could not change privacy");
    } finally {
      setOpenMenuForMedia(null);
    }
  };

  const editMediaCaption = async (mediaId) => {
    // lowdb server doesn't have a PUT for media caption; quick inline approach:
    // We'll delete+recreate with new caption is dangerous.
    // Instead, prompt and store via "privacy" endpoint hack is not correct.
    // For now, allow client-side only edit preview + force refresh from server to keep truth.
    const m = media.find((x) => x.id === mediaId);
    if (!m) return;
    const nextCaption = prompt("Edit caption:", m.caption || "") ?? m.caption;
    // Client-only immediate feedback:
    setMedia((prev) => prev.map((x) => (x.id === mediaId ? { ...x, caption: nextCaption } : x)));
    // Persist by removing & re-adding? Not ideal; we’ll send a no-op PUT /users/me with media embedded not supported.
    // If you’d like persistent captions, add a /api/media/:id endpoint on the server to update caption.
    alert("Caption updated locally. Add a backend /api/media/:id PATCH to persist.");
    setOpenMenuForMedia(null);
  };

  const deleteMedia = async (mediaId) => {
    const token = getToken();
    if (!token) return;
    if (!window.confirm("Delete this media?")) return;
    try {
      const r = await fetch(`${API_BASE}/media/${mediaId}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!r.ok) throw new Error("delete failed");
      await reloadMe();
    } catch (e) {
      console.error(e);
      alert("Could not delete media");
    } finally {
      setOpenMenuForMedia(null);
    }
  };

  // --------------------------------------------------------------
  // Posts (MyBuzz) — create/edit/delete + react + comments
  // --------------------------------------------------------------
  const handleCreatePost = async () => {
    const token = getToken();
    if (!token) return;
    if (!postText.trim() && !postFile) {
      alert("Write a status or attach media.");
      return;
    }
    setPosting(true);
    try {
      let mediaUrl = "";
      let type = "";
      if (postFile) {
        if (postFile.type.startsWith("video")) {
          const tooLong = await isVideoOver60s(postFile);
          if (tooLong) {
            alert("Please upload a video of 60 seconds or less.");
            setPosting(false);
            return;
          }
        }
        const up = await uploadToCloudinary(postFile);
        mediaUrl = up.secure_url;
        type = postFile.type.startsWith("video") ? "video" : "image";

        // Also save to gallery so it appears in PhotoBuzz/ReelsBuzz
        await fetch(`${API_BASE}/upload-media`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
          body: JSON.stringify({
            fileUrl: mediaUrl,
            type,
            caption: postCaption || "",
          }),
        }).catch(() => {});
      }

      const res = await fetch(`${API_BASE}/posts`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ text: postText, mediaUrl, type }),
      });
      if (!res.ok) throw new Error("post failed");
      const data = await res.json();
      const newPost = normalizePost(data.post);
      setPosts((prev) => [newPost, ...prev]);
      setPostText("");
      setPostFile(null);
      setPostCaption("");
      await reloadMe();
    } catch (e) {
      console.error(e);
      alert("Could not create post.");
    } finally {
      setPosting(false);
    }
  };

  const togglePostPrivacy = async (postId) => {
    const token = getToken();
    if (!token) return;
    try {
      const p = posts.find((x) => x.id === postId);
      if (!p) return;
      const next = p.privacy === "private" ? "public" : "private";
      const r = await fetch(`${API_BASE}/posts/${postId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ privacy: next }),
      });
      if (!r.ok) throw new Error("privacy failed");
      const data = await r.json();
      setPosts((prev) => prev.map((x) => (x.id === postId ? normalizePost(data.post) : x)));
    } catch (e) {
      console.error(e);
      alert("Could not change post privacy");
    } finally {
      setOpenMenuForPost(null);
    }
  };

  const editPostCaption = async (postId) => {
    const p = posts.find((x) => x.id === postId);
    if (!p) return;
    const nextText = prompt("Edit status/caption:", p.text || "") ?? p.text;
    const token = getToken();
    if (!token) return;
    try {
      const r = await fetch(`${API_BASE}/posts/${postId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ text: nextText }),
      });
      if (!r.ok) throw new Error("edit failed");
      const data = await r.json();
      setPosts((prev) => prev.map((x) => (x.id === postId ? normalizePost(data.post) : x)));
    } catch (e) {
      console.error(e);
      alert("Could not edit post");
    } finally {
      setOpenMenuForPost(null);
    }
  };

  const deletePost = async (postId) => {
    const token = getToken();
    if (!token) return;
    if (!window.confirm("Delete this post?")) return;
    try {
      const r = await fetch(`${API_BASE}/posts/${postId}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!r.ok) throw new Error("delete failed");
      setPosts((prev) => prev.filter((x) => x.id !== postId));
    } catch (e) {
      console.error(e);
      alert("Could not delete post");
    } finally {
      setOpenMenuForPost(null);
    }
  };

  // Reactions — short press = ❤️ toggle; long-press opens palette
  const handleHeartPressStart = (postId) => {
    longPressTimerRef.current = setTimeout(() => {
      setShowPaletteForPost(postId);
    }, 420); // long-press threshold
  };
  const handleHeartPressEnd = async (postId) => {
    if (longPressTimerRef.current) {
      clearTimeout(longPressTimerRef.current);
      longPressTimerRef.current = null;
      // short tap: toggle heart
      await reactWithEmoji(postId, "❤️");
    }
  };
  // --- Reaction handler (Fix) ---
const reactWithEmoji = async (postId, emoji) => {
  const token = getToken();
  if (!token) return;

  // ✅ instant local UI update before network
  setPosts((prev) =>
    prev.map((p) => {
      if (p.id !== postId) return p;
      const counts = { ...(p.reactionCounts || {}) };
      counts[emoji] = (counts[emoji] || 0) + 1;
      return { ...p, reactionCounts: counts };
    })
  );

  try {
    const r = await fetch(`${API_BASE}/posts/${postId}/react-emoji`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ emoji }),
    });
    if (!r.ok) throw new Error("react failed");

    const data = await r.json(); // { counts, reacted }
    setPosts((prev) =>
      prev.map((p) =>
        p.id === postId
          ? {
              ...p,
              reactionCounts: data.counts || {},
              reactions: data.reactions || {},
            }
          : p
      )
    );
  } catch (e) {
    console.error(e);
    alert("Could not react");
  } finally {
    setShowPaletteForPost(null);
  }
};


  // Comments
  const openComments = (postId) => {
    setActiveCommentPostId(postId);
    setCommentDraft("");
  };
  const closeComments = () => setActiveCommentPostId(null);

  const createComment = async (postId) => {
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
      setPosts((prev) =>
        prev.map((p) =>
          p.id === postId ? { ...p, comments: [...(p.comments || []), data.comment] } : p
        )
      );
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
      setPosts((prev) =>
        prev.map((p) =>
          p.id === postId
            ? {
                ...p,
                comments: p.comments.map((c) => (c.id === comment.id ? data.comment : c)),
              }
            : p
        )
      );
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
      setPosts((prev) =>
        prev.map((p) =>
          p.id === postId ? { ...p, comments: p.comments.filter((c) => c.id !== comment.id) } : p
        )
      );
    } catch (e) {
      console.error(e);
      alert("Could not delete comment");
    }
  };
// ❤️ Toggle heart on a comment
const toggleCommentHeart = async (postId, commentId) => {
  const token = getToken();
  if (!token) return;
  try {
    const r = await fetch(`${API_BASE}/posts/${postId}/comments/${commentId}/heart`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    const data = await r.json(); // { liked: boolean, count: number }
    setPosts((prev) =>
      prev.map((p) =>
        p.id === postId
          ? {
              ...p,
              comments: p.comments.map((c) =>
                c.id === commentId
                  ? { ...c, liked: data.liked, likeCount: data.count }
                  : c
              ),
            }
          : p
      )
    );
  } catch (e) {
    console.error(e);
    alert("Could not react to comment.");
  }
};
// 💬 Simple reply trigger (you can expand later)
const replyToCommentNew = (postId, comment) => {
  setActiveCommentPostId(postId);
  setCommentDraft(`@${comment.userId === user.id ? "you" : "match"} `);
};

// 💬 Prefill reply (you can thread later)
const replyToComment = (postId, comment) => {
  setActiveCommentPostId(postId);
  setCommentDraft((d) => (d?.length ? `${d} ` : "") + "@reply ");
};

  // --------------------------------------------------------------
  // Visibility: Clear / Blurred / Hidden
  // - Hidden → backend visibility "invisible"
  // - Clear / Blurred → saved into favorites as "blur:clear" or "blur:blurred"
  //   The server still blurs globally, so this prepares future per-user logic.
  // --------------------------------------------------------------
  const blurMode = useMemo(() => extractBlurMode(form.favorites || []), [form.favorites]);
  const isHidden = user?.visibility === "invisible";
  const showBlurChip = !isHidden && blurMode === "blurred"; // Only show "Blurred" chip if blurred

 // Set blur mode and optionally clear visibilityMode if choosing "clear"
const setBlurMode = async (mode) => {
  const token = getToken();
  if (!token) return;

  const nextFav = [
    ...(form.favorites || []).filter((f) => !(typeof f === "string" && f.startsWith("blur:"))),
    `blur:${mode}`,
  ];

  // If user selects "clear", we also neutralize visibilityMode to avoid auto reset
  const updatedForm = {
    ...form,
    favorites: nextFav,
    visibilityMode: mode === "clear" ? "" : form.visibilityMode,
  };

  setForm(updatedForm);

  try {
    const r = await fetch(`${API_BASE}/users/me`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify(updatedForm),
    });
    await r.json();
    // 🔥 Don’t call reloadMe immediately — it resets it back to auto
    // Instead, manually update localUser
    setLocalUser((prev) => ({ ...prev, ...updatedForm }));
    saveUserToStorage({ ...user, ...updatedForm });
  } catch (e) {
    console.error(e);
  }
};


  const setHidden = async (hidden) => {
    const token = getToken();
    if (!token) return;
    try {
      const r = await fetch(`${API_BASE}/users/me`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ visibility: hidden ? "invisible" : "active" }),
      });
      const data = await r.json();
      setLocalUser(data.user || data);
      saveUserToStorage(data.user || data);
    } catch (e) {
      console.error(e);
    }
  };

  // --------------------------------------------------------------
  // UI: Components
  // --------------------------------------------------------------
  const StatCard = ({ icon, label, value, onClick }) => (
    <button
      onClick={onClick}
      className="rounded-xl p-4 text-left bg-gradient-to-br from-rose-50 to-white border border-rose-100 hover:shadow transition"
    >
      <div className="text-2xl">{icon}</div>
      <div className="mt-1 text-xs text-gray-500">{label}</div>
      <div className="text-xl font-bold">{value || 0}</div>
    </button>
  );

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

  // --------------------------------------------------------------
// Render
// --------------------------------------------------------------
const isMyProfile = !propUser || propUser.id === user?.id;

// Posts visible to self vs others
const visiblePosts = useMemo(() => {
  if (!posts?.length) return [];
  if (isMyProfile) return posts; // show all if it's your own
  return posts.filter((p) => p.privacy !== "private");
}, [posts, isMyProfile]);

// Media visible to self vs others
const visibleMedia = useMemo(() => {
  if (!media?.length) return [];
  if (isMyProfile) return media; // show all if it's your own
  return media.filter((m) => m.privacy !== "private");
}, [media, isMyProfile]);

if (loading) {
  return (
    <div className="flex items-center justify-center min-h-screen">
      Loading...
    </div>
  );
}
if (!user) {
  return (
    <div className="flex items-center justify-center min-h-screen">
      <div className="text-center">
        <p className="mb-4">You are not logged in.</p>
        <button
          onClick={() => navigate("/login")}
          className="px-4 py-2 bg-red-600 text-white rounded"
        >
          Login
        </button>
      </div>
    </div>
  );
}


const showMemberSince = user.createdAt
  ? new Date(user.createdAt).toLocaleDateString()
  : "";

 return (
  <div className="min-h-screen bg-gradient-to-br from-pink-200 via-red-200 to-pink-300 py-6 px-3 sm:py-8 sm:px-4">
    <div className="max-w-5xl mx-auto bg-white rounded-2xl shadow-lg overflow-hidden flex flex-col md:flex-row">

        {/* Left: avatar + quick actions */}
          <div className="w-full md:w-1/3 p-4 sm:p-6 bg-gradient-to-b from-white to-pink-50 flex flex-col items-center">
          <div className="relative">
            <img
              src={avatarUrl || "https://via.placeholder.com/300?text=No+Photo"}
              alt="avatar"
              className="w-32 h-32 sm:w-40 sm:h-40 rounded-full object-cover border-4 border-white shadow-md"
            />
            <button
              onClick={() => avatarInputRef.current?.click()}
              className="absolute bottom-0 right-0 transform translate-x-1/4 translate-y-1/4 bg-white text-sm px-3 py-1 rounded-full shadow"
            >
              {avatarUploading ? "Saving..." : "Change"}
            </button>
            <input
              ref={avatarInputRef}
              type="file"
              accept="image/*"
              className="hidden"
              onChange={(e) => handleAvatarSelect(e.target.files?.[0])}
            />
          </div>

          <div className="mt-6 text-center">
            <h2 className="text-xl font-semibold">{fullName || "Your name"}</h2>
            <p className="text-sm text-gray-500">{user.email}</p>
          </div>

  {/* 🔐 Privacy & Visibility */}
<div className="mt-5 w-full flex flex-col gap-4">
   {/* Global mode (expandable) */}
  <div className="p-3 rounded-2xl bg-gradient-to-b from-white to-rose-50 border visibility-section">
    <button
      type="button"
      onClick={() => setShowVisibility((prev) => !prev)}
      className="w-full flex justify-between items-center text-sm font-semibold text-gray-800 mb-2"
    >
      <span>Profile visibility</span>
      <span className="text-gray-500 text-lg">{showVisibility ? "▾" : "▸"}</span>
    </button>

    {showVisibility && (
      <>
        <div className="grid grid-cols-1 gap-2">
     {/* New: No Blur Option */}
<button
  type="button"
  onClick={() => setBlurMode("clear")}
  className={`w-full text-left px-3 py-2 rounded-xl border transition ${
    blurMode === "clear"
      ? "bg-rose-500 text-white border-rose-500"
      : "bg-white text-gray-700 border-gray-300 hover:border-rose-300"
  }`}
>
  <div className="text-sm font-medium">No Blur (Always clear)</div>
  <div className="text-xs opacity-80">
    Your profile photos and info are fully visible by default.
  </div>
</button>


          {/* Existing Modes */}
          {VISIBILITY_MODES.map((m) => (
            <button
              key={m.key}
              type="button"
                  onClick={() => {
                    setVisibilityMode(m.key);
                    setBlurMode("blurred"); // switch back to blur when using visibility modes
                  }}
              className={`w-full text-left px-3 py-2 rounded-xl border transition ${
                form.visibilityMode === m.key
                  ? "bg-rose-500 text-white border-rose-500"
                  : "bg-white text-gray-700 border-gray-300 hover:border-rose-300"
              }`}
            >
              <div className="text-sm font-medium">
                {m.label}
                {m.key === "hidden" && user?.visibility === "invisible" ? " ✓" : ""}
              </div>
              {m.key === "auto" && (
                <div className="text-xs opacity-80">
                  Photos appear blurred in Discover until you both like each other.
                </div>
              )}
              {m.key === "limited" && (
                <div className="text-xs opacity-80">
                  Show a limited preview (up to 3 photos + a few facts).
                </div>
              )}
              {m.key === "full" && (
                <div className="text-xs opacity-80">
                  Show full profile (except items set to “Matches only” below).
                </div>
              )}
              {m.key === "hidden" && (
                <div className="text-xs opacity-80">
                  Not discoverable. Existing matches can still chat.
                </div>
              )}
            </button>
          ))}
        </div>
      </>
    )}
  </div>


{/* Per-field audience (expandable) */}
<div className="p-3 rounded-2xl bg-white border audience-section">
  <button
    type="button"
    onClick={() => setShowAudience((prev) => !prev)}
    className="w-full flex justify-between items-center text-sm font-semibold text-gray-800 mb-2"
  >
    <span>Who can see each item?</span>
    <span className="text-gray-500 text-lg">{showAudience ? "▾" : "▸"}</span>
  </button>

  {showAudience && (
    <>
      <div className="space-y-1">
        {FIELD_KEYS.map(({ key, label }) => (
          <FieldAudienceRow
            key={key}
            k={key}
            label={label}
            value={form.fieldVisibility?.[key] || "public"}
            disabled={form.visibilityMode === "hidden"}
            onChange={setFieldAudience}
          />
        ))}
      </div>
      {form.visibilityMode === "hidden" && (
        <div className="mt-2 text-[11px] text-gray-500">
          You’re hidden—per-field settings won’t apply until you switch modes.
        </div>
      )}
    </>
  )}
</div>



  {/* Primary actions kept the same */}
  <button
    onClick={() => setEditMode(true)}
    className="w-full bg-gradient-to-r from-pink-500 to-rose-500 text-white font-medium px-4 py-2 rounded-full shadow hover:opacity-90 transition"
  >
    Edit Profile
  </button>
  <button
    onClick={() => navigate("/settings")}
    className="w-full bg-gradient-to-r from-rose-500 to-pink-500 text-white font-medium px-4 py-2 rounded-full shadow hover:opacity-90 transition"
  >
    ⚙️ Settings
  </button>


  {blurMode === "blurred" && (
    <span className="text-xs text-gray-500 italic">
      Your profile appears blurred in Discover
    </span>
  )}
</div>


        </div>

        {/* Right: details & tabs */}
<div className="w-full md:w-2/3 p-4 sm:p-6">
          <div className="flex justify-between items-start">
            <div>
              <h1 className="text-2xl font-bold">{fullName}</h1>
              <div className="flex gap-3 text-sm text-gray-600 mt-2">
                {/* age from dob */}
                <span>
                  {user.dob
                    ? (() => {
                        const birth = new Date(user.dob);
                        const ageDifMs = Date.now() - birth.getTime();
                        const ageDate = new Date(ageDifMs);
                        const age = Math.abs(ageDate.getUTCFullYear() - 1970);
                        return `${age} yrs`;
                      })()
                    : ""}
                </span>
                <span>{user.gender ? `• ${user.gender}` : ""}</span>
                <span>{user.orientation ? `• ${user.orientation}` : ""}</span>
              </div>
            </div>
            <div className="text-right">
              <p className="text-sm text-gray-500">Member since</p>
              <p className="font-semibold text-gray-700">{showMemberSince}</p>
            </div>
          </div>
              {/* Profile Info Section */}
              <div className="mt-4">
{/* --- BuzzStreak Section --- */}
<div className="flex flex-col items-center mt-2 w-full">
  <BuzzStreak onClick={() => handleBuzzStreak(user?.id)} />

  {/* 🔥 Show current streak count */}
  {streak?.count ? (
    <div className="text-sm text-gray-700 mt-1">
      🔥 BuzzStreak: <b>{streak.count}</b> day{streak.count > 1 ? "s" : ""}
    </div>
  ) : (
    <div className="text-sm text-gray-500 mt-1 italic">
      Tap to start your BuzzStreak 🔥
    </div>
  )}

  {/* 🎁 Show upcoming reward from backend */}
  {streak?.nextReward ? (
    <div className="mt-1 text-xs text-rose-600 font-medium bg-rose-50 px-3 py-1 rounded-full shadow-sm">
      Next Reward → <b>{streak.nextReward.reward}</b> (Day {streak.nextReward.day})
    </div>
  ) : (
    streak?.count > 0 && (
      <div className="mt-1 text-xs text-green-600 font-medium bg-green-50 px-3 py-1 rounded-full shadow-sm">
        🎉 You’ve unlocked all rewards — keep buzzing!
      </div>
    )
  )}
</div>
<BuzzStreakRewards currentDay={streak?.count || 0} />

              </div>


          {/* Tabs */}
<div className="mt-5 flex flex-wrap gap-2 justify-center md:justify-start">
            {["info", "gallery", "posts"].map((t) => (
              <button
                key={t}
                onClick={() => setTab(t)}
                className={`px-4 py-2 rounded-full ${
                  tab === t ? "bg-pink-500 text-white" : "bg-gray-100 text-gray-700"
                }`}
              >
                {t === "info" ? "Info" : t === "gallery" ? "Gallery" : "MyBuzz"}
              </button>
            ))}
          </div>

          {/* Info Tab */}
          {tab === "info" && (
            <div className="mt-6">
              {/* About + AI rewrite hook (kept simple; button removed per last cycles to reduce clutter) */}
              <section>
                <h3 className="font-semibold text-gray-700 mb-2">About</h3>
                {!editMode ? (
                  <p className="text-gray-700">{user.bio || "No bio yet."}</p>
                ) : (
                  <textarea
                    name="bio"
                    value={form.bio}
                    onChange={handleChange}
                    className="w-full p-3 border rounded mb-3"
                    rows={4}
                    placeholder="Write about yourself..."
                  />
                )}
              </section>

              {/* Voice Intro */}
              <section className="mt-6">
                <div className="flex items-center justify-between">
                  <h4 className="font-semibold text-gray-700">Voice Intro</h4>
                  <div className="text-xs text-gray-500">Up to 60 seconds</div>
                </div>
                <div className="mt-2 p-3 border rounded-lg bg-gray-50">
                  <div className="flex items-center gap-2 flex-wrap">
                    {!recording ? (
                      <button
                        onClick={startRecording}
                        className="px-4 py-2 rounded bg-pink-500 text-white"
                      >
                        🎙️ Record
                      </button>
                    ) : (
                      <button
                        onClick={stopRecording}
                        className="px-4 py-2 rounded bg-red-500 text-white"
                      >
                        ⏹ Stop ({recordElapsed}s)
                      </button>
                    )}
                    <button
                      onClick={uploadVoiceIntro}
                      disabled={voiceUploading}
                      className="px-4 py-2 rounded border"
                    >
                      {voiceUploading ? "Saving..." : "Save"}
                    </button>
                    <button onClick={deleteVoiceIntro} className="px-4 py-2 rounded border">
                      Delete
                    </button>
                    {voiceUrl && (
                      <audio
                        controls
                        src={voiceUrl}
                        className="mt-2 w-full md:w-auto md:min-w-[280px]"
                      />
                    )}
                  </div>
                  <p className="text-xs text-gray-500 mt-2">
                    Tip: If your profile is blurred, matches will still hear this intro.
                  </p>
                </div>
              </section>

       {/* Interests */}
<section className="mt-6">
  <div className="flex items-center justify-between">
    <h4 className="font-semibold text-gray-700">Interests</h4>
    <div className="text-xs text-gray-500">
      {editMode ? `${form.interests.length}/5 selected` : null}
    </div>
  </div>

  {!editMode ? (
    <div className="mt-2 flex gap-2 flex-wrap">
      {(user.interests || []).map((i, idx) => (
        <span key={idx} className="px-3 py-1 bg-red-50 text-red-600 rounded-full text-sm">
          {i}
        </span>
      ))}
      {!(user.interests || []).length && (
        <div className="text-gray-400 mt-2">No interests yet</div>
      )}
    </div>
  ) : (
    <>
      <div className="mt-2 flex gap-2 flex-wrap">
        {INTEREST_OPTIONS.map((opt) => {
          const selected = form.interests.includes(opt);
          const disabled = !selected && form.interests.length >= 5;
          return (
            <button
              key={opt}
              type="button"
              onClick={() => toggleChip("interests", opt, 5)}
              disabled={disabled}
              className={`px-3 py-1 rounded-full text-sm border transition ${
                selected
                  ? "bg-red-500 text-white border-red-500"
                  : "bg-white text-gray-700 border-gray-300 hover:border-red-400"
              } ${disabled ? "opacity-50 cursor-not-allowed" : ""}`}
            >
              {opt}
            </button>
          );
        })}
        {/* Existing custom chips (if any) – show removable */}
        {form.interests
          .filter((x) => !INTEREST_OPTIONS.includes(x))
          .map((custom) => (
            <button
              key={custom}
              type="button"
              onClick={() => toggleChip("interests", custom, 5)}
              className="px-3 py-1 rounded-full text-sm border bg-white text-gray-700 hover:border-red-400"
              title="Remove"
            >
              {custom} ✕
            </button>
          ))}
      </div>

      {/* Add other interest */}
      <div className="mt-3 flex gap-2">
        <input
          type="text"
          placeholder="Other interest… (press Enter)"
          className="border p-2 rounded flex-1"
          onKeyDown={(e) => {
            const v = e.currentTarget.value.trim();
            if (e.key === "Enter" && v) {
              if (!form.interests.includes(v) && form.interests.length < 5) {
                setForm((p) => ({ ...p, interests: [...p.interests, v] }));
              }
              e.currentTarget.value = "";
            }
          }}
        />
      </div>
    </>
  )}
</section>


            {/* Hobbies */}
<section className="mt-6">
  <div className="flex items-center justify-between">
    <h4 className="font-semibold text-gray-700">Hobbies</h4>
    <div className="text-xs text-gray-500">
      {editMode ? `${form.hobbies.length}/5 selected` : null}
    </div>
  </div>

  {!editMode ? (
    <div className="mt-2 flex gap-2 flex-wrap">
      {(user.hobbies || []).map((i, idx) => (
        <span key={idx} className="px-3 py-1 bg-pink-50 text-pink-700 rounded-full text-sm">
          {i}
        </span>
      ))}
      {!(user.hobbies || []).length && (
        <div className="text-gray-400 mt-2">No hobbies yet</div>
      )}
    </div>
  ) : (
    <>
      <div className="mt-2 flex gap-2 flex-wrap">
        {HOBBY_OPTIONS.map((opt) => {
          const selected = form.hobbies.includes(opt);
          const disabled = !selected && form.hobbies.length >= 5;
          return (
            <button
              key={opt}
              type="button"
              onClick={() => toggleChip("hobbies", opt, 5)}
              disabled={disabled}
              className={`px-3 py-1 rounded-full text-sm border transition ${
                selected
                  ? "bg-pink-500 text-white border-pink-500"
                  : "bg-white text-gray-700 border-gray-300 hover:border-pink-400"
              } ${disabled ? "opacity-50 cursor-not-allowed" : ""}`}
            >
              {opt}
            </button>
          );
        })}
        {/* Existing custom hobby chips – removable */}
        {form.hobbies
          .filter((x) => !HOBBY_OPTIONS.includes(x))
          .map((custom) => (
            <button
              key={custom}
              type="button"
              onClick={() => toggleChip("hobbies", custom, 5)}
              className="px-3 py-1 rounded-full text-sm border bg-white text-gray-700 hover:border-pink-400"
              title="Remove"
            >
              {custom} ✕
            </button>
          ))}
      </div>

      {/* Add other hobby */}
      <div className="mt-3 flex gap-2">
        <input
          type="text"
          placeholder="Other hobby… (press Enter)"
          className="border p-2 rounded flex-1"
          onKeyDown={(e) => {
            const v = e.currentTarget.value.trim();
            if (e.key === "Enter" && v) {
              if (!form.hobbies.includes(v) && form.hobbies.length < 5) {
                setForm((p) => ({ ...p, hobbies: [...p.hobbies, v] }));
              }
              e.currentTarget.value = "";
            }
          }}
        />
      </div>
    </>
  )}
</section>

              {/* Social bar */}
              <SocialSection user={user} />
                {editMode && (
  <div className="mt-4 flex gap-3">
    <button
      onClick={handleSave}
      className="bg-gradient-to-r from-pink-500 to-rose-500 text-white px-4 py-2 rounded-full shadow hover:opacity-90 transition"
    >
      Save
    </button>
    <button
      onClick={() => {
        setEditMode(false);
        setFormFromUser(user);
      }}
      className="border border-gray-300 px-4 py-2 rounded-full hover:bg-gray-50 transition"
    >
      Cancel
    </button>
  </div>
)}


              
            </div>
          )}

          {/* Gallery Tab */}
       {tab === "gallery" && (
  <GallerySection
    faceBuzz={faceBuzz}
    photoBuzz={photoBuzz}
    reelsBuzz={reelsBuzz}
    editMediaCaption={editMediaCaption}
    toggleMediaPrivacy={toggleMediaPrivacy}
    deleteMedia={deleteMedia}
  />
)}

          {/* Posts / MyBuzz Tab */}
          {tab === "posts" && (
            <div className="mt-6">
              <h3 className="font-semibold text-gray-700 mb-3">Share something</h3>
              <div className="border rounded-lg p-4 bg-gray-50">
                <textarea
                  placeholder="What's on your mind?"
                  value={postText}
                  onChange={(e) => setPostText(e.target.value)}
                  className="w-full border p-2 rounded mb-3"
                  rows={3}
                />
<div className="flex flex-col sm:flex-row sm:items-center gap-3">
                  <input
                    type="file"
                    accept="image/*,video/*"
                    onChange={(e) => setPostFile(e.target.files?.[0] || null)}
                  />
                  <input
                    type="text"
                    value={postCaption}
                    onChange={(e) => setPostCaption(e.target.value)}
                    placeholder="Caption for attached media (optional)"
                    className="border p-2 rounded flex-1"
                  />
                </div>
                <div className="flex gap-2 mt-3">
                  <button
                    onClick={handleCreatePost}
                    disabled={posting}
                    className="bg-pink-500 text-white px-4 py-2 rounded disabled:opacity-60"
                  >
                    {posting ? "Posting..." : "Post"}
                  </button>
                  <button
                    onClick={() => {
                      setPostText("");
                      setPostFile(null);
                      setPostCaption("");
                    }}
                    className="border px-4 py-2 rounded"
                  >
                    Reset
                  </button>
                </div>
                <p className="text-xs text-gray-500 mt-2">Videos up to 60 seconds.</p>
              </div>

              <div className="mt-6 grid gap-4">
                {visiblePosts.map((p) => {
                  const counts = p.reactionCounts || {};
                  const heartCount = counts["❤️"] || 0;
                  const otherReacts =
                    REACTION_SET.filter((e) => e !== "❤️")
                      .map((e) => ({ e, n: counts[e] || 0 }))
                      .filter((x) => x.n > 0) || [];

                  return (
<div key={p.id} className="border rounded-lg p-3 sm:p-4 bg-white shadow-sm">
                      {/* Header */}
                      <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <img
                          src={user.avatar || "https://via.placeholder.com/48"}
                          className="w-10 h-10 rounded-full object-cover"
                        />
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-semibold">{fullName || "You"}</span>
                            {/* Privacy badge */}
                            <span
                              className={`text-[11px] px-2 py-0.5 rounded-full ${
                                p.privacy === "private"
                                  ? "bg-gray-200 text-gray-700"
                                  : "bg-green-100 text-green-700"
                              }`}
                            >
                              {p.privacy === "private" ? "🔒 Private" : "🌍 Public"}
                            </span>
                          </div>
                          <div className="text-xs text-gray-500">
                          {p.type === "image"
                            ? (p.text?.toLowerCase().includes("changed their profile picture") ||
                              p.text?.toLowerCase().includes("facebuzz"))
                              ? "updated a FaceBuzz avatar"
                              : "uploaded a PhotoBuzz"
                            : p.type === "video"
                            ? "shared a reelBuzz"
                            : "shared a buzz"}{" "}
                          • {timeAgo(p.createdAt)}
                        </div>

                        </div>
                      </div>

                      {/* 3-dots */}
                      <div className="relative">
                        <button
                          onClick={() =>
                            setOpenMenuForPost(openMenuForPost === p.id ? null : p.id)
                          }
                          className="px-2 py-1 rounded hover:bg-gray-100"
                        >
                          ⋯
                        </button>

                <DotMenu
                  open={openMenuForPost === p.id}
                  onClose={() => setOpenMenuForPost(null)}
                >
                  <div className={openMenuForPost === p.id ? "post-dotmenu-open" : ""}>
                    <DotItem onClick={() => editPostCaption(p.id)}>✏️ Edit</DotItem>
                    <DotItem onClick={() => togglePostPrivacy(p.id)}>
                      {p.privacy === "private" ? "Set to Public" : "Set to Private"}
                    </DotItem>

                    <div className="px-3 py-2 text-xs text-gray-500 italic">
                      Current:{" "}
                      {p.privacy === "private"
                        ? "Private (Only You)"
                        : "Public (Matches can view)"}
                    </div>

                    <DotItem danger onClick={() => deletePost(p.id)}>🗑 Delete</DotItem>
                  </div>
                </DotMenu>

                      </div>
                    </div>


                      {/* Content */}
                      {/* hide auto “changed their FaceBuzz picture.” captions */}
                      {p.text &&
                      !/changed\s+(their|his|her)\s+FaceBuzz picture\.?$/i.test(p.text) && (
                        <p className="mt-3">{p.text}</p>
                      )}
                     {p.mediaUrl && (
                        <div className="mt-3">
                          {p.type === "video" ? (
                            <video
                              src={p.mediaUrl}
                              controls
                              className="w-full max-h-[420px] rounded-lg object-cover"
                            />
                          ) : (
                            <img
                              src={p.mediaUrl}
                              alt=""
                              className="w-full max-h-[480px] rounded-lg object-contain"
                            />
                          )}
                        </div>
                      )}


                      {/* Reactions & comments */}
                      <div className="mt-3">
                        <div className="flex items-center gap-3 text-sm">
                          {/* Heart with short/long press */}
                          <button
                            className="px-3 py-1 rounded-full bg-rose-50 hover:bg-rose-100 select-none"
                            onMouseDown={() => handleHeartPressStart(p.id)}
                            onMouseUp={() => handleHeartPressEnd(p.id)}
                            onMouseLeave={() => {
                              if (longPressTimerRef.current) {
                                clearTimeout(longPressTimerRef.current);
                                longPressTimerRef.current = null;
                              }
                            }}
                          >
                            ❤️ {heartCount > 0 ? heartCount : ""}
                          </button>

                          {/* When palette open for this post */}
                          {showPaletteForPost === p.id && (
                            <div className="flex items-center gap-2 bg-white border rounded-full px-2 py-1 shadow">
                              {REACTION_SET.map((e) => (
                                <button
                                  key={e}
                                  onClick={() => reactWithEmoji(p.id, e)}
                                  className="px-2 py-1 hover:bg-gray-50 rounded-full"
                                >
                                  {e} {counts[e] ? counts[e] : ""}
                                </button>
                              ))}
                            </div>
                          )}

                          {/* Other reacts summary */}
                          {otherReacts.length > 0 && (
                            <div className="text-xs text-gray-500">
                              {otherReacts.map((r, idx) => (
                                <span key={r.e}>
                                  {r.e} {r.n}
                                  {idx < otherReacts.length - 1 ? " • " : ""}
                                </span>
                              ))}
                            </div>
                          )}

                          <button
                            className="ml-auto text-gray-600 hover:text-gray-800"
                            onClick={() => openComments(p.id)}
                          >
                            💬 {(p.comments || []).length} Comments
                          </button>
                        </div>
                      </div>

                      {/* Inline comments */}
{activeCommentPostId === p.id && (
  <div className="mt-3 border-t pt-3">
    <div className="space-y-2">
      {(p.comments || []).length === 0 && (
        <div className="text-sm text-gray-500">No comments yet. Be the first!</div>
      )}

      {(p.comments || []).map((c) => {
        const isMine = c.userId === user.id;          // comment author
        const isPostOwner = p.userId === user.id;     // post owner
        const canDelete = isMine || isPostOwner;      // allowed to delete
        const isOpen = openMenuForComment === `${p.id}-${c.id}`;

        return (
          <div key={c.id} className="bg-gray-50 rounded p-2 text-sm relative">
            <div className="flex items-start justify-between">
              <div>
                <div className="font-semibold flex items-center gap-2">
                  {isMine ? "You" : "Match"}
                  <span className="text-xs text-gray-500">{timeAgo(c.createdAt)}</span>
                </div>
                <div className="mt-1 text-gray-800">{c.text}</div>
              </div>

              {/* ⋯ menu */}
              <div className="relative">
                <button
                  onClick={() =>
                    setOpenMenuForComment(isOpen ? null : `${p.id}-${c.id}`)
                  }
                  className="px-2 py-1 rounded hover:bg-gray-100"
                >
                  ⋯
                </button>

               <DotMenu
                  open={isOpen}
                  onClose={() => setOpenMenuForComment(null)}
                >
                  <div className={isOpen ? "dotmenu-open" : ""}>
                    {isMine && (
                      <DotItem onClick={() => editComment(p.id, c)}>✏️ Edit</DotItem>
                    )}
                    {canDelete && (
                      <DotItem danger onClick={() => deleteComment(p.id, c)}>🗑 Delete</DotItem>
                    )}
                    <DotItem onClick={() => replyToComment(p.id, c)}>💬 Reply</DotItem>
                  </div>
                </DotMenu>

              </div>
            </div>

            {/* ❤️ Heart button */}
            <div className="flex items-center gap-3 mt-2 text-xs">
              <button
                onClick={() => toggleCommentHeart(p.id, c.id)}
                className={`flex items-center gap-1 px-2 py-1 rounded-full border text-gray-600 hover:bg-pink-50 transition ${
                  c.liked ? "bg-pink-100 border-pink-300 text-pink-600" : ""
                }`}
              >
                ❤️ {c.likeCount || 0}
              </button>
            </div>
          </div>
        );
      })}
    </div>

    {/* Comment input box */}
    <div className="flex gap-2 mt-2">
      <input
        className="flex-1 border p-2 rounded"
        placeholder="Write a comment…"
        value={commentDraft}
        onChange={(e) => setCommentDraft(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter") createComment(p.id);
        }}
      />
      <button
        onClick={() => createComment(p.id)}
        className="bg-pink-500 text-white px-4 py-2 rounded"
      >
        Send
      </button>
      <button onClick={closeComments} className="border px-4 py-2 rounded">
        Close
      </button>
    </div>
  </div>
)}
  </div>
                  );
                })}
                {!posts.length && <div className="text-gray-500">No posts yet.</div>}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}


