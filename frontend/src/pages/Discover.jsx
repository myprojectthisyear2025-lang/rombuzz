// src/pages/Discover.jsx
import React, {
  useEffect,
  useMemo,
  useRef,
  useState,
  useCallback,
} from "react";
import { useNavigate } from "react-router-dom";
import { io } from "socket.io-client";
import {
  FaHeart,
  FaTimes,
  FaHeadphones,
  FaMagic,
  FaMapMarkerAlt,
  FaSyncAlt,
  FaBolt,
  FaUser,
  FaLock,
  FaChevronDown,
  FaStar,
} from "react-icons/fa";
/*
const API_BASE = "http://localhost:4000/api";
const SOCKET_URL = "http://localhost:4000";
const PLACEHOLDER = "https://via.placeholder.com/600x800?text=RomBuzz";
*/
const API_BASE = process.env.REACT_APP_API_BASE || "https://rombuzz-api.onrender.com/api";
const SOCKET_URL = process.env.REACT_APP_SOCKET_URL || "https://rombuzz-api.onrender.com";
const PLACEHOLDER = "https://via.placeholder.com/600x800?text=RomBuzz";

/* ============================================================
   UX toggles – flip these as you like
============================================================ */
const UX = {
  // Visuals
  AUTO_BLUR: true,          // false = never blur in "auto" mode
  SHOW_RADAR: true,         // show/hide the orbit/radar widget
  SHOW_BUZZZONE: true,      // show/hide “BuzzZone active…” banner
  SHOW_WINGMAN: true,       // show/hide Wingman button + suggestions

  // Interaction
  TAP_TO_REVEAL: true,      // disable “tap to reveal” progress if false
  SWIPE_ENABLED: true,      // disable swipe gestures if false (buttons still work)
  LIKE_AUTOSKIP: true,      // after like, auto-advance to the next card
};

/* ============================================================
   Utils
============================================================ */
const token = () =>
  localStorage.getItem("token") || sessionStorage.getItem("token") || "";

const getStoredUser = () => {
  try {
    return (
      JSON.parse(localStorage.getItem("user")) ||
      JSON.parse(sessionStorage.getItem("user"))
    );
  } catch {
    return null;
  }
};

const clamp = (v, min, max) => Math.max(min, Math.min(max, v));

async function putMe(body) {
  const res = await fetch(`${API_BASE}/users/me`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token()}`,
    },
    body: JSON.stringify(body),
  });
  return res.ok;
}

/* ============================================================
   Radar (moves to side on desktop, bottom on mobile)
============================================================ */
function RadarCanvas({ users = [] }) {
  const canvasRef = useRef(null);
  const animRef = useRef(null);
  const tRef = useRef(0);

  const phaseMap = useMemo(() => {
    const map = new Map();
    users.forEach((u) => {
      map.set(u.id, (u.id.charCodeAt(0) % 360) * (Math.PI / 180));
    });
    return map;
  }, [users]);

  const draw = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;

    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    const w = rect.width;
    const h = rect.height;
    const cx = w / 2;
    const cy = h / 2;
    const radius = Math.min(w, h) * 0.45;

    ctx.clearRect(0, 0, w, h);

    const g = ctx.createRadialGradient(cx, cy, radius * 0.2, cx, cy, radius);
    g.addColorStop(0, "rgba(255, 182, 193, 0.25)");
    g.addColorStop(1, "rgba(255, 255, 255, 0.0)");
    ctx.fillStyle = g;
    ctx.beginPath();
    ctx.arc(cx, cy, radius, 0, Math.PI * 2);
    ctx.fill();

    ctx.strokeStyle = "rgba(255, 105, 135, 0.25)";
    ctx.lineWidth = 2;
    for (let i = 0.25; i <= 1; i += 0.25) {
      ctx.beginPath();
      ctx.arc(cx, cy, radius * i, 0, Math.PI * 2);
      ctx.stroke();
    }

    ctx.beginPath();
    ctx.fillStyle = "rgba(255, 105, 135, 0.65)";
    ctx.arc(cx, cy, 6, 0, Math.PI * 2);
    ctx.fill();

    const t = tRef.current;
    users.forEach((u) => {
      const phi = phaseMap.get(u.id) || 0;
      const spin = 0.3 + (u.id.charCodeAt(0) % 7) * 0.05;
      const dist = u.distanceMeters == null ? 800 : u.distanceMeters;
      const rFrac = clamp((dist / 2000) * 0.8 + 0.2, 0.2, 1);
      const r = radius * rFrac;

      const x = cx + Math.cos(phi + t * spin) * r;
      const y = cy + Math.sin(phi + t * spin) * r;

      const bubble = ctx.createRadialGradient(x, y, 0, x, y, 16);
      bubble.addColorStop(0, "rgba(255, 105, 135, 0.9)");
      bubble.addColorStop(1, "rgba(255, 105, 135, 0.0)");
      ctx.fillStyle = bubble;
      ctx.beginPath();
      ctx.arc(x, y, 16, 0, Math.PI * 2);
      ctx.fill();

      ctx.beginPath();
      ctx.fillStyle = "white";
      ctx.arc(x, y, 4, 0, Math.PI * 2);
      ctx.fill();
    });

    tRef.current += 0.005;
    animRef.current = requestAnimationFrame(draw);
  }, [users, phaseMap]);

  useEffect(() => {
    animRef.current = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(animRef.current);
  }, [draw]);

  return (
    <div className="relative w-full aspect-square mx-auto max-w-xs md:max-w-sm">
      <canvas ref={canvasRef} className="w-full h-full rounded-full shadow-inner" />
      <div className="absolute -bottom-5 left-1/2 -translate-x-1/2 text-[10px] text-rose-600/70">
        <FaMapMarkerAlt className="inline mr-1" /> Orbit radius ≈ distance
      </div>
    </div>
  );
}

/* ============================================================
   Compact vibe controls
============================================================ */
// Public, visible on profile (segmented)
const PRIMARY_PUBLIC = [
  { key: "", label: "All" },
  { key: "serious", label: "Long-term" },
  { key: "casual", label: "Casual" },
  { key: "friends", label: "Friends" },
  { key: "gymbuddy", label: "GymBuddy" },
];

// Filter dropdown lists (Public + Private only here)
const PUBLIC_LIST = [
  { key: "", label: "All" },
  { key: "serious", label: "Long-term dating 💍" },
  { key: "casual", label: "Casual date 🥂" },
  { key: "friends", label: "New friends 🧑‍🤝‍🧑" },
  { key: "gymbuddy", label: "Fitness partner 🏋️" },
];
const PRIVATE_LIST = [
  { key: "flirty", label: "Flirty 😉" },
  { key: "chill", label: "Cozy & chill 📺" },
  { key: "timepass", label: "Low-pressure chat 🫧" },
];

// Premium restricted options are shown in a locked box separately
const RESTRICTED_LIST = [
  { key: "ons", label: "One-night connection ⚡" },
  { key: "threesome", label: "Group date (18+) 🎭" },
  { key: "onlyfans",  label: "OnlyFans 🔥" },

];

function Segmented({ value, onChange, options }) {
  return (
    <div className="inline-flex bg-white rounded-full p-1 shadow-sm border">
      {options.map((opt) => {
        const active = opt.key === value;
        return (
          <button
            key={opt.key}
            onClick={() => onChange(opt.key)}
            className={`px-3 py-1.5 text-sm rounded-full transition ${
              active ? "bg-rose-500 text-white" : "text-gray-700 hover:bg-gray-50"
            }`}
          >
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}

function FilterDropdown({ value, onPick, buttonClass = "" }) {
  const [open, setOpen] = useState(false);
  const all = [...PUBLIC_LIST, ...PRIVATE_LIST];
  const current = all.find((x) => x.key === value) || PUBLIC_LIST[0];

  const menuRef = useRef(null);
  useEffect(() => {
    const onDoc = (e) => {
      if (!menuRef.current) return;
      if (!menuRef.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  const Item = ({ it }) => (
    <button
      onClick={() => {
        setOpen(false);
        onPick(it.key);
      }}
      className="w-full text-left px-3 py-2 rounded hover:bg-rose-50"
    >
      {it.label}
    </button>
  );

  return (
    <div className="relative inline-block" ref={menuRef}>
      <button
        onClick={() => setOpen((v) => !v)}
        className={`px-3 py-1.5 rounded-full bg-white shadow border flex items-center gap-2 ${buttonClass}`}
        title="Filter by vibe"
      >
        <span className="text-gray-700">{current.label}</span>
        <FaChevronDown className="text-gray-600" />
      </button>

      {open && (
        <div className="absolute z-40 mt-2 w-64 bg-white border rounded-2xl shadow-xl p-2">
          <div className="px-2 py-1 text-xs font-semibold text-gray-500">
            Public
          </div>
          {PUBLIC_LIST.map((it) => (
            <Item key={`p-${it.key}`} it={it} />
          ))}

          <div className="px-2 pt-2 pb-1 text-xs font-semibold text-gray-500">
            Private
          </div>
          {PRIVATE_LIST.map((it) => (
            <Item key={`pv-${it.key}`} it={it} />
          ))}
        </div>
      )}
    </div>
  );

}

/* ===== Restricted “Modes” dropdown ===== */
function RestrictedModesDropdown({ onPick, restrictedEligible, onOpenGate, buttonClass = "" }) {
  const [open, setOpen] = useState(false);
  const menuRef = useRef(null);

  useEffect(() => {
    const onDoc = (e) => {
      if (!menuRef.current) return;
      if (!menuRef.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  const handlePick = (key) => {
    setOpen(false);
    if (!restrictedEligible) {
      onOpenGate?.();
      return;
    }
    onPick?.(key);
  };

  return (
    <div className="relative inline-block" ref={menuRef}>
      <button
        onClick={() => setOpen((v) => !v)}
        className={`px-3 py-1.5 rounded-full bg-white shadow border flex items-center gap-2 ${buttonClass}`}
        title="Restricted modes (18+)"
      >
        <span className="text-gray-700">Modes</span>
        <FaChevronDown className="text-gray-600" />
      </button>

      {open && (
        <div className="absolute z-40 mt-2 w-72 bg-white border rounded-2xl shadow-xl p-2">
          <div className="px-3 pt-2 pb-1 text-[11px] font-semibold text-gray-500">
            Premium features • Unlock adult-only filters with verification
          </div>
          <div className="p-1">
            {RESTRICTED_LIST.map((it) => (
              <button
                key={it.key}
                onClick={() => handlePick(it.key)}
                className="w-full text-left px-3 py-2 rounded hover:bg-rose-50 flex items-center justify-between"
              >
                <span>{it.label}</span>
                {!restrictedEligible && <FaLock className="text-gray-400" />}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}


/* ============================================================
   Premium Gate (inline modal)
============================================================ */
function PremiumGate({ open, onClose, onSuccess }) {
  const [step, setStep] = useState(0);
  const [busy, setBusy] = useState(false);
  if (!open) return null;

  const doUpgrade = async () => {
    setBusy(true);
    try {
      await fetch(`${API_BASE}/premium/upgrade`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token()}` },
      });
      setStep(1);
    } finally {
      setBusy(false);
    }
  };

   // 2) Live selfie upload (mock URL or wire to uploader)
  const doSelfie = async () => {
    setBusy(true);
    try {
      // TODO: replace selfieUrl with the result from your uploader / camera
      const r = await fetch(`${API_BASE}/premium/verify/upload-selfie`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token()}`,
        },
        body: JSON.stringify({ selfieUrl: "mock://selfie-proof" }),
      });
      if (!r.ok) throw new Error("selfie_failed");
      setStep(2);
    } catch (e) {
      alert("Selfie upload failed. Please try again.");
    } finally {
      setBusy(false);
    }
  };

  // 3) ID + DOB upload/submit (mock URL + prompt for DOB)
  const doID = async () => {
    setBusy(true);
    try {
      const dob = window.prompt("Enter your DOB (YYYY-MM-DD) for 18+ check:");
      if (!dob) throw new Error("dob_required");

      // TODO: replace idUrl with your actual uploaded document URL
      const r1 = await fetch(`${API_BASE}/premium/verify/upload-id`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token()}`,
        },
        body: JSON.stringify({ idUrl: "mock://gov-id", dob }),
      });
      if (!r1.ok) {
        const j = await r1.json().catch(() => ({}));
        throw new Error(j?.error || "id_failed");
      }

      // Auto-approve if both selfie & ID exist and age >= 18
      const r2 = await fetch(`${API_BASE}/premium/verify/auto-approve`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token()}` },
      });

      if (r2.status === 403) {
        const j = await r2.json().catch(() => ({}));
        if (j?.error === "underage") {
          alert("Sorry, you must be 18+ to use adult-only features.");
          setBusy(false);
          return; // stop wizard
        }
      }

      if (!r2.ok) throw new Error("verify_failed");

      setStep(3); // proceed to consent
    } catch (e) {
      alert("Verification failed. Please re-check your info and try again.");
    } finally {
      setBusy(false);
    }
  };


  const doConsent = async () => {
    setBusy(true);
    try {
      await fetch(`${API_BASE}/premium/consent`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token()}`,
        },
        body: JSON.stringify({ textHash: "terms-restricted-v1" }),
      });
      onSuccess?.();
      onClose();
    } finally {
      setBusy(false);
    }
  };

  const steps = [
    {
      title: "Upgrade to Premium",
      desc: "Unlock restricted filters.",
      action: doUpgrade,
      cta: "Upgrade",
    },
    {
      title: "Live selfie check",
      desc: "Quick liveness capture.",
      action: doSelfie,
      cta: "Take selfie",
    },
    {
      title: "Scan government ID (18+)",
      desc: "Age verification required.",
      action: doID,
      cta: "Scan ID",
    },
    {
      title: "Accept safety agreement",
      desc: "Consent & community rules.",
      action: doConsent,
      cta: "Accept & unlock",
    },
  ];

  const s = steps[step];

  return (
    <div className="fixed inset-0 z-50 bg-black/50 flex items-center justify-center p-4">
      <div className="bg-white rounded-2xl max-w-sm w-full p-5 shadow-xl">
        <h3 className="text-lg font-semibold mb-1">{s.title}</h3>
        <p className="text-sm text-gray-600 mb-4">
          {s.desc} Adults only (18+). Consent required. No illegal use.
        </p>
        <div className="flex items-center justify-between text-xs text-gray-500 mb-4">
          <span>
            Step {step + 1} / {steps.length}
          </span>
        </div>
        <div className="flex gap-2 justify-end">
          <button className="px-4 py-2 rounded border" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button
            className="px-4 py-2 rounded text-white bg-rose-600 disabled:opacity-60"
            onClick={s.action}
            disabled={busy}
          >
            {busy ? "Working..." : s.cta}
          </button>
        </div>
      </div>
    </div>
  );
}
/* ============================================================
   Visibility helpers
============================================================ */
const getVisibilityMode = (u) => (u?.visibilityMode || "auto"); // "auto" | "limited" | "full" | "hidden"

// Field-level guard: "public" (default) | "matches" | "hidden"
const canShowField = (u, key, matched = false) => {
  const rule = u?.fieldVisibility?.[key] || "public";
  if (rule === "hidden") return false;
  if (rule === "matches") return !!matched;
  return true;
};

// Card blur logic for *non-matches* in Discover:
//  - full     → no blur
//  - limited  → no blur (info limited elsewhere)
//  - auto     → blurred (we use reveal 0..1 you already had)
//  - hidden   → filtered out of list (never shown)
const computeBlurPx = (u, reveal) => {
  const mode = getVisibilityMode(u);
  if (mode === "full" || mode === "limited") return "0px";
  if (mode === "auto") {
    if (!UX.AUTO_BLUR) return "0px";
    const maxBlur = 18;
    const px = Math.round((1 - reveal) * maxBlur);
    return `${px}px`;
  }
  // "hidden" should be filtered, but default to strong blur if it slips through
  return "18px";
};

/* ============================================================
   Discover Page (swipe-first)
============================================================ */
export default function Discover() {
  const navigate = useNavigate();
  const me = getStoredUser();

  // Geo
  const [coords, setCoords] = useState(null);

  // Data
  const [users, setUsers] = useState([]); // stack; index 0 is top card
  const current = users[0] || null;

  // UI
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState("");
  const [myMood, setMyMood] = useState(""); // public
  const [filterMood, setFilterMood] = useState(""); // filter
  const [reveal, setReveal] = useState(0);
  const [buzzing, setBuzzing] = useState(false);
  const [wingmanOpeners, setWingmanOpeners] = useState([]);
  const [buzzZoneCount, setBuzzZoneCount] = useState(0);

  // Premium gate
  const [gateOpen, setGateOpen] = useState(false);
  const [restrictedEligible, setRestrictedEligible] = useState(false);

  // Sockets
  const socketRef = useRef(null);

  /* ---------------------------
   Geolocation
  --------------------------- */
  useEffect(() => {
    let cancelled = false;
    if (!navigator.geolocation) {
      setCoords(null);
      return;
    }
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        if (cancelled) return;
        const { latitude, longitude } = pos.coords;
        setCoords({ lat: latitude, lng: longitude });
      },
      () => setCoords(null),
      { enableHighAccuracy: true, timeout: 8000, maximumAge: 5000 }
    );
    return () => {
      cancelled = true;
    };
  }, []);

  /* ---------------------------
   Socket
  --------------------------- */
  useEffect(() => {
    const s = io(SOCKET_URL, { auth: { token: token() } });
    socketRef.current = s;

    s.on("connect", () => {
      const uid = me?.id;
      if (uid) s.emit("register", uid);
    });

    s.on("match", ({ otherUserId }) => {
      if (current && otherUserId === current.id) {
        setMessage("💞 It's a match!");
        setReveal(1);
      }
    });

    s.on("buzz_request", () => setMessage("💌 Someone nearby buzzed you"));

    return () => s.disconnect();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /* ---------------------------
   Premium status
  --------------------------- */
  useEffect(() => {
    (async () => {
      try {
        const r = await fetch(`${API_BASE}/premium/status`, {
          headers: { Authorization: `Bearer ${token()}` },
        });
        if (r.ok) {
          const j = await r.json();
          const ok =
            (j.premiumTier && j.premiumTier !== "free") &&
            j.kycStatus === "verified" &&
            j?.consent?.restrictedAccepted;
          setRestrictedEligible(!!ok);
        }
      } catch {}
    })();
  }, []);

  /* ---------------------------
   Fetch discover
  --------------------------- */
  const fetchDiscover = useCallback(
    async (extra = {}) => {
      setLoading(true);
      try {
        const qs = new URLSearchParams();
        if (coords?.lat) qs.set("lat", String(coords.lat));
        if (coords?.lng) qs.set("lng", String(coords.lng));
        if (filterMood) qs.set("vibe", filterMood);
        Object.entries(extra).forEach(([k, v]) => {
          if (v !== "" && v != null) qs.set(k, String(v));
        });

        const res = await fetch(`${API_BASE}/discover?${qs.toString()}`, {
          headers: { Authorization: `Bearer ${token()}` },
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data?.error || "discover_failed");
        let list = Array.isArray(data.users) ? data.users : [];

        // Filter out users who set visibility to "hidden"
        list = list.filter((u) => getVisibilityMode(u) !== "hidden");

        // compute buzz zone (within 50m)
        const crowd = list.filter(
          (u) => typeof u.distanceMeters === "number" && u.distanceMeters <= 50
        );

        setBuzzZoneCount(crowd.length);

        setUsers(list);
        setReveal(0);
      } catch (e) {
        console.error("DISCOVER error:", e);
      } finally {
        setLoading(false);
      }
    },
    [coords, filterMood]
  );

  useEffect(() => {
    fetchDiscover();
  }, [fetchDiscover]);

  /* ---------------------------
   Mood persistence & filter picking
  --------------------------- */
  const updateMyMood = async (key) => {
    setMyMood(key);
    try {
      await putMe({ vibe: key });
    } catch {}
    fetchDiscover();
  };

  const pickFilterMood = (key) => {
    setFilterMood(key);
    fetchDiscover({ vibe: key });
  };

  /* ---------------------------
   Swipe handling (like Tinder)
  --------------------------- */
  const dragRef = useRef({ active: false, x: 0, y: 0, startX: 0, startY: 0 });

  const onPointerDown = (e) => {
    const p = dragRef.current;
    p.active = true;
    p.startX = e.clientX || (e.touches && e.touches[0]?.clientX) || 0;
    p.startY = e.clientY || (e.touches && e.touches[0]?.clientY) || 0;
    p.x = 0;
    p.y = 0;
  };

  const onPointerMove = (e) => {
    const p = dragRef.current;
    if (!p.active) return;
    const cx = e.clientX || (e.touches && e.touches[0]?.clientX) || 0;
    const cy = e.clientY || (e.touches && e.touches[0]?.clientY) || 0;
    p.x = cx - p.startX;
    p.y = cy - p.startY;
    // Trigger small reveal when dragging
    setReveal((r) => clamp(r + 0.01, 0, 1));
  };

  const removeTopCard = () => {
    setUsers((prev) => prev.slice(1));
    setReveal(0);
  };

  const onPointerUp = async () => {
    const p = dragRef.current;
    if (!p.active) return;
    p.active = false;

    const THRESH_X = 120;

    if (p.x > THRESH_X) {
      await handleBuzz(true); // animate-like path
    } else if (p.x < -THRESH_X) {
      handleSkip(true);
    } else {
      // snap back
      setCardStyle({ x: 0, y: 0, rot: 0, opacityLike: 0, opacityNope: 0 });
    }
  };

  const [cardStyle, setCardStyle] = useState({
    x: 0,
    y: 0,
    rot: 0,
    opacityLike: 0,
    opacityNope: 0,
  });

  useEffect(() => {
    const p = dragRef.current;
    if (!p.active) return;

    const id = requestAnimationFrame(() => {
      const rot = p.x / 15; // tilt
      const like = clamp(p.x / 120, 0, 1);
      const nope = clamp(-p.x / 120, 0, 1);
      setCardStyle({ x: p.x, y: p.y, rot, opacityLike: like, opacityNope: nope });
    });

    return () => cancelAnimationFrame(id);
  });

  /* ---------------------------
   Buttons replicate swipe
  --------------------------- */
  const handleSkip = (alreadySwiped = false) => {
    if (!current) return;
    if (!alreadySwiped) {
      // animate left
      setCardStyle({ x: -window.innerWidth, y: 0, rot: -20, opacityLike: 0, opacityNope: 1 });
      setTimeout(removeTopCard, 180);
    } else {
      removeTopCard();
    }
  };

  const buzzAPI = async (userId) => {
    const res = await fetch(`${API_BASE}/likes`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token()}`,
      },
      body: JSON.stringify({ to: userId }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data?.error || "buzz_failed");
    return data;
  };

  const handleBuzz = async (alreadySwiped = false) => {
    if (!current) return;
    setBuzzing(true);
    try {
      if (!alreadySwiped) {
        // animate right
        setCardStyle({ x: window.innerWidth, y: 0, rot: 20, opacityLike: 1, opacityNope: 0 });
      }
      const data = await buzzAPI(current.id);

      if (data.matched) {
        setMessage(`💞 It's a match with ${current.firstName || "someone"}!`);
        setReveal(1);
      } else {
        setMessage(`✅ You buzzed ${current.firstName || "someone"}!`);
        setReveal((r) => clamp(r + 0.4, 0, 1));
      }

      if (UX.LIKE_AUTOSKIP) {
        setTimeout(removeTopCard, alreadySwiped ? 0 : 180);
      }
    } catch (e) {
      alert(e.message || "Something went wrong");
      // snap back on error
      setCardStyle({ x: 0, y: 0, rot: 0, opacityLike: 0, opacityNope: 0 });
    } finally {
      setBuzzing(false);
    }
  };

  const tapToReveal = () => {
    if (!UX.TAP_TO_REVEAL) return;
    setReveal((r) => clamp(r + 0.2, 0, 1));
  };

  const openProfile = () => {
    if (!current) return;
    if (me && current.id === me.id) {
      navigate("/profile");
    } else {
      // tiny preview payload if backend blocks
      const previewFromDiscover = {
        id: current.id,
        firstName: current.firstName,
        lastName: current.lastName,
        avatar: current.avatar,
        media: Array.isArray(current.media) ? current.media.slice(0, 3) : [],
        bio: current.bio || "",
        dob: current.dob,
        height: current.height,
        city: current.city,
        orientation: current.orientation,
        interests: current.interests || [],
        hobbies: current.hobbies || [],
        favorites: current.favorites || [],
        distanceMeters: current.distanceMeters,
        verified: current.verified,
        visibilityMode: current.visibilityMode,
        fieldVisibility: current.fieldVisibility || {},
      };
      // NOTE: route fixed to /view/:id to match App.jsx
      navigate(`/view/${current.id}`, { state: { previewFromDiscover } });
    }
  };

  /* ---------------------------
   Wingman openers
  --------------------------- */
  const fetchWingman = async () => {
    try {
      const mySummary = `${me?.firstName || ""} likes ${(me?.interests || [])
        .slice(0, 3)
        .join(", ")}`;
      const their =
        `${current?.firstName || "They"}: ` +
        `${(current?.bio || "").slice(0, 120)}`;
      const res = await fetch(`${API_BASE}/ai/wingman/suggest`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token()}`,
        },
        body: JSON.stringify({
          myProfileSummary: mySummary,
          theirProfileSummary: their,
          style: "friendly",
        }),
      });
      const data = await res.json();
      if (res.ok && Array.isArray(data.suggestions)) {
        setWingmanOpeners(data.suggestions);
      } else {
        setWingmanOpeners([]);
      }
    } catch {
      setWingmanOpeners([]);
    }
  };

  /* ---------------------------
   Derived styles
  --------------------------- */
  const blurPx = useMemo(() => {
    if (!current) return "0px";
    return computeBlurPx(current, reveal);
  }, [current, reveal]);

  const moodBg = useMemo(() => {
    switch (filterMood) {
      case "flirty":
        return "from-rose-100 via-pink-100 to-rose-200";
      case "chill":
        return "from-sky-100 via-blue-100 to-sky-200";
      case "timepass":
        return "from-amber-100 via-yellow-100 to-amber-200";
      case "serious":
        return "from-rose-100 via-rose-50 to-rose-200";
      case "casual":
        return "from-pink-100 via-rose-100 to-red-100";
      case "friends":
        return "from-violet-100 via-fuchsia-100 to-violet-200";
      case "gymbuddy":
        return "from-emerald-100 via-green-100 to-emerald-200";
      default:
        return "from-pink-100 via-rose-100 to-red-100";
    }
  }, [filterMood]);

  /* ---------------------------
   Loading / Empty
  --------------------------- */
  if (loading) {
    return (
      <div className={`min-h-screen flex items-center justify-center bg-gradient-to-br ${moodBg}`}>
        <div className="text-gray-700 animate-pulse">Scanning nearby buzzers…</div>
      </div>
    );
  }

  if (!current && users.length === 0) {
    return (
      <div className={`min-h-screen flex flex-col items-center justify-center gap-4 bg-gradient-to-br ${moodBg}`}>
        <div className="text-gray-800">No new buzzers nearby 💫</div>
        <button
          onClick={() => fetchDiscover()}
          className="px-5 py-2 rounded-full bg-white shadow hover:bg-rose-50 text-rose-600 flex items-center gap-2"
        >
          <FaSyncAlt /> Refresh
        </button>
      </div>
    );
  }

  /* ---------------------------
   UI Layout: center swipe card, radar side
  --------------------------- */
  return (
    <div className={`min-h-screen bg-gradient-to-br ${moodBg}`}>
      <div className="max-w-6xl mx-auto px-4 pt-6 pb-24">
        {/* Top controls row */}
<div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between mb-8 md:mb-10">
          {/* My vibe */}
          <div className="flex items-center gap-3">
            <span className="text-xs text-gray-600">My vibe:</span>
            <Segmented value={myMood} onChange={updateMyMood} options={PRIMARY_PUBLIC} />
          </div>

     {/* Filter + actions */}
<div className="flex items-center gap-2">
  <span className="text-xs text-gray-600">Filter:</span>
  <FilterDropdown value={filterMood} onPick={pickFilterMood} />

  {/* ⬇️ New: Restricted “Modes” dropdown */}
  <RestrictedModesDropdown
    restrictedEligible={restrictedEligible}
    onOpenGate={() => setGateOpen(true)}
    onPick={(key) => {
      setFilterMood(key);
      fetchDiscover({ vibe: key });
    }}
  />

  <button
    onClick={() => fetchDiscover()}
    className="px-3 py-1.5 rounded-full bg-white shadow text-rose-600 flex items-center gap-2"
    title="Refresh"
  >
    <FaSyncAlt /> Refresh
  </button>
  {UX.SHOW_WINGMAN && (
    <button
      onClick={fetchWingman}
      className="px-3 py-1.5 rounded-full bg-gradient-to-r from-rose-500 to-pink-500 text-white shadow flex items-center gap-2"
      title="Wingman pick"
    >
      <FaMagic /> Wingman pick
    </button>
  )}
</div>

        </div>

        {/* BuzzZone banner */}
        {UX.SHOW_BUZZZONE && buzzZoneCount >= 2 && (
          <div className="mb-4 p-3 rounded-xl bg-white/70 backdrop-blur border text-rose-700 flex items-center gap-2 shadow-sm">
            <FaBolt />
            <span className="font-medium">BuzzZone active: {buzzZoneCount} people within 50m</span>
          </div>
        )}

        {/* Grid: center = swipe card; side = radar */}
<div className="grid grid-cols-1 md:grid-cols-3 gap-8 md:gap-12 items-start">
          {/* Left / on mobile hidden spacer */}
          <div className="hidden md:block" />

          {/* Center: swipe stack */}
          <div className="flex flex-col items-center">
            {/* Toast */}
            {message && (
              <div className="mb-3">
                <div className="inline-block px-4 py-2 rounded-full bg-white/80 backdrop-blur text-rose-700 shadow">
                  {message}
                </div>
              </div>
            )}

            {/* Card stack (show top + a faint next underneath) */}
<div className="relative w-full max-w-sm h-[28rem] mt-2 md:mt-4">
              {/* Next card preview */}
              {users[1] && (
                <div className="absolute inset-0 bg-white rounded-2xl overflow-hidden shadow-xl scale-95 translate-y-3 opacity-70 pointer-events-none">
                  <img
                    src={users[1].avatar || PLACEHOLDER}
                    alt="next"
                    className="w-full h-full object-cover"
                    onError={(e) => {
                      if (e.currentTarget.src !== PLACEHOLDER)
                        e.currentTarget.src = PLACEHOLDER;
                    }}
                  />
                </div>
              )}

              {/* Top card (draggable) */}
              {current && (
                <div
                  className="absolute inset-0 bg-white rounded-2xl overflow-hidden shadow-2xl cursor-grab active:cursor-grabbing select-none"
                  style={{
                    transform: `translate(${cardStyle.x}px, ${cardStyle.y}px) rotate(${cardStyle.rot}deg)`,
                    transition: dragRef.current.active ? "none" : "transform 180ms ease",
                  }}
                  {...(UX.SWIPE_ENABLED
                    ? {
                        onMouseDown: onPointerDown,
                        onMouseMove: onPointerMove,
                        onMouseUp: onPointerUp,
                        onMouseLeave: () => dragRef.current.active && onPointerUp(),
                        onTouchStart: onPointerDown,
                        onTouchMove: onPointerMove,
                        onTouchEnd: onPointerUp,
                      }
                    : {})}
                  onClick={(e) => {
                    e.stopPropagation();
                    tapToReveal();
                  }}
                >
                  <div className="relative w-full h-full bg-gray-200">
                    <img
                      src={current.avatar || PLACEHOLDER}
                      alt={current.firstName}
                      className="w-full h-full object-cover"
                      style={{ filter: `blur(${blurPx})` }}
                      draggable={false}
                      onError={(e) => {
                        if (e.currentTarget.src !== PLACEHOLDER)
                          e.currentTarget.src = PLACEHOLDER;
                      }}
                    />

                    {/* LIKE / NOPE overlays */}
                    <div
                      className="absolute top-4 left-4 px-3 py-1 border-4 rounded-xl text-2xl font-extrabold"
                      style={{
                        borderColor: `rgba(16, 185, 129, ${cardStyle.opacityLike})`,
                        color: `rgba(16, 185, 129, ${cardStyle.opacityLike})`,
                        transform: "rotate(-15deg)",
                        opacity: cardStyle.opacityLike,
                      }}
                    >
                      LIKE
                    </div>
                    <div
                      className="absolute top-4 right-4 px-3 py-1 border-4 rounded-xl text-2xl font-extrabold"
                      style={{
                        borderColor: `rgba(244, 63, 94, ${cardStyle.opacityNope})`,
                        color: `rgba(244, 63, 94, ${cardStyle.opacityNope})`,
                        transform: "rotate(15deg)",
                        opacity: cardStyle.opacityNope,
                      }}
                    >
                      NOPE
                    </div>

                    {/* Top-right small chips */}
                    <div className="absolute top-3 right-3 flex gap-2">
                      {["auto", "limited"].includes(getVisibilityMode(current)) && UX.AUTO_BLUR && (
                        <span className="px-2 py-0.5 rounded-full text-xs bg-white/80 backdrop-blur text-gray-700 border">
                          Preview
                        </span>
                      )}
                      {current.verified && (
                        <span className="px-2 py-0.5 rounded-full text-xs bg-emerald-100 text-emerald-700">
                          Verified
                        </span>
                      )}
                      {current.vibe && (
                        <span className="px-2 py-0.5 rounded-full text-xs bg-rose-100 text-rose-700">
                          {current.vibe}
                        </span>
                      )}
                    </div>

                    {/* Footer */}
                    <div className="absolute inset-x-0 bottom-0 p-4 bg-gradient-to-t from-black/70 to-transparent text-white">
                      <div
                          className="flex items-center gap-2 text-2xl font-semibold hover:underline"
                          onClick={(e) => {
                            e.stopPropagation();
                            openProfile();
                          }}
                        >
                          {current.firstName} {current.lastName}
                          <span
                            className={`inline-block w-3 h-3 rounded-full ${
                              current.status === "active"
                                ? "bg-green-500 shadow-[0_0_6px_2px_rgba(34,197,94,0.6)] animate-pulse"
                                : "bg-gray-400"
                            }`}
                            title={current.status === "active" ? "Online" : "Offline"}
                          ></span>
                        </div>

                      <div className="text-sm opacity-90 line-clamp-2">
                        {current.bio ? current.bio : "No bio yet."}
                      </div>

                      <div className="text-xs opacity-80 italic mt-1">
                        {UX.TAP_TO_REVEAL ? "Drag to swipe • Tap to reveal" : "Drag to swipe"}
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Controls */}
            <div className="mt-5 flex items-center justify-center gap-6">
              {/* Skip */}
              <button
                onClick={() => handleSkip(false)}
                className="w-14 h-14 rounded-full bg-white shadow hover:shadow-md border border-gray-200 flex items-center justify-center text-gray-600 hover:scale-105 transition"
                title="Skip"
              >
                <FaTimes size={20} />
              </button>
              {/* Like / Buzz */}
              <button
                onClick={() => handleBuzz(false)}
                disabled={buzzing}
                title="Buzz (like)"
                className={`w-20 h-20 rounded-full relative overflow-hidden transition hover:scale-105 group
                bg-gradient-to-br from-rose-400 to-pink-500 text-white shadow-lg disabled:opacity-60
                ${!buzzing ? "animate-[pulse_2.5s_ease-in-out_infinite]" : ""}`}
              >
                <span className="pointer-events-none absolute inset-0 opacity-0 group-hover:opacity-100 transition">
                  <span className="absolute -inset-10 rotate-45 bg-white/15 blur-2xl" />
                </span>
                <FaHeart size={26} className="mx-auto" />
              </button>
              {/* View profile */}
              <button
                onClick={openProfile}
                className="w-14 h-14 rounded-full bg-white shadow hover:shadow-md border border-gray-200 flex items-center justify-center text-rose-600 hover:scale-105 transition"
                title="View profile"
              >
                <FaUser size={18} />
              </button>
            </div>

            {/* Voice intro */}
            {current?.voiceIntro && (
              <div className="mt-4 flex items-center justify-center">
                <button
                  onClick={() => {
                    const a = new Audio(current.voiceIntro);
                    a.play().catch(() => {});
                    setReveal((r) => clamp(r + 0.15, 0, 1));
                  }}
                  className="px-4 py-2 rounded-full bg-white shadow border text-gray-700 flex items-center gap-2"
                >
                  <FaHeadphones /> Listen (3s)
                </button>
              </div>
            )}

            {/* Wingman openers */}
            {UX.SHOW_WINGMAN && wingmanOpeners.length > 0 && (
              <div className="mt-5 p-3 rounded-2xl bg-white/80 backdrop-blur border shadow-sm w-full max-w-sm">
                <div className="text-sm font-semibold text-rose-700 mb-2">Wingman suggests:</div>
                <ul className="space-y-2 text-sm">
                  {wingmanOpeners.map((s, i) => (
                    <li
                      key={i}
                      className="p-2 rounded-xl bg-white border hover:bg-rose-50 cursor-pointer"
                      onClick={() => {
                        navigator.clipboard?.writeText(s).catch(() => {});
                        setMessage("Copied opener ✨");
                      }}
                    >
                      {s}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {/* Right: radar (moves below on mobile) */}
          {UX.SHOW_RADAR && (
            <div className="md:sticky md:top-24">
              <div className="md:block">
                <RadarCanvas users={users} />
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Premium gate */}
      <PremiumGate
        open={gateOpen}
        onClose={() => setGateOpen(false)}
        onSuccess={() => {
          setRestrictedEligible(true);
          setGateOpen(false);
        }}
      />
    </div>
  );
}
