// src/pages/ChatWindow.jsx
import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  FaPhone,
  FaVideo,
  FaTimes,
  FaPaperclip,
  FaSmile,
  FaPaperPlane,
  FaMicrophone,
  FaMicrophoneSlash,
  FaVideoSlash,
  FaSyncAlt,
  FaPalette,
  FaPhoneSlash,
} from "react-icons/fa";

import EmojiPicker from "emoji-picker-react";
import { useNavigate } from "react-router-dom";
import AiWingmanChat from "../components/AiWingmanChat";
import MeetMap from "../components/MeetMap";
import { FaMapMarkerAlt } from "react-icons/fa";

//const API_BASE = "http://localhost:4000";
const API_BASE = process.env.REACT_APP_API_BASE || "https://rombuzz-api.onrender.com/api";

// STUN for NAT traversal (add TURN in prod)
const ICE_CONFIG = {
  iceServers: [
    { urls: "stun:stun.l.google.com:19302" },
    { urls: "stun:stun1.l.google.com:19302" },
  ],
};

// Simple “Snapchat-like” CSS filters (applied to local preview)
const VIDEO_FILTERS = [
  "none",
  "grayscale(100%)",
  "sepia(100%)",
  "contrast(150%)",
  "saturate(160%)",
  "hue-rotate(25deg)",
  "hue-rotate(300deg) saturate(140%)",
  "brightness(110%) contrast(110%)",
];


// ===== Serialization helpers (keep your ::RBZ:: format) =====
const RBZ_TAG = "::RBZ::";
const encodePayload = (obj) => `${RBZ_TAG}${JSON.stringify(obj)}`;
const maybeDecode = (m) => {
  if (!m) return m;
  if (m.type === "image" || m.type === "video" || m.url) return m;
  if (typeof m.text === "string" && m.text.startsWith(RBZ_TAG)) {
    try {
      const payload = JSON.parse(m.text.slice(RBZ_TAG.length));
      return { ...m, ...payload };
    } catch {}
  }
  return m;
};

// ===== Local per-room storage =====
const k = (roomId, name) => `RBZ:${roomId}:${name}`;
const getLS = (key, fallback) => {
  try {
    const v = localStorage.getItem(key);
    return v ? JSON.parse(v) : fallback;
  } catch {
    return fallback;
  }
};
const setLS = (key, val) => {
  try {
    localStorage.setItem(key, JSON.stringify(val));
  } catch {}
};

const EDIT_MS = 60 * 60 * 1000; // 1h
const THEMES = {
  default:  { wrap: "", pane: "bg-white", messages: "bg-gradient-to-br from-rose-50 to-rose-100" },
  midnight: { wrap: "bg-gray-900 text-gray-100", pane: "bg-gray-900", messages: "bg-gray-900" },
  rose:     { wrap: "bg-rose-50", pane: "bg-white", messages: "bg-gradient-to-br from-rose-50 to-rose-100" },
  ocean:    { wrap: "bg-sky-50", pane: "bg-white", messages: "bg-gradient-to-br from-sky-50 to-teal-50" },

  // NEW
  forest:   { wrap: "bg-emerald-50", pane: "bg-white", messages: "bg-gradient-to-br from-emerald-50 to-lime-50" },
  lavender: { wrap: "bg-purple-50",  pane: "bg-white", messages: "bg-gradient-to-br from-purple-50 to-fuchsia-50" },
  sunset:   { wrap: "bg-orange-50",  pane: "bg-white", messages: "bg-gradient-to-br from-amber-50 to-rose-100" },
  mono:     { wrap: "bg-gray-50",    pane: "bg-white", messages: "bg-gradient-to-br from-gray-50 to-gray-100" },
  terminal: { wrap: "bg-black text-green-200", pane: "bg-black", messages: "bg-black" },
  candy:    { wrap: "bg-pink-50",    pane: "bg-white", messages: "bg-gradient-to-br from-pink-50 to-rose-100" },
};

export default function ChatWindow({ socket, me, peer, onClose }) {
  const navigate = useNavigate();

  // ============= computed & auth =============
  const myId = me.id || me._id;
  const peerId = peer.id || peer._id;
  const roomId = useMemo(() => {
    const a = String(myId), b = String(peerId);
    return a < b ? `${a}_${b}` : `${b}_${a}`;
  }, [myId, peerId]);
  const token = localStorage.getItem("token") || sessionStorage.getItem("token");

  // ============= state =============
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [typing, setTyping] = useState(false);
  const [peerOnline, setPeerOnline] = useState(false);

  // composer/ui
  const [showEmoji, setShowEmoji] = useState(false);
  const [blockedBanner, setBlockedBanner] = useState({ iBlocked: false, blockedMe: false });
  const [manualOffline, setManualOffline] = useState(false);
  const [onlineAlert, setOnlineAlert] = useState(false);
  const [nickname, setNickname] = useState("");
const [theme, setTheme] = useState("default");
const [showHeaderMenu, setShowHeaderMenu] = useState(false); // 👈 new

  // Wingman
const [showWing, setShowWing] = useState(false);
// Map meet
const [showMap, setShowMap] = useState(false);

// 🔇 Mute per-chat
const [mute, setMute] = useState(false);

// 📌 Pinned messages
const [pinnedIds, setPinnedIds] = useState([]);

// reactions/read receipts (move this block up BEFORE searchHits)

 const [seenMap, setSeenMap] = useState({}); // {msgId: true}
  const [hiddenIds, setHiddenIds] = useState({}); // local "unsend for me"
  // 🔍 Search in conversation
const [searchQuery, setSearchQuery] = useState("");
const [searchIndex, setSearchIndex] = useState(0);

const searchHits = useMemo(() => {
  if (!searchQuery) return [];
  const q = searchQuery.toLowerCase();
  return messages
    .map(maybeDecode)
    .filter((m) => !hiddenIds[m.id])
    .filter((m) => (m.textFallback || m.text || m.url || "").toLowerCase().includes(q))
    .map((m) => m.id);
}, [messages, hiddenIds, searchQuery]);

useEffect(() => { setSearchIndex(0); }, [searchQuery]);

const jumpToHit = (dir = 1) => {
  if (!searchHits.length) return;
  const i = (searchIndex + dir + searchHits.length) % searchHits.length;
  setSearchIndex(i);
  const id = searchHits[i];
  const el = document.getElementById(`msg-${id}`);
  el?.scrollIntoView({ behavior: "smooth", block: "center" });
};

// 🖼️ Media gallery modal
const [showGallery, setShowGallery] = useState(false);

// ✅ Multi-select delete mode
const [selectMode, setSelectMode] = useState(false);
const [selectedIds, setSelectedIds] = useState({});

// 👇 new
const [reactFor, setReactFor] = useState(null);       // message to react to

  // attachments/camera (reuse your Cloudinary unsigned flow)
  const CLOUD_NAME = "drcxu0mks";
  const UPLOAD_PRESET = "rombuzz_unsigned";

  // reply + selection
  const [replyTo, setReplyTo] = useState(null); // {id, preview, type}
  const [actionBar, setActionBar] = useState(null); // message currently selected for long-press action
  const actionBarTimer = useRef(null);

  // reactions/read receipts
 
  const chatEndRef = useRef(null);
// call (simple-peer)
const [showCall, setShowCall] = useState(false);
const [callType, setCallType] = useState(null); // "audio" | "video"
const [callError, setCallError] = useState("");
const [ringing, setRinging]   = useState(false);  // 👈 add back

// NEW flags
const [isCaller, setIsCaller] = useState(false); // am I the one who placed the call?
const [incoming, setIncoming] = useState(false); // receiver is seeing the accept/decline UI
const [inCall, setInCall] = useState(false);     // connected

// media toggles
const [muted, setMuted] = useState(false);
const [cameraOn, setCameraOn] = useState(true);     // for video calls
const [usingFront, setUsingFront] = useState(true); // camera facing
const [filterIndex, setFilterIndex] = useState(0);  // CSS filter

const peerRef = useRef(null);
const streamRef = useRef(null);
const remoteVideoRef = useRef(null);
const localVideoRef  = useRef(null);


const playSafe = (ref) => {
  try { ref.current && ref.current.play().catch(()=>{}); } catch {}
};
const stopSafe = (ref) => {
  try { if (ref.current) { ref.current.pause(); ref.current.currentTime = 0; } } catch {}
};


// 🔔 Ringtones (simple: use the two <audio> elements rendered at the bottom)
const callerToneRef   = useRef(null); // ringback for the caller
const incomingToneRef = useRef(null); // ringtone for the receiver



  // ============= hydrate per-room prefs =============
  useEffect(() => {
  if (!roomId) return;
  setNickname(getLS(k(roomId, "nickname"), ""));
  setTheme(getLS(k(roomId, "theme"), "default"));
  setOnlineAlert(!!getLS(k(roomId, "alertOnline"), false));
  setManualOffline(!!getLS(k(roomId, "manualOffline"), false));

  // NEW
  setMute(!!getLS(k(roomId, "mute"), false));
  setPinnedIds(getLS(k(roomId, "pinnedIds"), []));
}, [roomId]);

  // ============= history load =============
  useEffect(() => {
    let mounted = true;
    (async () => {
      try {
        const r = await fetch(`${API_BASE}/api/chat/rooms/${roomId}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!mounted) return;
        const list = await r.json();
        setMessages(Array.isArray(list) ? list.map(maybeDecode) : []);
      } catch {
        setMessages([]);
      }
    })();
    return () => (mounted = false);
  }, [roomId, token]);

  // ============= socket listeners =============
 useEffect(() => {
  if (!socket || !roomId || !peerId) return;

  // ✅ join room for messages
  socket.emit("joinRoom", roomId);

  // ✅ fetch initial online/offline snapshot once
  fetch(`${API_BASE}/api/presence/${peerId}`)
    .then((r) => r.json())
    .then((d) => setPeerOnline(!!d.online))
    .catch(() => {});

  const onMsg = (raw) => {
    const msg = maybeDecode(raw);
    setMessages((prev) =>
      prev.some((m) => m.id === msg.id) ? prev : [...prev, msg]
    );
  };

  const onTyping = ({ fromId }) => {
    if (fromId === peerId) {
      setTyping(true);
      clearTimeout(onTyping._t);
      onTyping._t = setTimeout(() => setTyping(false), 1500);
    }
  };

  const onEdit = ({ msgId, text }) => {
    setMessages((prev) =>
      prev.map((m) =>
        m.id === msgId ? maybeDecode({ ...m, text }) : m
      )
    );
  };

  const onDelete = ({ msgId }) => {
    setMessages((prev) =>
      prev.map((m) =>
        m.id === msgId
          ? { ...m, deleted: true, text: "This message was unsent" }
          : m
      )
    );
  };

  const onReact = ({ msgId, userId, emoji }) => {
    setMessages((prev) =>
      prev.map((m) => {
        if (m.id !== msgId) return m;
        const reactions = { ...(m.reactions || {}) };
        if (!emoji) delete reactions[userId];
        else reactions[userId] = emoji;
        return { ...m, reactions };
      })
    );
  };

  const onSeen = (msgId) =>
    setSeenMap((prev) => ({ ...prev, [msgId]: true }));

  // ✅ presence events
  const onOnline = ({ userId }) => {
    if (userId === peerId) {
      setPeerOnline(true);
      if (onlineAlert && !mute) notifyOnline(peer);
    }
  };

  const onOffline = ({ userId }) => {
    if (userId === peerId) setPeerOnline(false);
  };

  socket.on("message", onMsg);
  socket.on("chat:message", onMsg);
  socket.on("typing", onTyping);
  socket.on("message:edit", onEdit);
  socket.on("message:delete", onDelete);
  socket.on("message:react", onReact);
  socket.on("message:seen", onSeen);
  socket.on("presence:online", onOnline);
  socket.on("presence:offline", onOffline);
  // ✅ Delivery confirmation listener
  const onDelivered = (ack) => {
    setMessages((prev) =>
      prev.map((m) =>
        m.id === ack.id || m._temp === ack.id
          ? { ...m, _temp: false }
          : m
      )
    );
  };
  socket.on("message:delivered", onDelivered);

  return () => {
    socket.off("message", onMsg);
    socket.off("chat:message", onMsg);
    socket.off("typing", onTyping);
    socket.off("message:edit", onEdit);
    socket.off("message:delete", onDelete);
    socket.off("message:react", onReact);
    socket.off("message:seen", onSeen);
    socket.off("presence:online", onOnline);
    socket.off("presence:offline", onOffline);
    socket.off("message:delivered", onDelivered);
    socket.emit("leaveRoom", roomId);
  };
}, [socket, roomId, peerId, onlineAlert, peer, mute]);

  // autoscroll
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // ============= helpers =============
  const mine = (m) => (m.from || m.fromId) === myId;

  const uploadToCloudinary = async (fileOrBlob) => {
    const form = new FormData();
    form.append("file", fileOrBlob);
    form.append("upload_preset", UPLOAD_PRESET);
    const r = await fetch(`https://api.cloudinary.com/v1_1/${CLOUD_NAME}/auto/upload`, {
      method: "POST",
      body: form,
    });
    const j = await r.json();
    if (!j.secure_url) throw new Error("Cloudinary upload failed");
    return j.secure_url;
  };

  const notifyOnline = async (who) => {
  // 🔇 Respect per-room mute
  if (mute) return;
  try {
    if (!("Notification" in window)) return;
    if (Notification.permission !== "granted") {
      const p = await Notification.requestPermission();
      if (p !== "granted") return;
    }
    new Notification("RomBuzz", {
      body: `${[who.firstName, who.lastName].filter(Boolean).join(" ") || "They"} is online — wanna buzz?`,
    });
  } catch {}
};


  // ============= sending (REST-first) =============
  const sendSerialized = async (payloadObj) => {
    const text = Array.isArray(payloadObj) ? "" : encodePayload(payloadObj);
    const tempId = crypto.randomUUID();
    const serverBody = Array.isArray(payloadObj)
      ? null
      : { text }; // for now we store within ::RBZ::

    // Optimistic local insert
    const temp = {
      id: tempId,
      roomId,
      from: myId,
      to: peerId,
      text: serverBody ? text : "",
      ...(!serverBody && payloadObj), // if array, ignore
      type: payloadObj?.type || (payloadObj?.url ? payloadObj.type : "text"),
      time: new Date().toISOString(),
      _temp: true,
    };

    setMessages((prev) => [...prev, temp]);

    try {
      const r = await fetch(`${API_BASE}/api/chat/rooms/${roomId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ text: text || payloadObj?.text || "" }),
      });
      if (r.status === 403) {
        setBlockedBanner((b) => ({ ...b, blockedMe: true }));
        return;
      }
      const j = await r.json();
      const serverMsg = j?.message ? maybeDecode(j.message) : null;
      if (serverMsg) {
        setMessages((prev) => {
          const exists = prev.some((m) => m.id === serverMsg.id);
          if (exists) return prev.filter((m) => m.id !== tempId);
          return prev.map((m) => (m.id === tempId ? serverMsg : m));
        });
      }
    } catch (e) {
      console.error("send failed", e);
    }
  };

  const onSend = async () => {
    const txt = input.trim();
    if (!txt) return;
    const payload = replyTo
      ? { type: "text", text: txt, replyTo }
      : { type: "text", text: txt };
    setInput("");
    setReplyTo(null);
    await sendSerialized(payload);
  };

  const onPickFile = async (e) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    const url = await uploadToCloudinary(file);
    const type = file.type.startsWith("video") ? "video" : "image";
    const payload = replyTo ? { type, url, replyTo } : { type, url };
    await sendSerialized(payload);
  };

  const onTyping = (v) => {
    setInput(v);
    socket?.emit("typing", { roomId, fromId: myId, toId: peerId });
  };

  // mark a specific peer message as seen
  const markSeen = (msgId) => {
    if (!socket) return;
    socket.emit("message:seen", { roomId, msgId });
  };

  // ============= long-press & swipe-to-reply =============
  const startLongPress = (m) => {
    clearTimeout(actionBarTimer.current);
    actionBarTimer.current = setTimeout(() => {
      setActionBar(m);
    }, 420); // ~Facebookish feel
  };
  const cancelLongPress = () => clearTimeout(actionBarTimer.current);

  // swipe (touch) to reply (drag right)
  const swipeState = useRef({ x: 0, y: 0, dragging: false, deltaX: 0 });
  const onTouchStart = (e) => {
    const t = e.touches?.[0];
    if (!t) return;
    swipeState.current = { x: t.clientX, y: t.clientY, dragging: true, deltaX: 0 };
  };
  const onTouchMove = (e, m) => {
    if (!swipeState.current.dragging) return;
    const t = e.touches?.[0];
    if (!t) return;
    const dx = t.clientX - swipeState.current.x;
    swipeState.current.deltaX = dx;
    // visual hint could be added; we only trigger at threshold
  };
  const onTouchEnd = (m) => {
    if (!swipeState.current.dragging) return;
    const { deltaX } = swipeState.current;
    swipeState.current.dragging = false;
    if (deltaX > 48) {
      // set reply target
      const dec = maybeDecode(m);
      setReplyTo({
        id: m.id,
        type: dec.type || "text",
        preview: dec.url || dec.text || "",
      });
    }
  };

  // ============= per-message actions =============
  const openEmojiReact = async (msg, emoji) => {
    try {
      const r = await fetch(`${API_BASE}/api/chat/rooms/${roomId}/${msg.id}/react`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ emoji }),
      });
      await r.json();
    } catch (e) {
      console.error("react error", e);
    }
  };

  const editMessage = async (msg) => {
    const dec = maybeDecode(msg);
    const fresh = window.prompt("Edit message:", dec?.text || "");
    if (fresh == null) return;
    try {
      const r = await fetch(`${API_BASE}/api/chat/rooms/${roomId}/${msg.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ text: fresh }),
      });
      const j = await r.json();
      if (!j?.ok) {
        alert(j?.error || "Edit failed");
      }
    } catch (e) {
      console.error("edit failed", e);
    }
  };

  const unsendForMe = async (msg) => {
    try {
      const r = await fetch(`${API_BASE}/api/chat/rooms/${roomId}/${msg.id}?scope=me`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });
      const j = await r.json();
      if (j?.ok) setHiddenIds((h) => ({ ...h, [msg.id]: true }));
    } catch (e) {
      console.error("unsend me failed", e);
    }
  };

  const unsendForAll = async (msg) => {
    try {
      const r = await fetch(`${API_BASE}/api/chat/rooms/${roomId}/${msg.id}?scope=all`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });
      const j = await r.json();
      if (!j?.ok) alert(j?.error || "Unsend failed");
    } catch (e) {
      console.error("unsend all failed", e);
    }
  };

  const copyMessage = async (msg) => {
    const dec = maybeDecode(msg);
    const t = dec?.url || dec?.text || "";
    try {
      await navigator.clipboard?.writeText(String(t));
    } catch {}
  };

const beginCall = async (type /* "audio" | "video" */) => {
  setShowCall(true);
  setCallType(type);
  setIsCaller(true);
  setIncoming(false);
  setRinging(true);
  setInCall(false);
  setCallError("");

  // Caller hears ringback (caller tone)
  playSafe(callerToneRef);

  try {
    const selfCall = String(myId) === String(peerId);
    let stream;
    try {
      stream = await navigator.mediaDevices.getUserMedia({
        audio: true,
        video: type === "video" ? { facingMode: usingFront ? "user" : "environment" } : false,
      });
    } catch (e) {
      console.warn("Video unavailable, fallback to audio-only", e);
      stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
      setCameraOn(false);
      if (type === "video") setCallType("audio");
    }

    streamRef.current = stream;
    stream.getAudioTracks()?.forEach(t => (t.enabled = !muted));
    stream.getVideoTracks()?.forEach(t => (t.enabled = type === "video" && cameraOn));

    if (localVideoRef.current && type === "video") {
      localVideoRef.current.srcObject = stream;
      applyLocalFilter();
    }

    const SimplePeer = (await import("simple-peer")).default;
    const p = new SimplePeer({ initiator: true, trickle: true, stream, config: ICE_CONFIG });
    peerRef.current = p;

    // ✅ FIXED: Send signal data properly
    // These are already correct - keep them as is
p.on("signal", (data) => {
  console.log("📡 Sending signal data:", data);
  socket.emit("call:signal", { roomId, payload: { from: myId, data } });
});

    p.on("stream", (remote) => {
      console.log("✅ Remote stream received!");
      if (remoteVideoRef.current) {
        remoteVideoRef.current.srcObject = remote;
        remoteVideoRef.current.muted = selfCall;
      }
      setInCall(true);
      setRinging(false);
      stopSafe(callerToneRef);
      stopSafe(incomingToneRef);
    });

    p.on("error", (err) => {
      console.error("❌ Peer error:", err);
      setCallError(String(err));
    });
    
    p.on("close", () => {
      console.log("🔴 Peer connection closed");
      endCall();
    });

// ✅ FIXED: Send call offer with roomId AND from
console.log("📞 Sending call offer for room:", roomId);
socket.emit("call:offer", { 
  roomId, 
  type, 
  from: myId  // 👈 CRITICAL: Add this
});

// TEMPORARY: Test if socket is working
socket.emit("test_call", { roomId, type, from: myId });
console.log("🧪 Test event sent");

  } catch (e) {
    console.error("❌ Call setup failed:", e);
    stopSafe(callerToneRef);
    stopSafe(incomingToneRef);
    setCallError(String(e));
    setRinging(false);
  }
};


useEffect(() => {
  if (!socket || !roomId) return;

  const onOffer = ({ roomId: rid, type }) => {
    if (rid !== roomId) return;
    setShowCall(true);
    setCallType(type);
    setIsCaller(false);
    setIncoming(true);
    setRinging(true);
    setInCall(false);
    setCallError("");
    // receiver hears ringtone
    playSafe(incomingToneRef);
  };

  const onAnswer = ({ roomId: rid, accepted }) => {
    if (rid !== roomId) return;
    if (!accepted) {
      endCall("declined");
    } else {
      setInCall(true);
      setRinging(false);
      stopSafe(callerToneRef);
      stopSafe(incomingToneRef);
    }
  };

const onSignal = ({ roomId: rid, payload }) => {
  if (rid && rid !== roomId) return;
  const { from, data } = payload || {};
  console.log("📡 Received signal data from:", from, data);
  
  // 👈 CRITICAL: Prevent self-signaling
  if (peerRef.current && data && from !== myId) { 
    try { 
      peerRef.current.signal(data); 
    } catch (e) {
      console.error("❌ Error signaling peer:", e);
    }
  }
};

  const onEnd = ({ roomId: rid }) => {
    if (rid && rid !== roomId) return;
    endCall();
  };

  socket.on("call:offer", onOffer);
  socket.on("call:answer", onAnswer);
  socket.on("call:signal", onSignal);
  socket.on("call:end", onEnd);

  return () => {
    socket.off("call:offer", onOffer);
    socket.off("call:answer", onAnswer);
    socket.off("call:signal", onSignal);
    socket.off("call:end", onEnd);
  };
}, [socket, roomId]);

const acceptCall = async ({ initiator = false, type }) => {
  try {
    // stop receiver's ringtone
    stopSafe(incomingToneRef);
    setIncoming(false);
    setRinging(false);

    const selfCall = String(myId) === String(peerId);

    let stream;
    try {
      stream = await navigator.mediaDevices.getUserMedia({
        audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
        video: type === "video" ? { facingMode: usingFront ? "user" : "environment" } : false,
      });
    } catch (e) {
      console.warn("Video unavailable on accept, fallback to audio-only", e);
      stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
      setCameraOn(false);
      if (type === "video") setCallType("audio");
    }

    streamRef.current = stream;
    stream.getAudioTracks()?.forEach(t => (t.enabled = !muted));
    stream.getVideoTracks()?.forEach(t => (t.enabled = type === "video" && cameraOn));

    if (localVideoRef.current && type === "video") {
      localVideoRef.current.srcObject = stream;
      applyLocalFilter();
    }

    const SimplePeer = (await import("simple-peer")).default;
    const p = new SimplePeer({ initiator: !!initiator, trickle: true, stream, config: ICE_CONFIG });
    peerRef.current = p;

    // ✅ FIXED: Send signal data properly
    p.on("signal", (data) => {
      console.log("📡 Sending answer signal:", data);
      socket.emit("call:signal", { roomId, payload: { from: myId, data } });
    });
    
    p.on("stream", (remote) => {
      console.log("✅ Answer stream received!");
      if (remoteVideoRef.current) {
        remoteVideoRef.current.srcObject = remote;
        remoteVideoRef.current.muted = selfCall;
      }
      setInCall(true);
      setRinging(false);
      stopSafe(callerToneRef);
      stopSafe(incomingToneRef);
    });
    
    p.on("error", (err) => {
      console.error("❌ Peer error in answer:", err);
      setCallError(String(err));
    });
    
    p.on("close", () => {
      console.log("🔴 Answer peer connection closed");
      endCall();
    });

   // ✅ FIXED: Send call answer with roomId AND from
console.log("📞 Sending call answer for room:", roomId);
socket.emit("call:answer", { 
  roomId, 
  accepted: true, 
  from: myId  // 👈 CRITICAL: Add this
});

  } catch (e) {
    console.error("❌ Accept call failed:", e);
    setCallError(String(e));
  }
};

const endCall = (reason = "ended") => {
  stopSafe(callerToneRef);
  stopSafe(incomingToneRef);

  try {
    peerRef.current?.destroy();
    streamRef.current?.getTracks()?.forEach((t) => t.stop());
  } catch {}

  peerRef.current = null;
  streamRef.current = null;

  setShowCall(false);
  setCallType(null);
  setCallError("");
  setIncoming(false);
  setRinging(false);
  setInCall(false);

socket?.emit("call:end", { 
  roomId, 
  reason, 
  from: myId  // 👈 CRITICAL: Add this
});
};


const applyLocalFilter = () => {
  if (!localVideoRef.current) return;
  const css = VIDEO_FILTERS[filterIndex] || "none";
  localVideoRef.current.style.filter = css;
};

useEffect(() => { applyLocalFilter(); }, [filterIndex, showCall, callType]);

const toggleMute = () => {
  setMuted((m) => {
    const next = !m;
    streamRef.current?.getAudioTracks()?.forEach(t => (t.enabled = !next));
    return next;
  });
};

const toggleCamera = () => {
  if (callType !== "video") return; // no-op on voice calls
  setCameraOn((on) => {
    const next = !on;
    streamRef.current?.getVideoTracks()?.forEach(t => (t.enabled = next));
    return next;
  });
};

const flipCamera = async () => {
  if (callType !== "video") return;
  const wantFront = !usingFront;
  try {
    // get a new stream with opposite facingMode
    const newStream = await navigator.mediaDevices.getUserMedia({
      audio: true,
      video: { facingMode: wantFront ? "user" : "environment" },
    });
    // replace track on the peer connection
    const newVideoTrack = newStream.getVideoTracks()[0];
    const sender = peerRef.current?.streams?.[0]
      ? peerRef.current?._pc?.getSenders?.()?.find(s => s.track && s.track.kind === "video")
      : null;

    // Fallback: replace via SimplePeer API (works in most versions)
    if (peerRef.current && newVideoTrack) {
      try {
        peerRef.current.replaceTrack(
          streamRef.current.getVideoTracks()[0],
          newVideoTrack,
          streamRef.current
        );
      } catch {}
    }
    // Update local stream and element
    streamRef.current?.getTracks()?.forEach(t => t.stop());
    streamRef.current = newStream;
    if (localVideoRef.current) localVideoRef.current.srcObject = newStream;
    setUsingFront(wantFront);
  } catch (e) {
    console.error("flip camera failed", e);
  }
};

const cycleFilter = () => {
  setFilterIndex((i) => (i + 1) % VIDEO_FILTERS.length);
};

const declineCall = () => {
socket.emit("call:answer", { 
  roomId, 
  accepted: false, 
  from: myId  // 👈 CRITICAL: Add this
});
  endCall("declined");
};



  // ============= UI computed =============
  const themeCls = THEMES[theme] || THEMES.default;

  const canEdit = (m) =>
    mine(m) && Date.now() - new Date(m.time || m.createdAt || Date.now()).getTime() <= EDIT_MS;

  const actionBarVisible = !!actionBar;

  // --- SEARCH helpers (add once) ---
const highlight = (txt, q) => {
  if (!q) return txt;
  const escaped = q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const parts = String(txt).split(new RegExp(`(${escaped})`, "ig"));
  return parts.map((p, i) =>
    p.toLowerCase() === q.toLowerCase()
      ? <mark key={i} className="bg-yellow-200 rounded px-0.5">{p}</mark>
      : <span key={i}>{p}</span>
  );
};

const matchesQuery = (msg, q) => {
  if (!q) return true;
  const m = maybeDecode(msg);
  const s = (m.textFallback || m.text || m.url || "").toLowerCase();
  return s.includes(q.toLowerCase());
};

  // ============= render =============
  return (
    <main className={`flex flex-col h-full min-h-0 ${themeCls.wrap}`}>
      {/* Header */}
      <div className={`h-[56px] sticky top-0 z-30 flex items-center justify-between px-3 border-b shadow-sm ${themeCls.pane}`}>
        <div className="flex items-center gap-3 min-w-0">
          <button onClick={onClose} className="md:hidden text-xl">⬅️</button>
          <img
            src={peer.avatar || "https://i.pravatar.cc/80"}
            className="h-9 w-9 rounded-full object-cover border cursor-pointer hover:scale-105 transition"
            alt=""
            onClick={() => ((peer.id || peer._id) === (me.id || me._id) ? navigate("/profile") : navigate(`/view/${peer.id || peer._id}`))}
          />
          <div className="leading-tight min-w-0">
            <div className="font-semibold text-sm md:text-base truncate">
              {nickname?.trim() || [peer.firstName, peer.lastName].filter(Boolean).join(" ") || "Unknown"}
            </div>
            <div className="text-[11px] text-gray-500 flex items-center gap-1">
              <span className={peerOnline ? "text-green-500" : "text-gray-300"}>●</span>
              {typing ? "typing…" : peerOnline ? "Active now" : "Offline"}
            </div>
          </div>
        </div>

       <div className="flex items-center gap-1">
  {/* AI Wingman */}
  <button className="p-2 rounded-full hover:bg-gray-100" onClick={() => setShowWing((v) => !v)} title="AI Wingman">🤝</button>
  {/* Voice / Video */}
  <button className="p-2 rounded-full hover:bg-gray-100" onClick={() => beginCall("audio")} title="Voice Call"><FaPhone /></button>
  <button className="p-2 rounded-full hover:bg-gray-100" onClick={() => beginCall("video")} title="Video Call"><FaVideo /></button>
  {/* Midpoint meet */}
  <button className="p-2 rounded-full hover:bg-gray-100" onClick={() => setShowMap(true)} title="Safe Meet">
    <FaMapMarkerAlt className="text-red-500" />
  </button>

  {/* Header menu (nickname/theme/alerts/offline + MUTE) */}
  <div className="relative">
    <button className="p-2 hover:bg-gray-100 rounded-full" onClick={(e) => { e.stopPropagation(); setShowHeaderMenu(v=>!v); }} title="Chat settings">⋯</button>
    {showHeaderMenu && (
      <div className="absolute right-0 mt-2 w-72 bg-white border rounded-2xl shadow-lg p-3 z-50" onClick={(e)=>e.stopPropagation()}>
        {/* existing fields... */}
        {/* 🔇 Mute toggle */}
        <div className="flex items-center justify-between mt-2">
          <span className="text-gray-700">Mute this chat</span>
          <input
            type="checkbox"
            checked={!!mute}
            onChange={(e) => {
              const on = e.target.checked;
              setMute(on);
              setLS(k(roomId, "mute"), on);
            }}
          />
        </div>
        {/* Delete conversation + Done (keep your previous delete button if added) */}
        {/* ... keep the rest of your menu unchanged ... */}
      </div>
    )}
  

  {showHeaderMenu && (
    <div
      className="absolute right-0 mt-2 w-72 bg-white border rounded-2xl shadow-lg p-3 z-50"
      onClick={(e) => e.stopPropagation()}
    >
      <div className="space-y-3 text-sm">
        {/* Nickname */}
        <div>
          <label className="block text-gray-600 mb-1">Nickname</label>
          <input
            className="w-full border rounded-lg px-2 py-1 outline-none focus:ring-2 focus:ring-rose-400"
            value={nickname}
            onChange={(e) => {
              const v = e.target.value;
              setNickname(v);
              setLS(k(roomId, "nickname"), v);
            }}
            placeholder="Optional nickname for this chat"
          />
        </div>
         {/* Search in conversation */}
<div>
  <label className="block text-gray-600 mb-1">Search</label>
  <div className="flex gap-2">
    <input
      className="flex-1 border rounded-lg px-2 py-1 outline-none focus:ring-2 focus:ring-rose-400"
      value={searchQuery}
      onChange={(e) => setSearchQuery(e.target.value)}
      placeholder="Type to search…"
    />
    <button
      className="px-2 py-1 rounded-lg border hover:bg-gray-100"
      onClick={() => jumpToHit(-1)}
      disabled={!searchHits.length}
      title="Previous match"
    >‹</button>
    <button
      className="px-2 py-1 rounded-lg border hover:bg-gray-100"
      onClick={() => jumpToHit(1)}
      disabled={!searchHits.length}
      title="Next match"
    >›</button>
  </div>
  {searchQuery && (
    <div className="text-xs text-gray-500 mt-1">
      {searchHits.length ? `${searchIndex + 1}/${searchHits.length} matches` : "No matches"}
    </div>
  )}
</div>
 {/* Tools */}
<div className="grid grid-cols-2 gap-2">
  <button
    className={`px-3 py-2 rounded-lg border ${selectMode ? "bg-rose-500 text-white border-rose-500" : "hover:bg-gray-100"}`}
    onClick={() => setSelectMode(v => !v)}
  >
    {selectMode ? "Done selecting" : "Select messages"}
  </button>
  <button
    className="px-3 py-2 rounded-lg border hover:bg-gray-100"
    onClick={() => setShowGallery(true)}
  >
    Open Gallery
  </button>
  <button
    className="px-3 py-2 rounded-lg border hover:bg-gray-100"
    onClick={() => {
      if (pinnedIds.length === 0) return alert("No pinned messages yet.");
      const first = document.getElementById(`msg-${pinnedIds[0]}`);
      first?.scrollIntoView({ behavior: "smooth", block: "center" });
    }}
  >
    Jump to pins
  </button>
  <button
    className="px-3 py-2 rounded-lg border hover:bg-gray-100"
    onClick={() => setPinnedIds([])}
    disabled={!pinnedIds.length}
    title="Clear all pinned"
  >
    Clear all pins
  </button>
</div>



{/* 📌 Pinned */}
{pinnedIds.length > 0 && (
  <div className="sticky top-0 z-10 py-1 -mt-1">
    <div className="bg-white/80 backdrop-blur border rounded-xl p-2 flex flex-wrap gap-2">
      {pinnedIds.map(pid => {
        const pm = messages.map(maybeDecode).find(m => m.id === pid);
        if (!pm) return null;
        const preview = pm.url || pm.textFallback || (pm.text?.startsWith(RBZ_TAG) ? "" : pm.text) || "[media]";
        return (
          <button
            key={pid}
            className="text-xs px-2 py-1 rounded-full bg-rose-50 border hover:bg-rose-100 truncate max-w-[200px]"
            title="Jump to pinned"
            onClick={() => {
              const el = document.getElementById(`msg-${pid}`);
              el?.scrollIntoView({ behavior: "smooth", block: "center" });
            }}
          >
            📌 {String(preview).slice(0, 40)}
          </button>
        );
      })}
      <button
        className="ml-auto text-xs text-gray-500 hover:underline"
        onClick={() => { setPinnedIds([]); setLS(k(roomId, "pinnedIds"), []); }}
      >
        Clear pins
      </button>
    </div>
  </div>
)}

        {/* Theme */}
        <div>
          <label className="block text-gray-600 mb-1">Theme</label>
        <select
  className="w-full border rounded-lg px-2 py-1 outline-none focus:ring-2 focus:ring-rose-400"
  value={theme}
  onChange={(e) => {
    const v = e.target.value;
    setTheme(v);
    setLS(k(roomId, "theme"), v);
  }}
>
  {Object.keys(THEMES).map(key => (
    <option key={key} value={key}>{key}</option>
  ))}
</select>

        </div>

        {/* Toggles */}
        <div className="flex items-center justify-between">
          <span className="text-gray-700">Alert when online</span>
          <input
            type="checkbox"
            checked={!!onlineAlert}
            onChange={(e) => {
              const on = e.target.checked;
              setOnlineAlert(on);
              setLS(k(roomId, "alertOnline"), on);
            }}
          />
        </div>
        <div className="flex items-center justify-between">
          <span className="text-gray-700">Show me offline</span>
          <input
            type="checkbox"
            checked={!!manualOffline}
            onChange={(e) => {
              const on = e.target.checked;
              setManualOffline(on);
              setLS(k(roomId, "manualOffline"), on);
            }}
          />
        </div>

        <div className="flex items-center justify-between">
  <button
    className="px-3 py-1 rounded-lg bg-red-50 text-red-700 border border-red-200 hover:bg-red-100"
    onClick={async () => {
      if (!window.confirm("Delete this conversation for you? This can't be undone.")) return;
      try {
     const r = await fetch(`${API_BASE}/api/chat/rooms/${roomId}`, {
  method: "DELETE",
  headers: { Authorization: `Bearer ${token}` },
});

if (!r.ok) {
  let msg = "Failed to delete conversation.";
  try {
    const j = await r.json();
    if (j?.error) msg = j.error;
  } catch {}
  return alert(msg);
}
// clear local state and close
setMessages([]);
setShowHeaderMenu(false);
onClose?.();

      } catch (e) {
        console.error(e);
        alert("Delete failed.");
      }
    }}
  >
    Delete conversation
  </button>

  <button
    className="px-3 py-1 rounded-lg bg-rose-500 text-white hover:bg-rose-600"
    onClick={() => setShowHeaderMenu(false)}
  >
    Done
  </button>
</div>

      </div>
    </div>
  )}
</div>

        </div>
      </div>

      {/* Messages */}
      <div className={`flex-1 min-h-0 overflow-y-auto px-3 md:px-4 py-2 space-y-1.5 ${themeCls.messages}`}>
 {messages
  .filter((m) => !hiddenIds[m.id])
  .map((raw) => {
    const m = maybeDecode(raw);
    // ...


            const isMine = mine(m);

            // mark seen for peer's messages as they render
// mark seen for peer's messages once
if (!isMine && !m.deleted && !seenMap[m.id]) {
  markSeen(m.id);
  setSeenMap(prev => ({ ...prev, [m.id]: true }));
}
{selectMode && (
  <input
    type="checkbox"
    className="mt-2 mx-2"
    checked={!!selectedIds[m.id]}
    onChange={(e) => {
      const on = e.target.checked;
      setSelectedIds(prev => {
        const next = { ...prev };
        if (on) next[m.id] = true; else delete next[m.id];
        return next;
      });
    }}
  />
)}


            const bubbleBase = "max-w-[80%] md:max-w-[70%] px-3 py-2 rounded-2xl animate-chatfade break-words whitespace-pre-wrap [overflow-wrap:anywhere] inline-block";
            const skin = isMine ? "bg-rose-500 text-white ml-auto" : "bg-white border border-gray-200 text-gray-800";

            const canMsgEdit = canEdit(m);

            const showReplyHeader = !!m.replyTo;

            const reactions = m.reactions || {};
            const reactionCounts = Object.values(reactions).reduce((acc, e) => {
              acc[e] = (acc[e] || 0) + 1;
              return acc;
            }, {});

            return (
                    <div
                id={`msg-${m.id}`}
                key={m.id}
                className={`flex ${isMine ? "justify-end" : "justify-start"} ${selectMode && selectedIds[m.id] ? "ring-2 ring-rose-400 rounded-lg" : ""}`}
                onClick={() => {
                  if (selectMode) {
                    setSelectedIds(prev => ({ ...prev, [m.id]: !prev[m.id] }));
                  }
                }}
                
                onContextMenu={(e) => { e.preventDefault(); setActionBar(m); }}
                onMouseDown={() => startLongPress(m)}
                onMouseUp={cancelLongPress}
                onMouseLeave={cancelLongPress}
                onTouchStart={onTouchStart}
                onTouchMove={(e) => onTouchMove(e, m)}
                onTouchEnd={() => onTouchEnd(m)}
              >
                <div className={`items-end gap-2 ${isMine ? "flex-row-reverse justify-end" : "justify-start"} flex w-full`}>
                  {!isMine && (
                    <img src={peer.avatar || "https://i.pravatar.cc/40"} alt="" className="h-7 w-7 rounded-full" />
                  )}

                  <div className={`${bubbleBase} ${skin}`}>
                    {/* Reply header */}
                    {showReplyHeader && (
                      <div className={`text-[11px] mb-1 px-2 py-1 rounded-lg ${isMine ? "bg-white/20" : "bg-gray-100"}`}>
                        Replying to: <span className="italic">{String(m.replyTo.preview || "").slice(0, 80)}</span>
                      </div>
                    )}
{selectMode && (
  <div className="mb-1 -mt-1 -mr-1 flex justify-end">
    <input
      type="checkbox"
      className="h-4 w-4"
      checked={!!selectedIds[m.id]}
      onChange={(e) => {
        const on = e.target.checked;
        setSelectedIds(prev => {
          const next = { ...prev };
          if (on) next[m.id] = true; else delete next[m.id];
          return next;
        });
      }}
      onClick={(e) => e.stopPropagation()}
    />
  </div>
)}

                    {/* body (text/image/video) */}
                   {/* body (text/image/video) */}
{m.type === "image" && m.url ? (
  <img
    src={m.url}
    alt=""
    className="rounded-lg max-h-72 object-contain cursor-pointer"
    onClick={() => window.open(m.url, "_blank")}
  />
) : m.type === "video" && m.url ? (
  <video controls src={m.url} className="rounded-lg max-h-72" />
) : (
  <div className="break-words whitespace-pre-wrap [overflow-wrap:anywhere] inline-block max-w-full">
    {(() => {
      const hasText = typeof m.text === "string" && m.text.length > 0;
      const isRBZ   = hasText && m.text.startsWith(RBZ_TAG);
      const t = isRBZ ? (m.textFallback || "") : (hasText ? m.text : (m.textFallback || ""));
      return t ? highlight(t, searchQuery) : "[empty]";
    })()}
  </div>


)}


                    {/* footer */}
                    <div className="text-[10px] opacity-70 mt-0.5 flex items-center gap-1">
                      {new Date(m.time || m.createdAt || Date.now()).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                      {m.edited && <span>(edited)</span>}
                      {m._temp && <span>• sending…</span>}
                      {isMine && !m._temp && (
                        <>
                          <span>•</span>
                          <span title={seenMap[m.id] ? "Seen" : "Sent"}>{seenMap[m.id] ? "✓✓" : "•"}</span>
                        </>
                      )}
                    </div>

                    {/* reactions row */}
                    {!!Object.keys(reactionCounts).length && (
                      <div className={`mt-1 text-[12px] ${isMine ? "opacity-90" : "text-gray-600"}`}>
                        {Object.entries(reactionCounts).map(([e, c]) => (
                          <span key={e} className="mr-2">{e} {c}</span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        <div ref={chatEndRef} />
      </div>

      {/* Reply preview bar */}
      {replyTo && (
        <div className="px-3 py-2 border-t bg-white flex items-center gap-2 text-sm">
          <div className="text-gray-500">Replying to:</div>
          <div className="flex-1 truncate italic">{String(replyTo.preview || "").slice(0, 100)}</div>
          <button className="text-gray-500 hover:text-black" onClick={() => setReplyTo(null)} title="Cancel">
            <FaTimes />
          </button>
        </div>
      )}

      {/* Blocked / manual offline banners */}
      {(blockedBanner.iBlocked || blockedBanner.blockedMe) && (
        <div className="px-3 py-2 bg-yellow-50 text-yellow-800 text-sm border-y">
          {blockedBanner.iBlocked && !blockedBanner.blockedMe && <div>You’ve blocked this person. Unblock to continue chatting.</div>}
          {blockedBanner.blockedMe && <div>You cannot chat with this user.</div>}
        </div>
      )}
      {manualOffline && !(blockedBanner.iBlocked || blockedBanner.blockedMe) && (
        <div className="px-3 py-2 bg-gray-50 text-gray-700 text-sm border-y">You are marked offline. Others may see you as inactive.</div>
      )}

      {/* Composer */}
      <div
        className={`h-[60px] border-t bg-white px-2 md:px-3 flex items-center gap-2 ${blockedBanner.iBlocked || blockedBanner.blockedMe ? "opacity-60 pointer-events-none" : ""
          }`}
      >
        {/* Emoji */}
        <button className="p-2 rounded-lg hover:bg-gray-100 relative" onClick={() => setShowEmoji((v) => !v)} title="Emoji">
          <FaSmile />
          {showEmoji && (
            <div className="absolute bottom-16 right-0 z-50 bg-white rounded-xl shadow-lg animate-fadein">
              <EmojiPicker onEmojiClick={(e) => setInput((p) => p + (e.emoji || ""))} theme="light" />
            </div>
          )}
        </button>

        {/* Attach */}
        <label className="p-2 rounded-lg hover:bg-gray-100 cursor-pointer" title="Attach">
          <FaPaperclip />
          <input type="file" accept="image/*,video/*" onChange={onPickFile} className="hidden" />
        </label>

        {/* Input */}
        <input
          className="flex-1 p-3 rounded-xl border outline-none focus:ring-2 focus:ring-rose-400 text-sm"
          placeholder="Type a message…"
          value={input}
          onChange={(e) => onTyping(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && onSend()}
        />

        {/* Send */}
        <button onClick={onSend} className="p-3 rounded-xl bg-rose-500 text-white hover:bg-rose-600" title="Send">
          <FaPaperPlane />
        </button>
      </div>
{/* Bulk actions bar */}
{selectMode && (
  <div className="h-[52px] border-t bg-white px-3 flex items-center gap-2">
    <div className="text-sm text-gray-600 flex-1">
      {Object.keys(selectedIds).length} selected
    </div>
    <button
      className="px-3 py-1 rounded-lg bg-red-500 text-white hover:bg-red-600"
      onClick={async () => {
        if (!Object.keys(selectedIds).length) return;
        if (!window.confirm("Delete selected messages for you?")) return;
        try {
          await Promise.all(
            Object.keys(selectedIds).map(async (id) => {
              const r = await fetch(`${API_BASE}/api/chat/rooms/${roomId}/${id}?scope=me`, {
                method: "DELETE",
                headers: { Authorization: `Bearer ${token}` },
              });
              await r.json();
            })
          );
          // remove from UI without refetch
          setHiddenIds((h) => ({ ...h, ...selectedIds }));
          setSelectedIds({});
          setSelectMode(false);
        } catch (e) {
          console.error(e);
          alert("Bulk delete failed.");
        }
      }}
    >
      Delete selected
    </button>
    <button
      className="px-3 py-1 rounded-lg border hover:bg-gray-100"
      onClick={() => { setSelectedIds({}); setSelectMode(false); }}
    >
      Cancel
    </button>
  </div>
)}

      {/* Long-press bottom action bar (like Messenger) */}
     {actionBarVisible && (
  <div className="fixed left-0 right-0 bottom-[60px] z-40">
    <div className="mx-auto w-full max-w-md bg-white/95 backdrop-blur border rounded-2xl shadow-lg p-2 flex items-center justify-around">
      {/* Reactions via emoji picker quick open */}
      {/* Quick reactions row */}
<div className="flex items-center gap-1">
  {["❤️","😂","👍","😮","😍","😢"].map(e => (
    <button
      key={e}
      className="px-2 py-1 rounded hover:bg-gray-100 text-lg"
      onClick={() => { openEmojiReact(actionBar, e); setActionBar(null); }}
      title={`React ${e}`}
    >{e}</button>
  ))}
  <button
    className="px-2 py-1 rounded hover:bg-gray-100 text-sm"
    onClick={() => setReactFor(actionBar)}   // 👈 opens the EmojiPicker overlay you already added
    title="More…"
  >
    More…
  </button>
</div>

<button
  className="px-3 py-1 rounded hover:bg-gray-100"
  onClick={() => {
    const dec = maybeDecode(actionBar);
    setReplyTo({ id: actionBar.id, type: dec.type || "text", preview: dec.url || dec.text || "" });
    setActionBar(null);
  }}
>
  Reply
</button>

<button
  className="px-3 py-1 rounded hover:bg-gray-100"
  onClick={() => {
    const id = actionBar.id;
    setPinnedIds(prev => {
      const next = prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id];
      setLS(k(roomId, "pinnedIds"), next);
      return next;
    });
    setActionBar(null);
  }}
>
  {pinnedIds.includes(actionBar?.id) ? "Unpin" : "Pin"}
</button>


      {mine(actionBar) && (
        <button
          className="px-3 py-1 rounded hover:bg-gray-100"
          onClick={() => {
            if (!canEdit(actionBar)) return alert("Edit window expired (1h).");
            editMessage(actionBar);
            setActionBar(null);
          }}
        >
          Edit
        </button>
      )}

      {mine(actionBar) ? (
        <button className="px-3 py-1 rounded hover:bg-gray-100" onClick={() => { unsendForAll(actionBar); setActionBar(null); }}>
          Unsend for everyone
        </button>
      ) : (
        <button className="px-3 py-1 rounded hover:bg-gray-100" onClick={() => { unsendForMe(actionBar); setActionBar(null); }}>
          Delete for me
        </button>
      )}

      {mine(actionBar) && (
        <button className="px-3 py-1 rounded hover:bg-gray-100" onClick={() => { unsendForMe(actionBar); setActionBar(null); }}>
          Unsend for me
        </button>
      )}

      <button className="px-3 py-1 rounded hover:bg-gray-100" onClick={() => { copyMessage(actionBar); setActionBar(null); }}>
        Copy
      </button>

      <button className="px-3 py-1 rounded hover:bg-gray-100 text-gray-500" onClick={() => setActionBar(null)}>
        Close
      </button>
    </div>
  </div>
)}


{/* Call modal */}
{showCall && (
  <div className="fixed inset-0 bg-black/90 text-white z-50">

    {/* ── Top center: avatar + name + status ───────────────────────── */}
    <div className="absolute top-3 left-1/2 -translate-x-1/2 flex items-center gap-3">
      <img
        src={peer.avatar || "https://i.pravatar.cc/120"}
        className="h-10 w-10 rounded-full border-2 border-white/60"
        alt=""
      />
      <div className="text-center">
        <div className="font-semibold text-lg">
          {[peer.firstName, peer.lastName].filter(Boolean).join(" ") || "Unknown"}
        </div>
        <div className="text-xs opacity-80">
          {incoming
            ? "Incoming call…"
            : !inCall
              ? "Ringing…"
              : (callType === "video" ? "Video connected" : "Voice connected")}
        </div>
      </div>
    </div>

    {/* ── Video layers / background ─────────────────────────────────── */}
    <div className="absolute inset-0">
      {/* remote fills when connected */}
      {inCall && callType === "video" && (
        <video ref={remoteVideoRef} autoPlay playsInline className="absolute inset-0 w-full h-full object-cover" />
      )}

      {/* local: full while waiting; PiP after connected */}
      {callType === "video" ? (
        <video
          ref={localVideoRef}
          autoPlay
          muted
          playsInline
          className={
            inCall
              ? "absolute right-3 bottom-28 w-40 h-28 rounded-xl border-2 border-white/40 object-cover shadow-lg"
              : "absolute inset-0 w-full h-full object-cover"
          }
        />
      ) : (
        !inCall && (
          <div className="absolute inset-0 grid place-items-center">
            <img
              src={peer.avatar || "https://i.pravatar.cc/200"}
              className="h-40 w-40 rounded-full object-cover border-4 border-white/70 shadow-lg"
              alt=""
            />
          </div>
        )
      )}
    </div>

    {/* ── Receiver incoming UI (no controls yet) ────────────────────── */}
    {incoming && (
      <div className="absolute inset-x-0 bottom-24 flex items-center justify-center gap-8">
        <button
          onClick={() => acceptCall({ initiator: false, type: callType })}
          className="h-16 w-16 rounded-full bg-green-500 hover:bg-green-600 grid place-items-center text-white text-2xl shadow-lg"
          title="Accept"
        >✔</button>
        <button
          onClick={() => { socket.emit("call:answer", { roomId, accepted: false }); endCall("declined"); }}
          className="h-16 w-16 rounded-full bg-red-600 hover:bg-red-700 grid place-items-center text-white text-2xl shadow-lg"
          title="Decline"
        >✖</button>
      </div>
    )}

   {/* Floating control bar (hidden for receiver while ringing) */}
{(!ringing) && (
  <div className="absolute left-0 right-0 bottom-6 z-50 flex items-center justify-center gap-4">
    {/* mute */}
    <button
      onClick={toggleMute}
      title={muted ? "Unmute" : "Mute"}
      className={`h-14 w-14 rounded-full bg-white/15 hover:bg-white/25 backdrop-blur border border-white/20 flex items-center justify-center ${muted ? "ring-2 ring-yellow-300" : ""}`}
    >
      <span className="text-2xl">{muted ? "🔈" : "🔇"}</span>
    </button>

    {/* camera (video only) */}
    <button
      onClick={toggleCamera}
      disabled={callType !== "video"}
      title={callType === "video" ? (cameraOn ? "Turn camera off" : "Turn camera on") : "Camera not available"}
      className={`h-14 w-14 rounded-full ${callType === "video" ? "bg-white/15 hover:bg-white/25" : "bg-white/10 opacity-50"} backdrop-blur border border-white/20 flex items-center justify-center ${cameraOn ? "" : "ring-2 ring-yellow-300"}`}
    >
      <span className="text-2xl">{cameraOn ? "📷" : "🚫"}</span>
    </button>

    {/* filter (video only) */}
    <button
      onClick={cycleFilter}
      disabled={callType !== "video"}
      title="Filters"
      className={`h-14 w-14 rounded-full ${callType === "video" ? "bg-white/15 hover:bg-white/25" : "bg-white/10 opacity-50"} backdrop-blur border border-white/20 flex items-center justify-center`}
    >
      <span className="text-2xl">✨</span>
    </button>

    {/* flip (video only) */}
    <button
      onClick={flipCamera}
      disabled={callType !== "video"}
      title="Flip camera"
      className={`h-14 w-14 rounded-full ${callType === "video" ? "bg-white/15 hover:bg-white/25" : "bg-white/10 opacity-50"} backdrop-blur border border-white/20 flex items-center justify-center`}
    >
      <span className="text-2xl">🔄</span>
    </button>

    {/* hang up */}
    <button
      onClick={() => endCall("hangup")}
      title="Hang up"
      className="h-14 w-14 rounded-full bg-red-600 hover:bg-red-700 text-white shadow-lg flex items-center justify-center"
    >
      <span className="text-2xl">✖</span>
    </button>
  </div>
)}

    {/* ── Caller waiting (only Cancel) ──────────────────────────────── */}
    {!incoming && !inCall && (
      <div className="absolute inset-x-0 bottom-6 flex items-center justify-center">
        <button
          onClick={() => endCall("cancelled")}
          className="h-12 w-12 rounded-full bg-red-600 text-white grid place-items-center shadow-lg"
          title="Cancel"
        >
          <FaPhoneSlash />
        </button>
      </div>
    )}
  </div>
)}

      {showGallery && (
  <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4" onClick={() => setShowGallery(false)}>
    <div className="bg-white rounded-2xl w-full max-w-5xl p-4" onClick={(e)=>e.stopPropagation()}>
      <div className="flex items-center justify-between border-b pb-2">
        <div className="font-semibold">Media Gallery</div>
        <button className="p-2 hover:bg-gray-100 rounded" onClick={() => setShowGallery(false)}><FaTimes /></button>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3 mt-3 max-h-[70vh] overflow-auto">
        {messages.map(maybeDecode).filter(m => (m.type === "image" || m.type === "video") && m.url).map(m => (
          <div key={m.id} className="border rounded-xl overflow-hidden bg-black">
            {m.type === "image" ? (
              <img src={m.url} alt="" className="w-full h-40 object-cover cursor-pointer" onClick={()=>window.open(m.url, "_blank")} />
            ) : (
              <video src={m.url} controls className="w-full h-40 object-cover" />
            )}
          </div>
        ))}
      </div>
    </div>
  </div>
)}


      {/* Wingman panel */}
      {showWing && (
        <AiWingmanChat
          open={showWing}
          onClose={() => setShowWing(false)}
          token={token}
          apiBase={API_BASE}
          roomId={roomId}
          myId={myId}
          peerId={peerId}
          messages={messages}
          onUseTip={(t) => setInput((p) => (p ? `${p} ${t}` : t))}
        />
      )}
   {/* Meet in the Middle popup */}
      {showMap && (
        <MeetMap
          me={me}
          peer={peer}
          onClose={() => setShowMap(false)}
        />
      )}
      {/* tiny CSS */}
      <style>{`
      .pinned-shadow { box-shadow: 0 1px 6px rgba(244,63,94,.25); }

        .animate-chatfade { animation: chatfade 0.25s ease-in; }
        @keyframes chatfade { from {opacity: 0; transform: translateY(8px);} to {opacity: 1; transform: translateY(0);} }
      `}</style>
    
{/* 👇 Reaction emoji picker overlay */}
{reactFor && (
  <div className="fixed inset-0 z-50" onClick={() => setReactFor(null)}>
    <div
      className="absolute left-1/2 -translate-x-1/2 bottom-[120px] bg-white rounded-xl shadow-lg p-1"
      onClick={(e) => e.stopPropagation()}
    >
      <EmojiPicker
        onEmojiClick={(e) => {
          if (e?.emoji) openEmojiReact(reactFor, e.emoji);
          setReactFor(null);
          setActionBar(null);
        }}
        theme="light"
      />
    </div>
  </div>
)}
{/* ring tones */}
<audio ref={callerToneRef}   src="/sounds/caller-soft-ring.mp3"   loop preload="auto" />
<audio ref={incomingToneRef} src="/sounds/incoming-chime.mp3"     loop preload="auto" />


    </main>
  );
}
