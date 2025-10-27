// src/pages/ChatWindow.jsx
import React, { useEffect, useMemo, useRef, useState } from "react";
import { FaBan } from "react-icons/fa";
import MeetMap from "../components/MeetMap"; // ✅ Unified meet-in-middle system
import { getSocket } from "../socket.js";

import {
  FaSmile,
  FaPaperclip,
  FaPaperPlane,
  FaPhone,
  FaVideo,
  FaTimes,
  FaCamera,
  FaStop,
  FaCircle
} from "react-icons/fa";
import EmojiPicker from "emoji-picker-react";

const API_BASE = "http://localhost:4000";

// ⚠️ Cloudinary setup
const CLOUD_NAME = import.meta.env.VITE_CLOUDINARY_CLOUD_NAME || "drcxu0mks";
const UPLOAD_PRESET = import.meta.env.VITE_CLOUDINARY_UPLOAD_PRESET || "rombuzz_unsigned";

// Special prefix for serialized media
const RBZ_TAG = "::RBZ::";

function encodeMedia(type, url, extra = {}) {
  return `${RBZ_TAG}${JSON.stringify({ type, url, ...extra })}`;
}
function maybeDecodeMessage(m) {
  if (m.type) return m;
  if (typeof m.text === "string" && m.text.startsWith(RBZ_TAG)) {
    try {
      const payload = JSON.parse(m.text.slice(RBZ_TAG.length));
      return { ...m, ...payload };
    } catch {
      return m;
    }
  }
  return m;
}

export default function ChatWindow({ me, peer, onClose }) {
  const socket = getSocket();
  const [messages, setMessages] = useState([]);
  const [blocked, setBlocked] = useState(false);

  const [input, setInput] = useState("");
  const [showEmoji, setShowEmoji] = useState(false);
  const [showMenu, setShowMenu] = useState(false);
  const [vanishMode, setVanishMode] = useState("off");

  const [showCall, setShowCall] = useState(false);
  const [callType, setCallType] = useState(null);

  // Camera
  const [showCamera, setShowCamera] = useState(false);
  const [recordVideo, setRecordVideo] = useState(false);
  const videoRef = useRef(null);
  const canvasRef = useRef(null);
  const streamRef = useRef(null);
  const mediaRecorderRef = useRef(null);
  const chunksRef = useRef([]);

  const chatEndRef = useRef(null);

  const myId = me.id || me._id;
  const peerId = peer.id || peer._id;
  const roomId = useMemo(() => {
    const a = String(myId);
    const b = String(peerId);
    return a < b ? `${a}_${b}` : `${b}_${a}`;
  }, [myId, peerId]);

  // Check if blocked
  const checkBlockStatus = async () => {
    const token = localStorage.getItem("token") || sessionStorage.getItem("token") || "";
    if (!token || !peer?.id) return;
    try {
      const r = await fetch(`${API_BASE}/api/blocks`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const j = await r.json();
      const myBlocks = j.blocks || [];
      const isBlocked = myBlocks.some((b) => b.id === (peer.id || peer._id));
      setBlocked(isBlocked);
    } catch (err) {
      console.error("block check error:", err);
    }
  };

  // Load chat history
  useEffect(() => {
    checkBlockStatus();
    if (!roomId) return;
    const token = localStorage.getItem("token") || sessionStorage.getItem("token");
    fetch(`${API_BASE}/api/chat/rooms/${roomId}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((r) => r.json())
      .then((list) => {
        const arr = Array.isArray(list) ? list : [];
        setMessages(arr.map(maybeDecodeMessage));
      })
      .catch(() => setMessages([]));
  }, [roomId]);

  // Live socket listeners
  useEffect(() => {
    if (!socket || !roomId) return;
    socket.emit("joinRoom", roomId);

    const onMsg = (raw) => {
      const msg = maybeDecodeMessage(raw);
      setMessages((prev) => (prev.some((m) => m.id === msg.id) ? prev : [...prev, msg]));
    };

    const onTyping = ({ fromId }) => {
      if (fromId === (peer.id || peer._id)) {
        setTyping(true);
        clearTimeout(onTyping._t);
        onTyping._t = setTimeout(() => setTyping(false), 1800);
      }
    };

    const onSeen = (msgId) => {
      setMessages((prev) =>
        prev.map((m) => (m.id === msgId ? { ...m, seen: true } : m))
      );
    };

    socket.on("message", onMsg);
    socket.on("typing", onTyping);
    socket.on("message:seen", onSeen);

    return () => {
      socket.off("message", onMsg);
      socket.off("typing", onTyping);
      socket.off("message:seen", onSeen);
      socket.emit("leaveRoom", roomId);
    };
  }, [socket, roomId, peer]);

  const [typing, setTyping] = useState(false);

  // Auto-scroll
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const mine = (m) => (m.from || m.fromId) === (me.id || me._id);

  const sendLive = (payload) => {
    if (!socket) return;
    socket.emit("sendMessage", { roomId, ...payload });
  };

  const persistText = async (text) => {
    const token = localStorage.getItem("token") || sessionStorage.getItem("token");
    await fetch(`${API_BASE}/api/chat/rooms/${roomId}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ text }),
    });
  };

  const sendText = async () => {
    const text = input.trim();
    if (!text) return;
    const msg = {
      id: crypto.randomUUID(),
      from: me.id || me._id,
      to: peer.id || peer._id,
      text,
      time: new Date().toISOString(),
    };
    setMessages((m) => [...m, msg]);
    setInput("");
    sendLive(msg);
    persistText(text);
  };

  const insertEmoji = (e) => setInput((p) => p + (e.emoji || ""));

  // Cloudinary upload
  async function uploadToCloudinary(fileOrBlob) {
    const form = new FormData();
    form.append("file", fileOrBlob);
    form.append("upload_preset", UPLOAD_PRESET);
    const res = await fetch(`https://api.cloudinary.com/v1_1/${CLOUD_NAME}/auto/upload`, {
      method: "POST",
      body: form,
    });
    const data = await res.json();
    if (!data.secure_url) throw new Error("Cloudinary upload failed");
    return data.secure_url;
  }

  const onPickFile = async (e) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    const url = await uploadToCloudinary(file);
    const type = file.type.startsWith("video") ? "video" : "image";
    const live = {
      id: crypto.randomUUID(),
      from: me.id || me._id,
      to: peer.id || peer._id,
      type,
      url,
      time: new Date().toISOString(),
      text: encodeMedia(type, url),
    };
    setMessages((m) => [...m, live]);
    sendLive(live);
    await persistText(live.text);
  };

  // Camera controls
  const openCamera = async (wantVideo = false) => {
    setShowCamera(true);
    setRecordVideo(false);
    const stream = await navigator.mediaDevices.getUserMedia({
      video: true,
      audio: wantVideo,
    });
    streamRef.current = stream;
    if (videoRef.current) videoRef.current.srcObject = stream;
  };

  const closeCamera = () => {
    setShowCamera(false);
    stopRecording();
    if (streamRef.current) {
      streamRef.current.getTracks().forEach((t) => t.stop());
      streamRef.current = null;
    }
  };

  const capturePhoto = async () => {
    if (!videoRef.current) return;
    const video = videoRef.current;
    const canvas = canvasRef.current;
    const w = video.videoWidth || 640;
    const h = video.videoHeight || 480;
    canvas.width = w;
    canvas.height = h;
    const ctx = canvas.getContext("2d");
    ctx.drawImage(video, 0, 0, w, h);
    const blob = await new Promise((r) => canvas.toBlob(r, "image/jpeg", 0.9));
    const url = await uploadToCloudinary(blob);
    const msg = {
      id: crypto.randomUUID(),
      from: me.id || me._id,
      to: peer.id || peer._id,
      type: "image",
      url,
      time: new Date().toISOString(),
      text: encodeMedia("image", url),
    };
    setMessages((m) => [...m, msg]);
    sendLive(msg);
    await persistText(msg.text);
    closeCamera();
  };

  const startRecording = () => {
    if (!streamRef.current) return;
    setRecordVideo(true);
    chunksRef.current = [];
    const mr = new MediaRecorder(streamRef.current, { mimeType: "video/webm" });
    mediaRecorderRef.current = mr;
    mr.ondataavailable = (e) => {
      if (e.data?.size) chunksRef.current.push(e.data);
    };
    mr.start();
  };

  const stopRecording = async () => {
    if (!mediaRecorderRef.current) return;
    const mr = mediaRecorderRef.current;
    setRecordVideo(false);
    await new Promise((res) => {
      mr.onstop = res;
      mr.stop();
    });
    const blob = new Blob(chunksRef.current, { type: "video/webm" });
    chunksRef.current = [];
    if (blob.size === 0) return;
    const url = await uploadToCloudinary(blob);
    const msg = {
      id: crypto.randomUUID(),
      from: me.id || me._id,
      to: peer.id || peer._id,
      type: "video",
      url,
      time: new Date().toISOString(),
      text: encodeMedia("video", url),
    };
    setMessages((m) => [...m, msg]);
    sendLive(msg);
    await persistText(msg.text);
    closeCamera();
  };

  const onInput = (val) => {
    setInput(val);
    socket?.emit("typing", {
      roomId,
      fromId: me.id || me._id,
      toId: peer.id || peer._id,
    });
  };

  return (
    <main className="flex flex-col flex-1 h-[calc(100vh-64px)] overflow-hidden bg-white">
      {/* Header */}
      <div className="h-16 border-b bg-white/90 px-4 flex items-center justify-between shadow-sm">
        <div className="flex items-center gap-3">
          <button onClick={onClose} className="md:hidden text-xl">⬅️</button>
          <img
            src={peer.avatar || "https://i.pravatar.cc/80"}
            className="h-10 w-10 rounded-full object-cover border"
            alt=""
          />
          <div>
            <div className="font-semibold text-gray-800">
              {[peer.firstName, peer.lastName].filter(Boolean).join(" ") || "Unknown"}
            </div>
            <div className="text-xs text-gray-500 flex items-center gap-1">
              <span className="text-green-500">●</span>
              {typing ? "typing…" : "Active now"}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            className="p-2 rounded-full hover:bg-gray-100"
            onClick={() => { setCallType("audio"); setShowCall(true); }}
            title="Voice Call"
          >
            <FaPhone className="text-gray-700" />
          </button>
          <button
            className="p-2 rounded-full hover:bg-gray-100"
            onClick={() => { setCallType("video"); setShowCall(true); }}
            title="Video Call"
          >
            <FaVideo className="text-gray-700" />
          </button>

          {/* ✅ Unified Meet button & flow */}
          <MeetMap me={me} peer={peer} />

          <div className="relative">
            <button
              className="p-2 hover:bg-gray-100 rounded-full"
              onClick={() => setShowMenu((v) => !v)}
              title="More"
            >
              ⋯
            </button>
            {showMenu && (
              <div className="absolute right-0 top-10 bg-white shadow-lg rounded-lg w-44 border text-sm z-20">
                {["View Profile", "Block", "Report", "Delete Chat"].map((opt) => (
                  <button
                    key={opt}
                    className="w-full text-left px-4 py-2 hover:bg-gray-50"
                  >
                    {opt}
                  </button>
                ))}
                <hr />
                <div className="px-4 py-2 text-xs text-gray-500">
                  Disappear:
                  <select
                    className="ml-2 border rounded text-xs"
                    value={vanishMode}
                    onChange={(e) => setVanishMode(e.target.value)}
                  >
                    <option value="off">Off</option>
                    <option value="seen">After Seen</option>
                    <option value="24h">After 24h</option>
                    <option value="7d">After 7 days</option>
                  </select>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto px-4 py-3 space-y-2" style={{ scrollBehavior: "smooth" }}>
        {messages.map((raw) => {
          const m = maybeDecodeMessage(raw);
          const isMine = mine(m);
          const base = "max-w-[70%] p-3 rounded-2xl";
          const skin = isMine
            ? "bg-rose-500 text-red-50 ml-auto"
            : "bg-white border border-gray-200 text-gray-800";
          return (
            <div key={m.id} className={`flex ${isMine ? "justify-end" : "justify-start"}`}>
              <div className={`flex items-end gap-2 ${isMine ? "flex-row-reverse" : ""}`}>
                {!isMine && (
                  <img
                    src={peer.avatar || "https://i.pravatar.cc/40"}
                    alt=""
                    className="h-7 w-7 rounded-full"
                  />
                )}
                <div className={`${base} ${skin}`}>
                  {m.type === "image" && (
                    <img src={m.url} alt="" className="rounded-lg max-h-72 object-contain" />
                  )}
                  {m.type === "video" && (
                    <video controls src={m.url} className="rounded-lg max-h-72" />
                  )}
                  {!m.type && <div>{m.text}</div>}
                  <div className="text-[10px] opacity-70 mt-1">
                    {new Date(m.time || m.createdAt || Date.now()).toLocaleTimeString([], {
                      hour: "2-digit",
                      minute: "2-digit",
                    })}
                    {isMine && (m.seen ? " • 👀" : " • ✓")}
                  </div>
                </div>
              </div>
            </div>
          );
        })}
        <div ref={chatEndRef} />
      </div>

      {/* Composer */}
      {blocked ? (
        <div className="flex-shrink-0 p-4 bg-rose-50 border-t border-rose-200 flex flex-col items-center justify-center text-center text-gray-700">
          <FaBan className="text-rose-500 mb-2" size={20} />
          <p className="text-sm">
            You’ve blocked this user. You can still read old messages, but can’t send new ones.
          </p>
          <button
            onClick={async () => {
              const token = localStorage.getItem("token") || sessionStorage.getItem("token") || "";
              if (!window.confirm("Unblock this user?")) return;
              await fetch(`${API_BASE}/api/blocks/${peer.id || peer._id}`, {
                method: "DELETE",
                headers: { Authorization: `Bearer ${token}` },
              });
              alert("User unblocked — you can now chat again.");
              setBlocked(false);
            }}
            className="mt-3 px-4 py-2 bg-rose-500 text-white rounded-full hover:bg-rose-600"
          >
            Unblock
          </button>
        </div>
      ) : (
        <div className="flex-shrink-0 h-16 border-t bg-white/80 px-3 flex items-center gap-2">
          <button
            className="p-2 rounded-lg hover:bg-gray-100 relative"
            onClick={() => setShowEmoji((v) => !v)}
            title="Emoji"
          >
            <FaSmile />
            {showEmoji && (
              <div className="absolute bottom-16 right-0 z-50 bg-white rounded-xl shadow-lg">
                <EmojiPicker onEmojiClick={(e) => setInput((p) => p + e.emoji)} theme="light" />
              </div>
            )}
          </button>

          <label className="p-2 rounded-lg hover:bg-gray-100 cursor-pointer" title="Attach">
            <FaPaperclip />
            <input type="file" accept="image/*,video/*" onChange={onPickFile} className="hidden" />
          </label>

          <button
            className="p-2 rounded-lg hover:bg-gray-100"
            onClick={() => openCamera(false)}
            title="Open Camera"
          >
            <FaCamera />
          </button>

          <input
            className="flex-1 p-3 rounded-xl border outline-none"
            placeholder="Type a message…"
            value={input}
            onChange={(e) => onInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && sendText()}
          />

          <button
            onClick={sendText}
            className="p-3 rounded-xl bg-rose-500 text-white hover:bg-rose-600"
            title="Send"
          >
            <FaPaperPlane />
          </button>
        </div>
      )}

      {/* Camera modal */}
      {showCamera && (
        <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl w-full max-w-2xl p-4">
            <div className="flex justify-between items-center border-b pb-2">
              <div className="font-semibold">Camera</div>
              <button className="p-2 hover:bg-gray-100 rounded" onClick={closeCamera}>
                <FaTimes />
              </button>
            </div>
            <div className="mt-3">
              <video ref={videoRef} autoPlay playsInline className="w-full rounded bg-black" />
              <canvas ref={canvasRef} className="hidden" />
            </div>
            <div className="mt-3 flex items-center gap-2 justify-center">
              {!recordVideo ? (
                <>
                  <button
                    onClick={capturePhoto}
                    className="px-4 py-2 rounded-lg bg-rose-500 text-white hover:bg-rose-600"
                  >
                    Capture Photo
                  </button>
                  <button
                    onClick={startRecording}
                    className="px-4 py-2 rounded-lg bg-gray-800 text-white hover:bg-black flex items-center gap-2"
                  >
                    <FaCircle /> Start Video
                  </button>
                </>
              ) : (
                <button
                  onClick={stopRecording}
                  className="px-4 py-2 rounded-lg bg-red-600 text-white hover:bg-red-700 flex items-center gap-2"
                >
                  <FaStop /> Stop & Send
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
