// frontend/src/pages/Chat.jsx
import React, { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams, useLocation } from "react-router-dom";
import { FaSearch } from "react-icons/fa";
import { getSocket } from "../socket";

const API_BASE = "http://localhost:4000";
const UNREAD_MAP_KEY = "RBZ:unread:map";
const UNREAD_TOTAL_KEY = "RBZ:unread:total";

/* ---------------------------
   Local helpers / global keys
----------------------------*/
const getLS = (k, f) => {
  try {
    const v = localStorage.getItem(k);
    return v ? JSON.parse(v) : f;
  } catch {
    return f;
  }
};
const setLS = (k, v) => {
  try {
    localStorage.setItem(k, JSON.stringify(v));
  } catch {}
};
const GK = {
  ringtoneAudio: "RBZ:GLOBAL:ringtone:audio",
  ringtoneVideo: "RBZ:GLOBAL:ringtone:video",
  msgSound: "RBZ:GLOBAL:msgSound",
  vibrate: "RBZ:GLOBAL:vibrate",
  showNavBadge: "RBZ:GLOBAL:showNavBadge",
  density: "RBZ:GLOBAL:ui:density",
  fontScale: "RBZ:GLOBAL:ui:fontScale",
  highContrast: "RBZ:GLOBAL:ui:highContrast",
  reduceMotion: "RBZ:GLOBAL:ui:reduceMotion",
  typing: "RBZ:GLOBAL:privacy:typing",
  receipts: "RBZ:GLOBAL:privacy:readReceipts",
  hidePreview: "RBZ:GLOBAL:privacy:hideNotifPreview",
  linkPreviews: "RBZ:GLOBAL:media:linkPreviews",
  autoDownload: "RBZ:GLOBAL:media:autoDownload",
  outputDevice: "RBZ:GLOBAL:audio:deviceId",
  ringVolume: "RBZ:GLOBAL:audio:ringVolume",
  blockUnknown: "RBZ:GLOBAL:calls:blockUnknown",
  dnd: "RBZ:GLOBAL:calls:dnd",
};
const DING = "data:audio/mp3;base64,//uQZAAAAAAAAAAAAAAAAAAAA";
const fileToDataUrl = (file) =>
  new Promise((res, rej) => {
    const fr = new FileReader();
    fr.onload = () => res(fr.result);
    fr.onerror = rej;
    fr.readAsDataURL(file);
  });

const makeRoomId = (a, b) => {
  const A = String(a),
    B = String(b);
  return A < B ? `${A}_${B}` : `${B}_${A}`;
};

// Simple ID generator to replace shortid
const generateId = () => {
  return Date.now().toString(36) + Math.random().toString(36).substr(2);
};

export default function Chat() {
  const navigate = useNavigate();

  const { userId: paramId } = useParams();
  const location = useLocation();
  const queryId = new URLSearchParams(location.search).get("u");
  const openToId = paramId || queryId || null;

  const user = useMemo(() => {
    try {
      return (
        JSON.parse(localStorage.getItem("user")) ||
        JSON.parse(sessionStorage.getItem("user"))
      );
    } catch {
      return null;
    }
  }, []);

  useEffect(() => {
    if (!user) navigate("/login");
  }, [user, navigate]);

  // Stop page scroll
  useEffect(() => {
    const elHtml = document.documentElement;
    const elBody = document.body;
    const prevHtml = elHtml.style.overflow;
    const prevBody = elBody.style.overflow;
    elHtml.style.overflow = "hidden";
    elBody.style.overflow = "hidden";
    return () => {
      elHtml.style.overflow = prevHtml;
      elBody.style.overflow = prevBody;
    };
  }, []);

  const socketRef = useRef(null);
  const [onlineMap, setOnlineMap] = useState({});

  const [matches, setMatches] = useState([]);
  const [filtered, setFiltered] = useState([]);
  const [activeMatch, setActiveMatch] = useState(null);

  const [showHamburger, setShowHamburger] = useState(false);
  const [gset, setGset] = useState(() => ({
    ringtoneAudio: getLS(GK.ringtoneAudio, ""),
    ringtoneVideo: getLS(GK.ringtoneVideo, ""),
    msgSound: getLS(GK.msgSound, true),
    vibrate: getLS(GK.vibrate, true),
    showNavBadge: getLS(GK.showNavBadge, true),
    density: getLS(GK.density, "cozy"),
    fontScale: getLS(GK.fontScale, 100),
    highContrast: getLS(GK.highContrast, false),
    reduceMotion: getLS(GK.reduceMotion, false),
    typing: getLS(GK.typing, true),
    receipts: getLS(GK.receipts, true),
    hidePreview: getLS(GK.hidePreview, false),
    linkPreviews: getLS(GK.linkPreviews, true),
    autoDownload: getLS(GK.autoDownload, "wifi"),
    outputDevice: getLS(GK.outputDevice, ""),
    ringVolume: getLS(GK.ringVolume, 0.8),
    blockUnknown: getLS(GK.blockUnknown, false),
    dnd: getLS(GK.dnd, false),
  }));

  // Restore unread map from storage (set by Navbar while user is off the chat page)
  const [unread, setUnread] = useState(() => getLS(UNREAD_MAP_KEY, {}));

  // On mount, broadcast the current total so Navbar can show the correct badge
  useEffect(() => {
    const total = Object.values(unread).reduce((a, b) => a + b, 0);
    localStorage.setItem(UNREAD_TOTAL_KEY, String(total));
    window.dispatchEvent(new CustomEvent("rbz:unread", { detail: { total } }));
  }, []); // run once

   // load matches (use correct backend route + flexible parsing)
  useEffect(() => {
    if (!user) return;
    const token =
      localStorage.getItem("token") || sessionStorage.getItem("token");
    fetch(`${API_BASE}/api/social/matches`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((r) => r.json())
      .then((data) => {
        // server returns an array; also support { matches: [...] }
        const list = Array.isArray(data)
          ? data
          : Array.isArray(data?.matches)
          ? data.matches
          : [];
        setMatches(list);
        setFiltered(list);
      })
      .catch(() => {
        setMatches([]);
        setFiltered([]);
      });
  }, [user]);


 // ✅ if a target is specified in the URL, auto-select that match (string-safe)
useEffect(() => {
  if (!openToId || !Array.isArray(matches) || !matches.length) return;
  const want = matches.find(
    (m) => String(m.id || m._id) === String(openToId)
  );
  if (want) {
    setActiveMatch(want);
  }
}, [openToId, matches]);

  // connect socket + presence + unread-on-message (ignore our own outbound)
  useEffect(() => {
    if (!user) return;

    const s = getSocket();
    socketRef.current = s;

    const myId = String(user.id || user._id);

    const onConnect = () => {
      try {
        s.emit("register", myId);
      } catch {}
    };
    s.on("connect", onConnect);

    const onOnline = ({ userId }) =>
      setOnlineMap((m) => ({ ...m, [userId]: true }));
    const onOffline = ({ userId }) =>
      setOnlineMap((m) => {
        const n = { ...m };
        delete n[userId];
        return n;
      });

    const handleIncoming = (raw) => {
      if (!raw) return;

      const toId =
        raw.to ||
        raw.toId ||
        raw.receiverId ||
        raw.recipientId ||
        raw.recipient?._id ||
        raw.recipientId?._id;

      const fromId =
        raw.from ||
        raw.fromId ||
        raw.senderId ||
        raw.userId ||
        raw.authorId ||
        raw.sender?._id;

      if (fromId && String(fromId) === myId) return;

      let viaRoomPeer = null;
      if (raw.roomId && typeof raw.roomId === "string") {
        const parts = raw.roomId.split("_").map(String);
        if (parts.includes(myId)) {
          viaRoomPeer = parts.find((p) => p !== myId) || null;
        }
      }
      if (!viaRoomPeer && Array.isArray(raw.participants)) {
        const others = raw.participants.map(String).filter((p) => p !== myId);
        if (others.length === 1) viaRoomPeer = others[0];
      }

      const addressedToMe =
        (toId && String(toId) === myId) ||
        (raw.roomId && viaRoomPeer) ||
        (Array.isArray(raw.participants) &&
          raw.participants.map(String).includes(myId));
      if (!addressedToMe) return;

      const sender = String(fromId || viaRoomPeer || "");
      if (!sender) return;

      const openId = activeMatch ? String(activeMatch.id || activeMatch._id) : null;
      if (openId && openId === sender) return;

      setUnread((prev) => {
        const next = { ...prev, [sender]: (prev[sender] || 0) + 1 };
        setLS(UNREAD_MAP_KEY, next);

        // Sound/vibrate UX
        if (gset.msgSound && !gset.dnd) {
          try {
            const a = new Audio(DING);
            a.play().catch(() => {});
          } catch {}
        }
        if (gset.vibrate && navigator.vibrate && !gset.dnd) navigator.vibrate([50]);

        // Broadcast aggregate
        const total = Object.values(next).reduce((a, b) => a + b, 0);
        localStorage.setItem(UNREAD_TOTAL_KEY, String(total));
        if (gset.showNavBadge) {
          window.dispatchEvent(new CustomEvent("rbz:unread", { detail: { total } }));
        }

        return next;
      });

      // 🔥 FIX: Emit direct:message event for navbar to catch
      // This ensures navbar gets notified even when user is not on chat page
      const directMessagePayload = {
        id: raw.id || generateId(),
        roomId: raw.roomId || makeRoomId(myId, sender),
        from: sender,
        to: myId,
        time: raw.time || new Date().toISOString(),
        preview: (raw.text || "").slice(0, 80),
        type: raw.type || "text",
      };

      // Emit to the user's private room (navbar listens here)
      s.emit("direct:message", directMessagePayload);
    };

    s.on("presence:online", onOnline);
    s.on("presence:offline", onOffline);

    s.on("message", handleIncoming);
    s.on("chat:message", handleIncoming);
    s.on("room:message", handleIncoming);
    s.on("newMessage", handleIncoming);
    s.on("direct:message", handleIncoming);

    return () => {
      s.off("connect", onConnect);
      s.off("presence:online", onOnline);
      s.off("presence:offline", onOffline);
      s.off("message", handleIncoming);
      s.off("chat:message", handleIncoming);
      s.off("room:message", handleIncoming);
      s.off("newMessage", handleIncoming);
      s.off("direct:message", handleIncoming);
      // NOTE: do NOT s.disconnect() — shared singleton
    };
  }, [user, activeMatch, gset.msgSound, gset.vibrate, gset.dnd, gset.showNavBadge]);

  // Join all match rooms so room broadcasts reach the sidebar
  useEffect(() => {
    const s = socketRef.current;
    if (!s || !user || !matches?.length) return;
    const myId = user.id || user._id;
    const roomIds = matches.map((m) => makeRoomId(myId, m.id || m._id));
    roomIds.forEach((rid) => s.emit("joinRoom", rid));
    return () => roomIds.forEach((rid) => s.emit("leaveRoom", rid));
  }, [matches, user]);

  // Clear unread for the thread we open — and broadcast the new total (Navbar updates)
  useEffect(() => {
    if (!activeMatch) return;
    const id = activeMatch.id || activeMatch._id;
    setUnread((prev) => {
      if (!prev[id]) return prev;
      const next = { ...prev };
      delete next[id];

      setLS(UNREAD_MAP_KEY, next);
      const total = Object.values(next).reduce((a, b) => a + b, 0);
      localStorage.setItem(UNREAD_TOTAL_KEY, String(total));
      window.dispatchEvent(new CustomEvent("rbz:unread", { detail: { total } }));

      return next;
    });
  }, [activeMatch]);

  const onSearch = (q) => {
    const query = q.toLowerCase();
    if (!query) return setFiltered(matches);
    setFiltered(
      matches.filter((m) =>
        `${m.firstName || ""} ${m.lastName || ""}`.toLowerCase().includes(query)
      )
    );
  };

  const openProfile = (matchUser) => {
    if (!matchUser) return;
    const id = matchUser.id || matchUser._id;
    const currentId = user?.id || user?._id;
    if (id === currentId) {
      navigate("/profile");
    } else {
      navigate(`/view/${id}`);
    }
  };

  if (!user) return null;

  const densityPad =
    gset.density === "compact" ? "p-2" : gset.density === "comfy" ? "p-4" : "p-3";
  const rootBg = gset.highContrast
    ? "bg-white"
    : "bg-gradient-to-br from-rose-50 to-rose-100";

   return (
 <div
  className={`flex flex-col md:flex-row fixed top-16 left-0 w-full h-[calc(100vh-64px)] overflow-hidden ${rootBg}`}
  style={{
    fontSize: `${Number(gset.fontScale) || 100}%`,
    margin: 0,
    padding: 0,
    overflow: "hidden",
  }}
>



      {/* Sidebar (desktop) */}
      <aside className="hidden md:flex w-80 min-w-72 max-w-80 border-r bg-white/90 backdrop-blur-md flex-col">
        <div className={`border-b flex items-center gap-2 ${densityPad}`}>
          <button
            className="p-2 rounded-lg hover:bg-rose-50"
            onClick={() => setShowHamburger(true)}
            title="Chat settings"
          >
            ☰
          </button>

          <FaSearch className="text-gray-500 shrink-0" />
          <input
            className="flex-1 outline-none text-sm"
            placeholder="Search matches"
            onChange={(e) => onSearch(e.target.value)}
          />
        </div>

        <div className="overflow-y-auto min-h-0">
          {filtered.map((m) => {
            const id = m.id || m._id;
            const name =
              [m.firstName, m.lastName].filter(Boolean).join(" ") || "Unknown";
            const online = !!onlineMap[id];
            const isActive =
              activeMatch && (activeMatch.id || activeMatch._id) === id;
            const count = unread[id] || 0;

            return (
              <div
                key={id}
                className={`w-full flex items-center gap-3 p-3 hover:bg-rose-50 text-left cursor-pointer ${
                  isActive ? "bg-rose-50" : ""
                }`}
              >
                <img
                  src={m.avatar || "https://i.pravatar.cc/80"}
                  alt=""
                  className="h-10 w-10 rounded-full object-cover border cursor-pointer hover:scale-105 transition"
                  onClick={(e) => {
                    e.stopPropagation();
                    openProfile(m);
                  }}
                />
                <div
                  className="flex-1 min-w-0"
                  onClick={(e) => {
                    e.stopPropagation();
                    openProfile(m);
                  }}
                >
                  <div className="flex items-center gap-2">
                    <div className="font-semibold truncate hover:underline flex-1">
                      {name}
                    </div>
                    {count > 0 && (
                      <span className="text-[11px] font-bold px-2 py-0.5 rounded-full bg-red-500 text-white shrink-0">
                        {count > 99 ? "99+" : count}
                      </span>
                    )}
                  </div>
                  <div className="text-xs text-gray-500 flex items-center gap-1">
                    <span
                      className={`text-lg ${
                        online ? "text-green-500" : "text-gray-300"
                      }`}
                    >
                      ●
                    </span>
                    {online ? "Active now" : "Offline"}
                  </div>
                </div>

                <button
                  onClick={() => setActiveMatch(m)}
                  className="ml-auto text-sm bg-rose-500 text-white rounded-full px-3 py-1 hover:bg-rose-600 transition"
                >
                  Chat
                </button>
              </div>
            );
          })}
        </div>
      </aside>

      {/* Main chat area */}
      <main className="flex-1 min-w-0 h-full flex flex-col">
      {activeMatch ? (
  <ChatWindowLazy
    socket={socketRef.current || getSocket()}
    me={user}
    peer={activeMatch}
    onClose={() => setActiveMatch(null)}
  />
) : (
  <div className="h-full grid place-items-center text-gray-500 text-sm md:text-base">
    Select a match to start chatting
  </div>
)}

      </main>

      {/* Drawer */}
      {showHamburger && (
        <div
          className="fixed inset-0 z-50"
          onClick={() => setShowHamburger(false)}
        >
          <div className="absolute inset-0 bg-black/40" />
          <div
            className="absolute top-0 left-0 h-full w-[360px] bg-white shadow-xl p-4 overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-2">
              <div className="font-semibold text-lg">Chat Settings</div>
              <button
                className="p-2 rounded hover:bg-gray-100"
                onClick={() => setShowHamburger(false)}
              >
                ✕
              </button>
            </div>

            {/* (settings UI left as-is) */}
            {/* Appearance */}
            <section className="space-y-3 py-3 border-b">
              <div className="font-medium">Appearance</div>
              <div className="grid grid-cols-3 gap-2">
                {["comfy", "cozy", "compact"].map((mode) => (
                  <button
                    key={mode}
                    onClick={() => {
                      setLS(GK.density, mode);
                      setGset((s) => ({ ...s, density: mode }));
                    }}
                    className={`px-3 py-2 rounded-lg border ${
                      gset.density === mode
                        ? "bg-rose-500 text-white border-rose-500"
                        : "hover:bg-gray-50"
                    }`}
                  >
                    {mode}
                  </button>
                ))}
              </div>
              <label className="text-sm">Font size: {gset.fontScale}%</label>
              <input
                type="range"
                min="90"
                max="120"
                value={gset.fontScale}
                onChange={(e) => {
                  const v = Number(e.target.value);
                  setLS(GK.fontScale, v);
                  setGset((s) => ({ ...s, fontScale: v }));
                }}
              />
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={!!gset.highContrast}
                  onChange={(e) => {
                    setLS(GK.highContrast, e.target.checked);
                    setGset((s) => ({ ...s, highContrast: e.target.checked }));
                  }}
                />
                High contrast
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={!!gset.reduceMotion}
                  onChange={(e) => {
                    setLS(GK.reduceMotion, e.target.checked);
                    setGset((s) => ({ ...s, reduceMotion: e.target.checked }));
                  }}
                />
                Reduce motion
              </label>
            </section>

            {/* Notifications */}
            <section className="space-y-3 py-3 border-b">
              <div className="font-medium">Notifications</div>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={!!gset.msgSound}
                  onChange={(e) => {
                    setLS(GK.msgSound, e.target.checked);
                    setGset((s) => ({ ...s, msgSound: e.target.checked }));
                  }}
                />
                New-message sound
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={!!gset.vibrate}
                  onChange={(e) => {
                    setLS(GK.vibrate, e.target.checked);
                    setGset((s) => ({ ...s, vibrate: e.target.checked }));
                  }}
                />
                Vibrate on message
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={!!gset.showNavBadge}
                  onChange={(e) => {
                    setLS(GK.showNavBadge, e.target.checked);
                    setGset((s) => ({ ...s, showNavBadge: e.target.checked }));
                  }}
                />
                Show unread badge in navbar
              </label>
              <button
                className="px-3 py-1 rounded border text-sm"
                onClick={async () => {
                  try {
                    if (Notification.permission !== "granted") {
                      await Notification.requestPermission();
                    }
                    new Notification("Rombuzz", {
                      body: "Notifications are enabled ✅",
                    });
                  } catch {}
                }}
              >
                Test desktop notification
              </button>
            </section>

            {/* Privacy */}
            <section className="space-y-3 py-3 border-b">
              <div className="font-medium">Privacy</div>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={!!gset.typing}
                  onChange={(e) => {
                    setLS(GK.typing, e.target.checked);
                    setGset((s) => ({ ...s, typing: e.target.checked }));
                  }}
                />
                Show "typing..." to others
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={!!gset.receipts}
                  onChange={(e) => {
                    setLS(GK.receipts, e.target.checked);
                    setGset((s) => ({ ...s, receipts: e.target.checked }));
                  }}
                />
                Send read receipts
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={!!gset.hidePreview}
                  onChange={(e) => {
                    setLS(GK.hidePreview, e.target.checked);
                    setGset((s) => ({ ...s, hidePreview: e.target.checked }));
                  }}
                />
                Hide message preview in notifications
              </label>
            </section>

            {/* Media */}
            <section className="space-y-3 py-3 border-b">
              <div className="font-medium">Media</div>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={!!gset.linkPreviews}
                  onChange={(e) => {
                    setLS(GK.linkPreviews, e.target.checked);
                    setGset((s) => ({ ...s, linkPreviews: e.target.checked }));
                  }}
                />
                Link previews
              </label>
              <div className="text-sm">
                Auto-download:{" "}
                <select
                  value={gset.autoDownload}
                  onChange={(e) => {
                    setLS(GK.autoDownload, e.target.value);
                    setGset((s) => ({ ...s, autoDownload: e.target.value }));
                  }}
                  className="border rounded px-2 py-1"
                >
                  <option value="wifi">Wi-Fi only</option>
                  <option value="always">Always</option>
                  <option value="never">Never</option>
                </select>
              </div>
            </section>

            {/* Calls */}
            <section className="space-y-3 py-3 border-b">
              <div className="font-medium">Calls</div>
              <div className="text-sm">Default voice ringtone</div>
              <input
                type="file"
                accept="audio/*"
                onChange={async (e) => {
                  const f = e.target.files?.[0];
                  if (!f) return;
                  if (f.size > 1.5 * 1024 * 1024)
                    return alert("Pick a file ≤1.5MB");
                  const data = await fileToDataUrl(f);
                  setLS(GK.ringtoneAudio, data);
                  setGset((s) => ({ ...s, ringtoneAudio: data }));
                }}
              />
              <div className="text-sm">Default video ringtone</div>
              <input
                type="file"
                accept="audio/*"
                onChange={async (e) => {
                  const f = e.target.files?.[0];
                  if (!f) return;
                  if (f.size > 1.5 * 1024 * 1024)
                    return alert("Pick a file ≤1.5MB");
                  const data = await fileToDataUrl(f);
                  setLS(GK.ringtoneVideo, data);
                  setGset((s) => ({ ...s, ringtoneVideo: data }));
                }}
              />
              <div className="text-sm">
                Ring volume: {(gset.ringVolume * 100) | 0}%
              </div>
              <input
                type="range"
                min="0"
                max="1"
                step="0.01"
                value={gset.ringVolume}
                onChange={(e) => {
                  const v = Number(e.target.value);
                  setLS(GK.ringVolume, v);
                  setGset((s) => ({ ...s, ringVolume: v }));
                }}
              />
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={!!gset.dnd}
                  onChange={(e) => {
                    setLS(GK.dnd, e.target.checked);
                    setGset((s) => ({ ...s, dnd: e.target.checked }));
                  }}
                />
                Do Not Disturb (auto-reject calls)
              </label>
            </section>

            {/* Advanced */}
            <section className="space-y-3 py-3">
              <div className="font-medium">Advanced</div>
              <button
                className="px-3 py-1 rounded border text-sm"
                onClick={() => {
                  if (!window.confirm("Clear custom ringtones?")) return;
                  [GK.ringtoneAudio, GK.ringtoneVideo].forEach((k) =>
                    localStorage.removeItem(k)
                  );
                  setGset((s) => ({
                    ...s,
                    ringtoneAudio: "",
                    ringtoneVideo: "",
                  }));
                }}
              >
                Clear custom ringtones
              </button>
            </section>
          </div>
        </div>
      )}
    </div>
  );
}

function ChatWindowLazy(props) {
  const [Comp, setComp] = useState(null);
  useEffect(() => {
    import("./ChatWindow.jsx").then((m) => setComp(() => m.default));
  }, []);
  if (!Comp) return null;
  return <Comp {...props} />;
}