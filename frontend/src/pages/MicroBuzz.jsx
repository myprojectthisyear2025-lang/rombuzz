// src/pages/MicroBuzz.jsx
import React, { useEffect, useRef, useState } from "react";
import { io } from "socket.io-client";
import { useNavigate } from "react-router-dom";

const socket = io("http://localhost:4000");
//const API_BASE = "http://localhost:4000/api";
const API_BASE =
  import.meta?.env?.VITE_API_BASE || "https://rombuzz-api.onrender.com/api";

export default function MicroBuzz({ user }) {
  const navigate = useNavigate();

  // -------- Helpers
  const token = () =>
    localStorage.getItem("token") || sessionStorage.getItem("token");

  // ✅ Buzz someone (like/match)
  const handleBuzz = async (targetId) => {
  console.log("⚡ handleBuzz triggered →", targetId);
  try {
    const res = await fetch(`${API_BASE}/microbuzz/buzz`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token()}`,
      },
      body: JSON.stringify({ toId: targetId }),
    });


      const data = await res.json();

      if (data.matched) {
        console.log("🎯 Match confirmed:", data);
        alert("🎉 It's a match! Opening chat...");
        navigate(`/chat/${targetId}`);
      } else if (data.alreadyLiked) {
        alert("You already buzzed this person before ⚡");
      } else {
        alert("You buzzed them! Waiting for them to buzz back 👋");
      }
    } catch (err) {
      console.error("❌ Buzz failed:", err);
      alert("Something went wrong while buzzing.");
    }
  };

  // ---------- UI States ----------
  const [isActive, setIsActive] = useState(false);
  const [status, setStatus] = useState(
    "Ultra-local discovery for shy moments. Turn on MicroBuzz, take a quick selfie, and we'll show nearby people who did the same. If you both tap Connect, it's an instant match."
  );
  const [error, setError] = useState("");
  const [debug, setDebug] = useState("");
  const [buzzRequest, setBuzzRequest] = useState(null);
  const [matchData, setMatchData] = useState(null);

  // ---------- Media & Geolocation ----------
  const videoRef = useRef(null);
  const streamRef = useRef(null);
  const [selfieUrl, setSelfieUrl] = useState("");
  const [coords, setCoords] = useState(null);

  // ---------- Nearby Scanning ----------
  const [nearby, setNearby] = useState([]);
  const scanTimerRef = useRef(null);
  const isScanningRef = useRef(false);
  const backoffRef = useRef(5000);

  // ---------- Animation ----------
  const rafRef = useRef(null);
  const [now, setNow] = useState(0);
  const orbitsRef = useRef({});
  const abortRef = useRef(null);

  // =====================================================
  // 🔌 SOCKET.IO SETUP
  // =====================================================

  useEffect(() => {
    const currentUser = JSON.parse(localStorage.getItem("user") || "{}");
    if (!currentUser?.id) {
      console.warn("⚠️ No user.id found for socket register");
      return;
    }

    // Wait until connected before registering
    if (socket.connected) {
      socket.emit("register", currentUser.id);
      console.log("🟣 Socket already connected → registered", currentUser.id);
    } else {
      socket.on("connect", () => {
        socket.emit("register", currentUser.id);
        console.log("🟣 Socket connected & registered:", currentUser.id);
      });
    }

    return () => {
      socket.off("connect");
    };
  }, []);

  // Listen for buzz requests, matches, and rejections
  useEffect(() => {
  // 💌 When someone buzzes YOU
socket.on("buzz_request", (data) => {
  console.log("📨 Received buzz_request:", data);

  // Force a visible test popup even if selfieUrl is missing
  if (!data || !data.fromId) {
    console.warn("⚠️ Invalid buzz_request payload:", data);
    return;
  }

  // Fallbacks so the popup always renders
  if (!data.selfieUrl) data.selfieUrl = "https://via.placeholder.com/100";
  if (!data.name) data.name = "Someone nearby";

  // Confirm in console that it's being rendered
  console.log("✅ Showing buzz popup for:", data.name, data.selfieUrl);

  setBuzzRequest(data);
});


    // 🎉 When a match happens
    socket.on("match", (data) => {
      console.log("🎉 Match event:", data);
      alert("🎉 It's a match! Opening chat...");
      const targetId = data?.otherUserId;
      if (targetId) navigate(`/chat/${targetId}`);
      setBuzzRequest(null);
    });

    // 🚫 When your buzz is rejected
    socket.on("buzz_rejected", (data) => {
      console.log("❌ Buzz rejected:", data);
      alert("❌ Your buzz was rejected.");
    });
  // 💥 When both should open each other's profile (match moment)
  socket.on("buzz_match_open_profile", (data) => {
    console.log("💫 buzz_match_open_profile:", data);
    const targetId = data?.otherUserId;
    const targetSelfie = data?.selfieUrl;
    setMatchData({
      otherUserId: targetId,
      selfieUrl: targetSelfie,
    });

    // ⏳ After 2 seconds, open profile page
    setTimeout(() => {
      if (targetId) navigate(`/viewProfile/${targetId}`);
      setMatchData(null);
    }, 2000);
  });

    return () => {
  socket.off("buzz_request");
  socket.off("match");
  socket.off("buzz_rejected");
  socket.off("buzz_match_open_profile");
};

  }, [navigate]);

  // =====================================================
  // 🔧 CAMERA + SCANNING (unchanged from your last version)
  // =====================================================

  function cleanupCamera() {
    const stream = streamRef.current;
    if (stream) {
      stream.getTracks().forEach((track) => track.stop());
      streamRef.current = null;
    }
    const video = videoRef.current;
    if (video) {
      video.srcObject = null;
      try {
        video.pause();
      } catch {}
    }
  }

  async function getLocation() {
    return new Promise((resolve, reject) => {
      if (!("geolocation" in navigator)) {
        reject(new Error("Geolocation not supported"));
        return;
      }
      navigator.geolocation.getCurrentPosition(
        (pos) => {
          resolve({
            lat: pos.coords.latitude,
            lng: pos.coords.longitude,
          });
        },
        (err) => reject(err),
        { enableHighAccuracy: true, timeout: 10000 }
      );
    });
  }

  // -------- Camera
  async function startMicroBuzz() {
    try {
      setError("");
      setDebug("");
      setStatus("Requesting camera…");

      // Hint to OS/browser: allow any front camera if available
      const stream = await navigator.mediaDevices.getUserMedia({
        video: {
          facingMode: { ideal: "user" },
          width: { ideal: 720 },
          height: { ideal: 720 },
        },
        audio: false,
      });

      // Attach locally
      streamRef.current = stream;
      if (videoRef.current) {
        videoRef.current.srcObject = stream;
        videoRef.current.setAttribute("playsInline", "true");
        videoRef.current.muted = true;
        await videoRef.current.play();
      }

      setStatus("Take a quick selfie to appear on the radar…");
    } catch (err) {
      console.error(err);
      setError(
        "Camera permission denied or not available. You can try another browser/device."
      );
      setStatus("Please allow camera access and try again.");
    }
  }

  async function takeSelfieAndActivate() {
    try {
      setError("");
      setStatus("Capturing selfie…");

      // 1) Grab a frame
      const video = videoRef.current;
      if (!video || !video.videoWidth) {
        throw new Error("Selfie failed. Video not ready.");
      }
      const side = Math.min(video.videoWidth, video.videoHeight);
      const cv = document.createElement("canvas");
      cv.width = 320;
      cv.height = 320;
      const ctx = cv.getContext("2d");
      const sx = (video.videoWidth - side) / 2;
      const sy = (video.videoHeight - side) / 2;
      ctx.drawImage(video, sx, sy, side, side, 0, 0, cv.width, cv.height);

      const blob = await new Promise((res) => cv.toBlob(res, "image/jpeg", 0.85));
      if (!blob) throw new Error("Selfie failed. Try again.");

      // 2) Upload selfie
      setStatus("Uploading selfie…");
      const fd = new FormData();
      fd.append("selfie", blob, "selfie.jpg");

      abortRef.current?.abort();
      abortRef.current = new AbortController();

      const upRes = await fetch(`${API_BASE}/microbuzz/selfie`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token()}` },
        body: fd,
        signal: abortRef.current.signal,
      });
      const upData = await safeJson(upRes);
      if (!upRes.ok)
        throw new Error(upData?.error || `Upload failed (HTTP ${upRes.status})`);

      const url = upData.url;
      if (!url) throw new Error("No URL returned from selfie upload.");
      setSelfieUrl(url);

      // 3) Stop camera immediately
      cleanupCamera();

      // 4) Get location & activate
      setStatus("Getting your location…");
      const pos = await getLocation();
      setCoords(pos);

      setStatus("Activating MicroBuzz…");
      await activatePresence(pos, url);

      // 5) Start scanning + animation
      setStatus("Scanning nearby…");
      setIsActive(true);
      await scanNearby(pos);
      startScanInterval();
      startRafAnimation();
    } catch (err) {
      console.error(err);
      cleanupCamera();
      setError(err?.message || "Selfie failed. Try again.");
      setStatus("Selfie failed. Try again.");
    }
  }

  async function activatePresence(pos, selfie) {
    abortRef.current?.abort();
    abortRef.current = new AbortController();
    const res = await fetch(`${API_BASE}/microbuzz/activate`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token()}`,
      },
      body: JSON.stringify({ lat: pos.lat, lng: pos.lng, selfieUrl: selfie }),
      signal: abortRef.current.signal,
    });
    const data = await safeJson(res);
    if (!res.ok) {
      throw new Error(data?.error || "Activate failed");
    }
  }

  // -------- Scanning
  function startScanInterval() {
    stopScanInterval();
    scanTimerRef.current = setInterval(async () => {
      if (isScanningRef.current) return;
      isScanningRef.current = true;
      try {
        const pos = coords || (await getLocation());
        setCoords(pos);
        // Re-activate to bump lastActive
        if (selfieUrl) await activatePresence(pos, selfieUrl);
        await scanNearby(pos);
        backoffRef.current = 5000; // reset backoff on success
      } catch (e) {
        console.warn("scan loop:", e);
        backoffRef.current = Math.min(
          20000,
          (backoffRef.current || 5000) + 3000
        );
      } finally {
        isScanningRef.current = false;
      }
    }, backoffRef.current);
  }

  function stopScanInterval() {
    if (scanTimerRef.current) {
      clearInterval(scanTimerRef.current);
      scanTimerRef.current = null;
    }
  }

  async function scanNearby(pos) {
    try {
      setStatus("Scanning nearby users…");
      setError("");

      const url = new URL(`${API_BASE}/microbuzz/nearby`);
      url.searchParams.set("lat", String(pos.lat));
      url.searchParams.set("lng", String(pos.lng));
      url.searchParams.set("radius", "0.75"); // ~750m for testing

      abortRef.current?.abort();
      abortRef.current = new AbortController();

      const res = await fetch(url.toString(), {
        headers: { Authorization: `Bearer ${token()}` },
        signal: abortRef.current.signal,
      });
      const data = await safeJson(res);
      if (!res.ok) throw new Error(data?.error || `HTTP ${res.status}`);

      const list = Array.isArray(data.users) ? data.users : [];
      setNearby(list);
      setStatus(
        list.length > 0
          ? "Nearby users found! Tap a photo to Buzz."
          : "No one nearby right now. Try again later."
      );

      // Seed/refresh orbit props for users
      list.forEach((u) => {
        if (!orbitsRef.current[u.id]) {
          const rf = clamp(u.distanceMeters ? u.distanceMeters / 800 : 0.4, 0.15, 0.95);
          orbitsRef.current[u.id] = {
            angle0: Math.random() * Math.PI * 2,
            speed: 0.3 + Math.random() * 0.7, // radians/sec
            radiusFactor: rf,
          };
        }
      });
      // prune orbits for users that disappeared
      Object.keys(orbitsRef.current).forEach((id) => {
        if (!list.find((u) => u.id === id)) {
          delete orbitsRef.current[id];
        }
      });
    } catch (err) {
      console.error(err);
      setError(err?.message || "Scan failed");
      setStatus("Scan error. Retrying soon…");
    }
  }

  // -------- Animation (requestAnimationFrame)
  function startRafAnimation() {
    stopRafAnimation();
    const origin = performance.now();
    const loop = (t) => {
      setNow(t - origin); // ms
      rafRef.current = requestAnimationFrame(loop);
    };
    rafRef.current = requestAnimationFrame(loop);
  }

  function stopRafAnimation() {
    if (rafRef.current) {
      cancelAnimationFrame(rafRef.current);
      rafRef.current = null;
    }
  }

  // -------- Stop flow
  async function stopMicroBuzz() {
    try {
      setStatus("Stopping…");
      setError("");
      cleanupCamera();
      stopScanInterval();
      stopRafAnimation();
      setNearby([]);
      setIsActive(false);

      abortRef.current?.abort();
      abortRef.current = new AbortController();
      await fetch(`${API_BASE}/microbuzz/deactivate`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token()}` },
        signal: abortRef.current.signal,
      });
      setStatus("MicroBuzz is off. Turn it on to start discovering.");
    } catch (err) {
      console.error(err);
      setError(err?.message || "Failed to stop");
    }
  }

  // Safely decode JSON or return null
  async function safeJson(res) {
    try {
      return await res.json();
    } catch {
      return null;
    }
  }
  function clamp(v, min, max) {
    return Math.max(min, Math.min(max, v));
  }

  // Respond to a Buzz popup ❤️ or ❌
async function respondToBuzz(accepted) {
  if (!buzzRequest) return;

  try {
    if (accepted) {
      // ✅ Send buzz back to confirm match
      const res = await fetch(`${API_BASE}/microbuzz/buzz`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token()}`,
        },
body: JSON.stringify({ toId: buzzRequest.fromId, confirm: true }),
      });

      const data = await res.json();
 

    } else {
      // ❌ Rejected buzz
      socket.emit("buzz_rejected", { toId: buzzRequest.fromId });
    }
  } catch (err) {
    console.error("❌ respondToBuzz error:", err);
  } finally {
    setBuzzRequest(null);
  }
}



  // Cleanup on unmount + pause scanning when tab hidden
  useEffect(() => {
    const onVisibility = () => {
      if (document.hidden) {
        stopScanInterval();
      } else if (isActive) {
        startScanInterval();
      }
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      document.removeEventListener("visibilitychange", onVisibility);
      cleanupCamera();
      stopScanInterval();
      stopRafAnimation();
      abortRef.current?.abort();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isActive]);

  // -------- Render
  return (
    <div className="min-h-screen bg-gradient-to-br from-purple-900 via-indigo-900 to-pink-800 p-4 flex items-center justify-center relative overflow-hidden">
      {/* Animated Background Elements */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute -top-40 -left-40 w-80 h-80 bg-purple-500/20 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute -bottom-40 -right-40 w-80 h-80 bg-pink-500/20 rounded-full blur-3xl animate-pulse delay-1000"></div>
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-indigo-500/10 rounded-full blur-3xl animate-pulse delay-500"></div>
      </div>

      <div className="relative bg-white/10 backdrop-blur-lg border border-white/20 shadow-2xl rounded-3xl p-6 sm:p-8 w-full max-w-4xl z-10">
        {/* Premium Glow Effect */}
        <div className="absolute -inset-1 bg-gradient-to-r from-purple-600 to-pink-600 rounded-3xl blur opacity-30 group-hover:opacity-100 transition duration-1000 group-hover:duration-200 animate-pulse"></div>
        
        <div className="relative">
          {/* Header */}
          <div className="flex items-center justify-between gap-3 mb-6">
            <div className="flex items-center gap-3">
              <div className="relative">
                <div className="w-12 h-12 bg-gradient-to-br from-purple-500 to-pink-500 rounded-2xl flex items-center justify-center shadow-lg">
                  <span className="text-2xl">📡</span>
                </div>
                <div className="absolute -top-1 -right-1 w-4 h-4 bg-green-400 rounded-full border-2 border-white animate-pulse"></div>
              </div>
              <div>
                <h1 className="text-3xl sm:text-4xl font-black bg-gradient-to-r from-white to-purple-200 bg-clip-text text-transparent">
                  MicroBuzz
                </h1>
                <p className="text-purple-200/80 text-sm font-medium">Live Nearby Discovery</p>
              </div>
            </div>
            <span className="bg-gradient-to-r from-yellow-400 to-orange-500 text-black text-xs font-bold px-3 py-2 rounded-full shadow-lg animate-pulse">
              🔥 PREMIUM SOON
            </span>
          </div>

          {/* Status Card */}
          <div className="bg-black/30 border border-white/10 rounded-2xl p-4 mb-6 backdrop-blur-sm">
            <div className="flex items-start gap-3">
              <div className="flex-shrink-0 w-3 h-3 bg-green-400 rounded-full mt-1.5 animate-pulse"></div>
              <p className="text-white/90 text-sm leading-relaxed">{status}</p>
            </div>
            {error && (
              <div className="mt-3 p-3 bg-red-500/20 border border-red-500/30 rounded-xl">
                <div className="flex items-center gap-2 text-red-200 text-sm">
                  <span>⚠️</span>
                  <span>{error}</span>
                </div>
              </div>
            )}
          </div>

          {/* Controls */}
          <div className="flex flex-wrap items-center gap-3 mb-8">
            {!isActive ? (
              <>
                <button
                  onClick={startMicroBuzz}
                  className="bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600 text-white px-6 py-3 rounded-xl font-semibold shadow-lg hover:shadow-xl transform hover:scale-105 transition-all duration-200 flex items-center gap-2"
                >
                  <span>🚀</span>
                  Activate MicroBuzz
                </button>
                {!!streamRef.current && (
                  <button
                    onClick={takeSelfieAndActivate}
                    className="bg-gradient-to-r from-green-500 to-emerald-500 hover:from-green-600 hover:to-emerald-600 text-white px-6 py-3 rounded-xl font-semibold shadow-lg hover:shadow-xl transform hover:scale-105 transition-all duration-200 flex items-center gap-2"
                  >
                    <span>📸</span>
                    Take Selfie & Start
                  </button>
                )}
              </>
            ) : (
              <>
                <button
                  onClick={stopMicroBuzz}
                  className="bg-gradient-to-r from-gray-600 to-gray-700 hover:from-gray-700 hover:to-gray-800 text-white px-6 py-3 rounded-xl font-semibold shadow-lg hover:shadow-xl transform hover:scale-105 transition-all duration-200 flex items-center gap-2"
                >
                  <span>⏹️</span>
                  Stop MicroBuzz
                </button>
                <button
                  onClick={() => coords && scanNearby(coords)}
                  className="bg-gradient-to-r from-blue-500 to-cyan-500 hover:from-blue-600 hover:to-cyan-600 text-white px-6 py-3 rounded-xl font-semibold shadow-lg hover:shadow-xl transform hover:scale-105 transition-all duration-200 flex items-center gap-2"
                >
                  <span>🔄</span>
                  Refresh Scan
                </button>
              </>
            )}
          </div>

          {/* Camera preview (only when awaiting selfie) */}
          {!isActive && streamRef.current && (
            <div className="mb-8">
              <div className="rounded-2xl overflow-hidden border-2 border-white/20 shadow-2xl max-w-sm mx-auto transform hover:scale-105 transition-transform duration-300">
                <video
                  ref={videoRef}
                  className="w-full h-auto bg-black"
                  playsInline
                  muted
                />
              </div>
              <p className="text-white/60 text-xs text-center mt-3">
                Position your face and click "📸 Take Selfie & Start".<br />
                Your camera will turn off after the selfie is taken.
              </p>
            </div>
          )}

          {/* Radar */}
          {isActive && (
            <div className="relative mx-auto mt-4 mb-4">
              <Radar
                you={selfieUrl}
                users={nearby}
                orbits={orbitsRef.current}
                nowMs={now}
                onBuzz={handleBuzz}
              />
            </div>
          )}

          {/* Debug (optional) */}
          {debug && (
            <pre className="text-[11px] text-white/50 bg-black/30 border border-white/10 rounded-xl p-3 mt-4 overflow-x-auto backdrop-blur-sm">
              {debug}
            </pre>
          )}

          {!isActive && (
            <div className="text-center text-white/50 text-sm mt-6">
              <div className="bg-white/5 rounded-2xl p-4 border border-white/10">
                <p className="font-semibold text-white/70 mb-2">💡 Pro Tip</p>
                <p>MicroBuzz works best in cafés, libraries, campuses, and social events where people are open to meeting new friends.</p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Buzz Request Popup */}
      {buzzRequest && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 backdrop-blur-xl">
          <div className="relative bg-gradient-to-br from-purple-900 to-pink-800 border border-white/20 rounded-3xl shadow-2xl p-8 w-96 max-w-[90vw] animate-pop-in">
            {/* Glow effect */}
            <div className="absolute -inset-1 bg-gradient-to-r from-purple-600 to-pink-600 rounded-3xl blur opacity-30"></div>
            
            <div className="relative">
              <div className="text-center">
                {/* Avatar with pulse animation */}
                <div className="relative inline-block">
                  <img
                    src={buzzRequest.selfieUrl || "https://via.placeholder.com/100"}
                    alt={buzzRequest.name || "Buzz request"}
                    className="w-24 h-24 rounded-2xl object-cover border-4 border-white/20 shadow-2xl mx-auto"
                  />
                  <div className="absolute inset-0 rounded-2xl border-2 border-pink-400 animate-ping opacity-60"></div>
                </div>
                
                <h3 className="text-2xl font-black text-white mt-6 mb-2">
                  💌 Buzz Incoming!
                </h3>
                
                <p className="text-xl font-semibold text-white/90 mb-1">
                  {buzzRequest.name || "Someone nearby"}
                </p>

                {buzzRequest.distanceMeters && (
                  <p className="text-white/60 text-sm mb-6">
                    {Math.round(buzzRequest.distanceMeters)} meters away • Ready to connect
                  </p>
                )}

                <p className="text-white/70 text-sm mb-8 leading-relaxed">
                  Accept to start chatting instantly, or dismiss to pass on this connection.
                </p>

                {/* Action Buttons */}
                <div className="flex justify-center gap-4">
                  <button
                    onClick={() => respondToBuzz(true)}
                    className="bg-gradient-to-r from-green-500 to-emerald-500 hover:from-green-600 hover:to-emerald-600 text-white px-8 py-4 rounded-2xl font-bold shadow-2xl transform hover:scale-110 transition-all duration-200 flex items-center gap-3 flex-1 justify-center"
                  >
                    <span className="text-xl">❤️</span>
                    Accept
                  </button>
                  <button
                    onClick={() => respondToBuzz(false)}
                    className="bg-gradient-to-r from-gray-600 to-gray-700 hover:from-gray-700 hover:to-gray-800 text-white px-8 py-4 rounded-2xl font-bold shadow-2xl transform hover:scale-110 transition-all duration-200 flex items-center gap-3 flex-1 justify-center"
                  >
                    <span className="text-xl">✖️</span>
                    Dismiss
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
      {/* 💥 Match Overlay */}
      {matchData && (
        <div className="fixed inset-0 z-[9999] flex flex-col items-center justify-center bg-black/80 backdrop-blur-md text-white animate-fade-in">
          <h1 className="text-5xl font-extrabold mb-6 animate-bounce">💥 It’s a Match!</h1>
          <div className="flex items-center justify-center gap-8">
            <img
              src={selfieUrl}
              alt="You"
              className="w-32 h-32 rounded-full border-4 border-pink-400 shadow-lg object-cover animate-pulse"
            />
            <span className="text-6xl animate-pulse">💖</span>
            <img
              src={matchData.selfieUrl || "https://via.placeholder.com/100"}
              alt="Match"
              className="w-32 h-32 rounded-full border-4 border-pink-400 shadow-lg object-cover animate-pulse"
            />
          </div>
          <p className="text-white/80 mt-6 text-lg font-medium animate-fade-in">
            Opening profiles...
          </p>
        </div>
      )}

      {/* Custom Animations */}
      <style>{`
        @keyframes fade-in {
          from { opacity: 0; transform: scale(0.95) translateY(10px); }
          to { opacity: 1; transform: scale(1) translateY(0); }
        }
        @keyframes pop-in {
          0% { opacity: 0; transform: scale(0.8) translateY(20px); }
          70% { opacity: 1; transform: scale(1.05) translateY(-5px); }
          100% { opacity: 1; transform: scale(1) translateY(0); }
        }
        .animate-fade-in { animation: fade-in 0.3s ease-out; }
        .animate-pop-in { animation: pop-in 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275); }
      `}</style>
    </div>
  );
}

/* ============================
   Radar component (superstar edition)
=============================== */
function Radar({ you, users, orbits, nowMs, onBuzz }) {
  const size = 480;
  const center = size / 2;
  const ringCount = 4;
  const maxRadius = size / 2 - 20;

  const tSec = (nowMs || 0) / 1000;

  // Compute positions
  const items = (users || []).map((u, idx) => {
    const seed = orbits[u.id] || { angle0: 0, speed: 0.5, radiusFactor: 0.7 };
    const radius = Math.max(60, maxRadius * seed.radiusFactor);
    const angle = seed.angle0 + seed.speed * tSec + idx * 0.35;
    const x = center + radius * Math.cos(angle);
    const y = center + radius * Math.sin(angle);
    return { ...u, x, y };
  });

  return (
    <div className="relative mx-auto" style={{ width: size, height: size }}>
      {/* Outer glow container */}
      <div className="absolute inset-0 rounded-full bg-gradient-to-r from-purple-500/30 to-pink-500/30 blur-xl animate-pulse"></div>
      
      {/* Main radar */}
      <div
        className="rounded-full shadow-2xl overflow-hidden relative border-2 border-white/10"
        style={{
          width: size,
          height: size,
          background: `
            radial-gradient(
              circle at center,
              rgba(168, 85, 247, 0.15) 0%,
              rgba(126, 34, 206, 0.25) 40%,
              rgba(236, 72, 153, 0.35) 100%
            )
          `,
        }}
      >
        {/* Grid rings with glow */}
        {[...Array(ringCount)].map((_, i) => {
          const r = ((i + 1) / ringCount) * maxRadius * 2;
          return (
            <div
              key={i}
              className="absolute rounded-full border border-purple-400/40 shadow-inner"
              style={{
                width: r,
                height: r,
                top: center - r / 2,
                left: center - r / 2,
                boxShadow: 'inset 0 0 20px rgba(168, 85, 247, 0.3)'
              }}
            />
          );
        })}

        {/* Crosshairs */}
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="w-full h-px bg-purple-400/30"></div>
        </div>
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="h-full w-px bg-purple-400/30"></div>
        </div>

        {/* Sweep line with enhanced glow */}
        <div
          className="absolute"
          style={{
            width: size,
            height: size,
            top: 0,
            left: 0,
            background: `
              conic-gradient(
                from 0deg,
                transparent 0deg,
                rgba(236, 72, 153, 0.6) 15deg,
                rgba(168, 85, 247, 0.8) 30deg,
                transparent 60deg
              )
            `,
            animation: "radar-sweep 3s linear infinite",
            mixBlendMode: "screen",
            pointerEvents: "none",
          }}
        />

        {/* You (center) with enhanced styling */}
        <div
          className="absolute rounded-2xl border-4 border-pink-400 shadow-2xl transform hover:scale-110 transition-transform duration-300 cursor-pointer"
          style={{
            width: 80,
            height: 80,
            top: center - 40,
            left: center - 40,
            backgroundColor: "#fff",
            overflow: "hidden",
            boxShadow: `
              0 0 0 8px rgba(236, 72, 153, 0.3),
              0 0 30px rgba(236, 72, 153, 0.5)
            `,
          }}
        >
          {you ? (
            <img src={you} alt="You" className="w-full h-full object-cover" />
          ) : (
            <div className="w-full h-full bg-gradient-to-br from-purple-400 to-pink-400 flex items-center justify-center">
              <span className="text-white text-2xl">👤</span>
            </div>
          )}
        </div>

        {/* Nearby avatars (enhanced) */}
        {items.map((u) => (
          <div
            key={u.id}
            onClick={() => onBuzz(u.id)}
            className="absolute rounded-2xl border-3 border-purple-400 hover:scale-125 transition-all duration-300 cursor-pointer shadow-2xl group"
            title={`${u.name || "Nearby"} • ${
              u.distanceMeters ? Math.round(u.distanceMeters) + "m" : ""
            }`}
            style={{
              width: 68,
              height: 68,
              top: u.y - 34,
              left: u.x - 34,
              overflow: "hidden",
              backgroundColor: "#fff",
              boxShadow: `
                0 10px 30px rgba(0,0,0,0.3),
                0 0 0 3px rgba(168, 85, 247, 0.8)
              `,
            }}
          >
            <img
              src={u.selfieUrl || "https://via.placeholder.com/68?text=User"}
              alt={u.name || "Nearby"}
              className="w-full h-full object-cover group-hover:scale-110 transition-transform duration-300"
            />
            
            {/* Distance badge */}
            {u.distanceMeters && (
              <div className="absolute -bottom-2 -right-2 bg-gradient-to-r from-purple-500 to-pink-500 text-white text-xs font-bold px-2 py-1 rounded-full shadow-lg">
                {Math.round(u.distanceMeters)}m
              </div>
            )}
            
            {/* Hover glow */}
            <div className="absolute inset-0 rounded-2xl border-2 border-transparent group-hover:border-white group-hover:shadow-[0_0_20px_rgba(255,255,255,0.8)] transition-all duration-300"></div>
          </div>
        ))}

        {/* Pulsing center dot */}
        <div
          className="absolute rounded-full bg-green-400 shadow-lg"
          style={{
            width: 12,
            height: 12,
            top: center - 6,
            left: center - 6,
            animation: "pulse 2s infinite",
            boxShadow: "0 0 0 0 rgba(74, 222, 128, 0.7)"
          }}
        ></div>
      </div>

      {/* Enhanced Styles */}
      <style>{`
        @keyframes radar-sweep {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        @keyframes pulse {
          0% { box-shadow: 0 0 0 0 rgba(74, 222, 128, 0.7); }
          70% { box-shadow: 0 0 0 10px rgba(74, 222, 128, 0); }
          100% { box-shadow: 0 0 0 0 rgba(74, 222, 128, 0); }
        }
      `}</style>
    </div>
  );
}