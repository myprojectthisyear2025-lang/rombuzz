// src/components/MeetMap.jsx
import React, { useEffect, useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { MapContainer, TileLayer, Marker, Popup, useMap } from "react-leaflet";
import { FaHeart, FaTimes, FaMapMarkerAlt } from "react-icons/fa";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import { getSocket } from "../socket";

// Fix Leaflet icon paths
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl:
    "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon-2x.png",
  iconUrl:
    "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon.png",
  shadowUrl:
    "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png",
});

//const API_BASE = "http://localhost:4000";
const API_BASE = process.env.REACT_APP_API_BASE || "https://rombuzz-api.onrender.com/api";

function FlyTo({ center }) {
  const map = useMap();
  useEffect(() => {
    if (center) map.flyTo(center, 13);
  }, [center]);
  return null;
}

export default function MeetMap({ me, peer, onClose }) {
  const socket = getSocket();
  const [prompt, setPrompt] = useState(null);
  const [myLoc, setMyLoc] = useState(null);
  const [peerLoc, setPeerLoc] = useState(null);
  const [midpoint, setMidpoint] = useState(null);
  const [places, setPlaces] = useState([]);
const [selected, setSelected] = useState(null);

// 🆕 pending place prompt (when peer picks one)
const [pendingPlace, setPendingPlace] = useState(null);
const [pendingFrom, setPendingFrom] = useState(null);
  const [loading, setLoading] = useState(false);
  const [waiting, setWaiting] = useState(false);
  const [showMap, setShowMap] = useState(false);

  const myId = me?.id || me?._id;
  const peerId = peer?.id || peer?._id;

  // 🔹 Fetch midpoint suggestions
  const fetchSuggestions = useCallback(async (a, b) => {
    try {
      const r = await fetch(`${API_BASE}/api/meet/suggest`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ a, b }),
      });
      const j = await r.json();
      setPlaces(Array.isArray(j.places) ? j.places : []);
    } catch (e) {
      console.error("❌ meet-suggest error", e);
      setPlaces([]);
    }
  }, []);

  // 🔹 Socket listeners
  useEffect(() => {
    if (!socket) return;

    socket.on("meet:request", ({ from }) => {
      console.log("📍 meet:request received from", from);
      if (from.id !== myId)
        setPrompt(`${from.firstName || "Someone"} ${from.lastName || ""}`.trim());
    });

  socket.on("meet:accept", ({ from, coords }) => {
  console.log("✅ meet:accept received from", from, coords);

  // 🧩 Validate the incoming coords before using them
  if (!coords || typeof coords.lat !== "number" || typeof coords.lng !== "number") {
    console.warn("⚠️ Invalid peer coordinates received:", coords);
    return;
  }

  setPeerLoc(coords);
  setWaiting(false);

  // 🧭 Compute midpoint only when both sides have valid coordinates
  if (myLoc && typeof myLoc.lat === "number" && typeof myLoc.lng === "number") {
    const mid = {
      lat: (myLoc.lat + coords.lat) / 2,
      lng: (myLoc.lng + coords.lng) / 2,
    };

    console.log("📍 Midpoint calculated:", mid);
    setMidpoint(mid);
    fetchSuggestions(myLoc, coords);
  } else {
    console.log("⏳ Waiting for my location before computing midpoint");
  }
});

// 🆕 When partner chooses a place
socket.on("meet:place:selected", ({ from, place }) => {
  console.log("📍 meet:place:selected received:", place);
  setPendingFrom(from);
  setPendingPlace(place);
});


    socket.on("meet:suggest", ({ midpoint, places }) => {
      console.log("💞 meet:suggest midpoint", midpoint);
      setMidpoint(midpoint);
      setPlaces(places);
      setShowMap(true);
      setWaiting(false);
      setLoading(false);
    });

    return () => {
      socket.off("meet:request");
      socket.off("meet:accept");
      socket.off("meet:suggest");
      socket.off("meet:decline");
    };
  }, [socket, myLoc, fetchSuggestions]);

  const resetAll = () => {
    setPrompt(null);
    setLoading(false);
    setWaiting(false);
    setShowMap(false);
    setPlaces([]);
    setMidpoint(null);
    setSelected(null);
  };

  // 🔹 Get my location
  const getMyLocation = (cb) => {
  setLoading(true);
  if (!navigator.geolocation) {
    alert("Geolocation not supported");
    setLoading(false);
    return;
  }

  navigator.geolocation.getCurrentPosition(
    (pos) => {
let loc = { lat: pos.coords.latitude, lng: pos.coords.longitude };

// ⚠️ TEMP: simulate distance between two users for local testing
if (window.navigator.userAgent.includes("Edg")) {
  // If running in Microsoft Edge, offset 0.02° (~2 km)
  loc = { lat: loc.lat + 0.02, lng: loc.lng + 0.02 };
}

      // 🪶 Debug + Safety log
      console.log("📍 Got my location", loc);

      if (!loc.lat || !loc.lng || isNaN(loc.lat) || isNaN(loc.lng)) {
        console.warn("⚠️ Invalid coordinates detected:", loc);
        setLoading(false);
        return;
      }

      setMyLoc(loc);
      setLoading(false);

      // ✅ Ensure callback is executed only when valid coords exist
      if (typeof cb === "function") cb(loc);
    },
    (err) => {
      console.error("❌ Geolocation error:", err);
      alert("Please allow location access to continue.");
      setLoading(false);
    },
    { enableHighAccuracy: true, timeout: 10000 }
  );
};

  // 🔹 Initiate meet request
  const startMeet = () => {
    getMyLocation((loc) => {
      socket.emit("meet:request", { from: myId, to: peerId });
      setWaiting(true);
    });
  };

  // 🔹 Accept prompt (receiver shares location)
  const acceptMeet = () => {
    getMyLocation((loc) => {
      socket.emit("meet:accept", { from: myId, to: peerId, coords: loc });
      setPrompt(null);
      setWaiting(true);
    });
  };

  // 🔹 Decline meet
  const declineMeet = () => {
    socket.emit("meet:decline", { from: myId, to: peerId });
    resetAll();
  };

  // 🔹 Choose a place
  const choosePlace = (p) => {
    socket.emit("meet:chosen", { from: myId, to: peerId, place: p });
    alert(`📍 You picked ${p.name}`);
    setSelected(p);
  };

  const center = midpoint || myLoc || { lat: 0, lng: 0 };

  // 🗺️ Map display
  const MapView = () => (
    <div className="flex-1 relative h-[80vh]">
    {myLoc ? (
  <>
    {/* 🆕 Banner when partner picks a place */}
    {pendingPlace && (
      <div className="absolute top-3 left-1/2 -translate-x-1/2 z-[9999] bg-white/90 text-gray-800 px-4 py-2 rounded-xl shadow-lg flex items-center gap-3">
        <span>
          {pendingFrom?.firstName || "Your partner"} marked{" "}
          <b>{pendingPlace.name}</b>
        </span>
        <button
          className="bg-green-500 text-white px-3 py-1 rounded-lg"
          onClick={() => {
            socket.emit("meet:place:accepted", {
              from: myId,
              to: peerId,
              place: pendingPlace,
            });
            setPendingPlace(null);
            alert(`✅ You accepted ${pendingPlace.name}!`);
          }}
        >
          Accept
        </button>
        <button
          className="bg-red-500 text-white px-3 py-1 rounded-lg"
          onClick={() => {
            setPendingPlace(null);
            socket.emit("meet:place:rejected", {
              from: myId,
              to: peerId,
              place: pendingPlace,
            });
          }}
        >
          Reject
        </button>
      </div>
    )}

    <MapContainer
      center={center || [12.9, 77.6]}
      zoom={13}
      style={{ height: "80vh", width: "100%" }}
    >
          <FlyTo center={center} />
          <TileLayer
            attribution='&copy; <a href="https://www.openstreetmap.org/">OpenStreetMap</a>'
            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          />
          {/* ✅ Safely render markers only if coordinates exist */}
{myLoc && typeof myLoc.lat === "number" && typeof myLoc.lng === "number" && (
  <Marker position={[myLoc.lat, myLoc.lng]}>
    <Popup>You</Popup>
  </Marker>
)}

{peerLoc && typeof peerLoc.lat === "number" && typeof peerLoc.lng === "number" && (
  <Marker position={[peerLoc.lat, peerLoc.lng]}>
    <Popup>{peer.firstName || "Partner"}</Popup>
  </Marker>
)}

{midpoint && typeof midpoint.lat === "number" && typeof midpoint.lng === "number" && (
  <Marker position={[midpoint.lat, midpoint.lng]}>
    <Popup>💞 Midpoint</Popup>
  </Marker>
)}

{Array.isArray(places) &&
  places.map((p, i) => (
    <Marker
      key={p.id || i}
      position={[
        p.coords?.lat || p.lat,
        p.coords?.lng || p.lng,
      ]}
      eventHandlers={{
        click: () => {
          setSelected(p);
          console.log("📍 You selected place:", p.name);
          socket.emit("meet:chosen", {
            from: myId,
            to: peerId,
            place: p,
          });
        },
      }}
    >
      <Popup>
        <b>{p.name}</b>
        <br />
        {p.category}
        <br />
        {p.address}
        <br />
        <button
          className="mt-1 bg-rose-500 text-white px-3 py-1 rounded-lg"
          onClick={() => choosePlace(p)}
        >
          Meet here ❤️
        </button>
      </Popup>
    </Marker>
  ))}



        </MapContainer>
        </>
      ) : (
        <div className="grid place-items-center text-gray-500 h-full">
          Getting your location…
        </div>
      )}
    </div>
  );

  return (
    <>
      {/* 🔘 Meet button (initiator) */}
      {!showMap && !prompt && (
        <button
          onClick={startMeet}
          className="flex items-center gap-2 px-4 py-2 bg-rose-500 text-white rounded-full hover:bg-rose-600 transition"
        >
          <FaMapMarkerAlt /> Meet halfway
        </button>
      )}

      {/* 💞 Prompt popup */}
      <AnimatePresence>
        {prompt && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4"
          >
            <motion.div
              initial={{ scale: 0.8, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              transition={{ type: "spring", stiffness: 200, damping: 20 }}
              className="bg-gradient-to-br from-rose-500 via-pink-500 to-amber-400 rounded-3xl shadow-2xl w-full max-w-sm text-white overflow-hidden border border-white/20"
            >
              <div className="flex items-center justify-between p-4 bg-white/10 border-b border-white/20">
                <h2 className="font-semibold text-lg flex items-center gap-2">
                  <FaMapMarkerAlt className="text-yellow-200" />
                  Meet Request
                </h2>
                <button onClick={declineMeet} className="hover:bg-white/20 p-2 rounded-full">
                  <FaTimes />
                </button>
              </div>
              <div className="p-6 text-center space-y-4">
                <div className="text-2xl font-bold">💞 {prompt} wants to meet halfway!</div>
                <p className="text-white/90 text-sm">
                  Share your location to find a fair midpoint with suggested cafés or parks.
                </p>
                <motion.div
                  initial={{ scale: 0 }}
                  animate={{ scale: 1 }}
                  transition={{ delay: 0.2, type: "spring", stiffness: 150 }}
                  className="flex justify-center mt-4"
                >
                  <FaHeart className="text-red-200 text-4xl animate-pulse drop-shadow-lg" />
                </motion.div>
                <div className="flex justify-center gap-3 mt-5">
                  <button
                    onClick={acceptMeet}
                    className="px-5 py-2 rounded-full bg-white text-rose-600 font-semibold hover:bg-rose-100 transition-all"
                  >
                    Share & Meet 💫
                  </button>
                  <button
                    onClick={declineMeet}
                    className="px-5 py-2 rounded-full bg-white/20 hover:bg-white/30 text-white font-medium transition-all"
                  >
                    Not Now
                  </button>
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* 🗺️ Map after accepted */}
      {showMap && (
        <div className="fixed inset-0 bg-white z-40 flex flex-col">
          <div className="flex justify-between items-center p-3 border-b">
            <h2 className="font-semibold text-lg flex items-center gap-2">
              <FaMapMarkerAlt className="text-rose-500" /> Meet halfway
            </h2>
            <button
              onClick={() => {
                resetAll();
                onClose && onClose();
              }}
              className="p-2 hover:bg-gray-100 rounded-full"
            >
              <FaTimes />
            </button>
          </div>
          <MapView />
        </div>
      )}

      {/* ⏳ Waiting indicator */}
      {waiting && (
        <div className="fixed bottom-5 left-0 right-0 text-center z-50">
          <div className="inline-block bg-yellow-100 text-yellow-800 px-4 py-2 rounded-full shadow text-sm">
            Waiting for {peer?.firstName || "partner"} to share location…
          </div>
        </div>
      )}
    </>
  );
}
