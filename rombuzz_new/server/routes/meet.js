/**
 * ============================================================
 * 📁 File: routes/meet.js
 * 🌍 Purpose: Unified Meet-in-Middle system (MongoDB version)
 *
 * Endpoints:
 *   POST /api/geo/save            → Save user's coordinates (Mongo)
 *   GET  /api/geo/approx          → Fetch another user's coordinates
 *   GET  /api/meet-suggest        → Suggest midpoint venues (Google/Static)
 *   POST /api/meet/suggest        → Suggest midpoint venues (Overpass API)
 *   GET  /api/presence/:id        → Check online status
 *
 * Notes:
 *   - Replaces all LowDB user lookups with Mongoose User model
 *   - Everything else (Google/Overpass/Presence) unchanged
 * ============================================================
 */

const express = require("express");
const router = express.Router();
const fetch = (...args) => import("node-fetch").then(({ default: fetch }) => fetch(...args));

const authMiddleware = require("../routes/auth-middleware");
const User = require("../models/User");

/* ============================================================
   📍 SECTION 1: GEOLOCATION SAVE & FETCH (MongoDB)
============================================================ */

/**
 * POST /api/geo/save
 * Save authenticated user's coordinates in MongoDB.
 */
router.post("/geo/save", authMiddleware, async (req, res) => {
  try {
    const { lat, lng } = req.body || {};
    if (!lat || !lng) return res.status(400).json({ error: "Invalid coords" });

    const user = await User.findOneAndUpdate(
      { id: req.user.id },
      { $set: { location: { lat, lng, updatedAt: new Date() } } },
      { new: true }
    );

    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({ success: true });
  } catch (err) {
    console.error("❌ /geo/save error:", err);
    res.status(500).json({ error: "geo save failed" });
  }
});

/**
 * GET /api/geo/approx
 * Fetch another user's stored coordinates (approximate).
 */
router.get("/geo/approx", authMiddleware, async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) return res.status(400).json({ error: "Missing userId" });

    const user = await User.findOne({ id: userId }, { location: 1, _id: 0 }).lean();
    if (!user?.location)
      return res.status(404).json({ error: "No location available" });

    res.json(user.location);
  } catch (err) {
    console.error("❌ /geo/approx error:", err);
    res.status(500).json({ error: "geo lookup failed" });
  }
});

/* ============================================================
   🌍 SECTION 2: GOOGLE PLACES MIDPOINT SUGGESTIONS
============================================================ */

router.get("/meet-suggest", authMiddleware, async (req, res) => {
  try {
    const me = req.user.id;
    const { otherId } = req.query;

    const [meUser, otherUser] = await Promise.all([
      User.findOne({ id: me }, { location: 1 }).lean(),
      User.findOne({ id: otherId }, { location: 1 }).lean(),
    ]);

    if (!meUser?.location || !otherUser?.location)
      return res.status(400).json({ error: "Missing user locations" });

    const mid = {
      lat: (meUser.location.lat + otherUser.location.lat) / 2,
      lng: (meUser.location.lng + otherUser.location.lng) / 2,
    };

    if (process.env.GOOGLE_MAPS_API_KEY) {
      const qs = new URLSearchParams({
        location: `${mid.lat},${mid.lng}`,
        radius: "4000",
        type: "cafe",
        key: process.env.GOOGLE_MAPS_API_KEY,
      });
      const resp = await fetch(
        `https://maps.googleapis.com/maps/api/place/nearbysearch/json?${qs}`
      );
      const data = await resp.json();
      (data.results || []).forEach((p) => {
        if (p.place_id)
          p.google_url = `https://www.google.com/maps/place/?q=place_id:${p.place_id}`;
      });
      return res.json({ midpoint: mid, places: data.results || [] });
    }

    // fallback demo list
    const demoPlaces = [
      {
        name: "Buzz Café",
        vicinity: "Central Plaza",
        rating: 4.6,
        google_url: `https://www.openstreetmap.org/#map=18/${mid.lat}/${mid.lng}`,
      },
      {
        name: "RomBuzz Park",
        vicinity: "Downtown",
        rating: 4.8,
        google_url: `https://www.openstreetmap.org/#map=18/${mid.lat}/${mid.lng}`,
      },
    ];

    res.json({ midpoint: mid, places: demoPlaces });
  } catch (err) {
    console.error("❌ meet-suggest error:", err);
    res.status(500).json({ error: "places_failed" });
  }
});

/* ============================================================
   🧭 SECTION 3: OVERPASS API MIDPOINT SUGGESTIONS
============================================================ */

router.post("/suggest", async (req, res) => {
  try {
    const { a, b } = req.body || {};
    if (!a || !b) {
      return res.status(400).json({ error: "Both coordinates (a & b) required" });
    }

    const midpoint = {
      lat: (Number(a.lat) + Number(b.lat)) / 2,
      lng: (Number(a.lng) + Number(b.lng)) / 2,
    };

    const radius = 1500;
    let places = [];

    const overpassQuery = `
      [out:json][timeout:25];
      (
        node["amenity"="cafe"](around:${radius},${midpoint.lat},${midpoint.lng});
        node["amenity"="restaurant"](around:${radius},${midpoint.lat},${midpoint.lng});
        node["leisure"="park"](around:${radius},${midpoint.lat},${midpoint.lng});
        node["amenity"="cinema"](around:${radius},${midpoint.lat},${midpoint.lng});
      );
      out center;
    `;
    const overpassURL = `https://overpass-api.de/api/interpreter?data=${encodeURIComponent(
      overpassQuery
    )}`;

    try {
      const response = await fetch(overpassURL, { timeout: 15000 });
      const data = await response.json();

      if (Array.isArray(data.elements)) {
        places = data.elements.slice(0, 15).map((p) => ({
          id: p.id,
          name:
            p.tags?.name ||
            p.tags?.brand ||
            `${p.tags?.amenity || p.tags?.leisure || "Place"} #${p.id}`,
          category: p.tags?.amenity || p.tags?.leisure || "venue",
          coords: { lat: p.lat, lng: p.lon },
          address:
            p.tags?.addr_full ||
            [p.tags?.addr_street, p.tags?.addr_city].filter(Boolean).join(", ") ||
            "Unknown",
        }));
      }
    } catch (err) {
      console.warn("⚠️ Overpass slow/unreachable:", err.message);
    }

    if (!places.length) {
      places = [
        {
          id: "midpoint-fallback",
          name: "Center Point Café",
          category: "cafe",
          coords: midpoint,
          address: "Approx. midpoint",
        },
      ];
    }

    res.json({ midpoint, places });
  } catch (err) {
    console.error("❌ /api/meet/suggest error:", err);
    res.status(500).json({ error: "Failed to fetch meet suggestions" });
  }
});

/* ============================================================
   🟢 SECTION 4: USER PRESENCE CHECK
============================================================ */

router.get("/presence/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const isOnline = !!global.onlineUsers?.[id];
    res.json({ online: isOnline });
  } catch (e) {
    console.error("Presence check failed:", e);
    res.status(500).json({ error: "presence lookup failed" });
  }
});

module.exports = router;
