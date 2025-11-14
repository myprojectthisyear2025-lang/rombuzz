/**
 * ============================================================
 * 📁 File: routes/meetSuggest.js
 * 🧭 Purpose: Handle “Meet-in-Middle” location suggestions.
 *
 * This route computes the midpoint between two users and
 * fetches nearby venues (cafés, restaurants, parks, cinemas)
 * using the OpenStreetMap Overpass API.
 *
 * ✅ Endpoint:
 *    POST /api/meet/suggest
 * 
 * ✅ Request body:
 *    {
 *      "a": { "lat": <number>, "lng": <number> },
 *      "b": { "lat": <number>, "lng": <number> }
 *    }
 *
 * ✅ Response:
 *    {
 *      "midpoint": { "lat": <number>, "lng": <number> },
 *      "places": [
 *        {
 *          "id": "node12345",
 *          "name": "Coffee House",
 *          "category": "cafe",
 *          "coords": { "lat": ..., "lng": ... },
 *          "address": "Street, City"
 *        },
 *        ...
 *      ]
 *    }
 *
 * 🧩 Features:
 *   - Calculates midpoint between two users
 *   - Queries Overpass API for nearby public meeting spots
 *   - Provides graceful fallback if API fails
 *   - Returns up to 15 results (filtered + normalized)
 *   - Fully stateless — no DB reads/writes
 *
 * 🧱 Dependencies:
 *   - node-fetch (ESM-safe import)
 *   - express
 *
 * 🧠 Used in:
 *   - Meet-in-Middle feature (Frontend map suggestion modal)
 *
 * ============================================================
 */

const express = require("express");
const router = express.Router();

// ✅ ESM-safe fetch wrapper (works with CommonJS)
const fetch = (...args) =>
  import("node-fetch").then(({ default: fetch }) => fetch(...args));

/* ============================================================
   📍 POST /api/meet/suggest
   ------------------------------------------------------------
   Takes two location objects (a, b) and returns:
   - Midpoint between them
   - Suggested nearby venues within 1.5 km radius
   ------------------------------------------------------------
============================================================ */
router.post("/suggest", async (req, res) => {
  try {
    const { a, b } = req.body || {};

    // 🔒 Validate inputs
    if (!a || !b) {
      return res.status(400).json({ error: "Both coordinates (a & b) required" });
    }

    // 🎯 Compute midpoint between the two coordinates
    const midpoint = {
      lat: (Number(a.lat) + Number(b.lat)) / 2,
      lng: (Number(a.lng) + Number(b.lng)) / 2,
    };

    // Search radius (in meters)
    const radius = 1500;

    // Overpass API query for common social venues
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
    const overpassURL = `https://overpass-api.de/api/interpreter?data=${encodeURIComponent(overpassQuery)}`;

    let places = [];

    try {
      // 🌍 Query Overpass API
      const response = await fetch(overpassURL, { timeout: 15000 });
      const data = await response.json();

      // ✅ Parse and normalize results
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
      console.warn("⚠️ Overpass slow/unreachable, fallback triggered:", err.message);
    }

    // 🧩 Graceful fallback if Overpass failed or returned nothing
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

    // ✅ Respond with midpoint and place suggestions
    res.json({ midpoint, places });
  } catch (err) {
    console.error("❌ /api/meet/suggest error:", err);
    res.status(500).json({ error: "Failed to fetch meet suggestions" });
  }
});

module.exports = router;
