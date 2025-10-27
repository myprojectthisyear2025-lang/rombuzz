// src/components/PremiumFilters.jsx
import React, { useState } from "react";

export default function PremiumFilters({ setPremiumOpen, loadDiscover }) {
  const [filters, setFilters] = useState({
    verified: "",
    zodiac: "",
    love: "",
  });

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white rounded-2xl shadow-xl p-6 w-full max-w-md">
        <h3 className="text-xl font-semibold mb-4">
          💎 Premium Filters (AI Wingman)
        </h3>

        <div className="space-y-3">
          <div>
            <label>Compatibility Score</label>
            <select className="border rounded w-full p-2" disabled>
              <option>Coming Soon — AI Wingman</option>
            </select>
          </div>

          <div>
            <label>Zodiac Match</label>
            <select
              value={filters.zodiac}
              onChange={(e) =>
                setFilters((p) => ({ ...p, zodiac: e.target.value }))
              }
              className="border rounded w-full p-2"
            >
              <option value="">Any</option>
              <option value="aries">Aries</option>
              <option value="leo">Leo</option>
              <option value="virgo">Virgo</option>
              <option value="libra">Libra</option>
              <option value="scorpio">Scorpio</option>
              <option value="sagittarius">Sagittarius</option>
              <option value="capricorn">Capricorn</option>
              <option value="aquarius">Aquarius</option>
              <option value="pisces">Pisces</option>
            </select>
          </div>

          <div>
            <label>Love Language</label>
            <select
              value={filters.love}
              onChange={(e) =>
                setFilters((p) => ({ ...p, love: e.target.value }))
              }
              className="border rounded w-full p-2"
            >
              <option value="">Any</option>
              <option value="touch">Physical Touch</option>
              <option value="words">Words of Affirmation</option>
              <option value="acts">Acts of Service</option>
              <option value="time">Quality Time</option>
              <option value="gifts">Gifts</option>
            </select>
          </div>

          <div>
            <label>Verified Profiles Only</label>
            <select
              value={filters.verified}
              onChange={(e) =>
                setFilters((p) => ({ ...p, verified: e.target.value }))
              }
              className="border rounded w-full p-2"
            >
              <option value="">Any</option>
              <option value="true">Verified Only ✅</option>
            </select>
          </div>
        </div>

        <div className="mt-6 flex justify-end gap-3">
          <button
            onClick={() => setPremiumOpen(false)}
            className="border rounded px-4 py-2"
          >
            Cancel
          </button>
          <button
            onClick={() => {
              setPremiumOpen(false);
              loadDiscover(filters);
            }}
            className="bg-gradient-to-r from-pink-500 to-red-500 text-white rounded px-4 py-2"
          >
            Apply
          </button>
        </div>
      </div>
    </div>
  );
}
