// ✅ src/components/BuzzStreak.jsx
import React, { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";

const API_BASE = "http://localhost:4000/api";

export default function BuzzStreak() {
  const [streak, setStreak] = useState({ count: 0 });
  const [checkedToday, setCheckedToday] = useState(false);
  const [loading, setLoading] = useState(true);
  const [showConfetti, setShowConfetti] = useState(false);
  const [showRewards, setShowRewards] = useState(false);

  const token =
    localStorage.getItem("token") || sessionStorage.getItem("token");

  // 🕓 Fetch streak
  useEffect(() => {
    if (!token) return;
    fetch(`${API_BASE}/streak/get`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((r) => r.json())
      .then((data) => {
        setStreak(data.streak || { count: 0 });
        setCheckedToday(data.checkedToday || false);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [token]);

  // 🔘 Daily check-in
  const handleCheckIn = async () => {
    if (checkedToday || !token) return;
    try {
      const r = await fetch(`${API_BASE}/streak/checkin`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
      });
      if (!r.ok) return;
      const data = await r.json();
      setStreak(data.streak || { count: 0 });
      setCheckedToday(true);
      setShowConfetti(true);
      setTimeout(() => setShowConfetti(false), 1500);
    } catch (err) {
      console.error("Check-in failed", err);
    }
  };

  // 🎉 Confetti
  const Confetti = () => (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: [1, 1, 0], y: [-10, -40, -80] }}
      transition={{ duration: 1.2 }}
      className="absolute top-0 left-1/2 transform -translate-x-1/2 text-3xl select-none"
    >
      ✨🔥✨
    </motion.div>
  );

  if (loading) return null;

  const progressPercent = Math.min((streak.count % 7) * (100 / 7), 100);
  const daysLeft = 7 - (streak.count % 7 || 7);

  return (
  <motion.div
    className="relative bg-gradient-to-r from-pink-500 to-purple-600 text-white 
    rounded-2xl p-6 mt-5 shadow-xl w-full max-w-[640px] mx-auto"
    initial={{ opacity: 0, y: 10 }}
    animate={{ opacity: 1, y: 0 }}
  >

      {showConfetti && <Confetti />}

      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h3 className="font-bold text-xl flex items-center gap-2">
            🔥 BuzzStreak
          </h3>
          <p className="text-sm opacity-90">Day {streak.count || 0}</p>
        </div>

        <button
          onClick={() => setShowRewards((p) => !p)}
          className="text-white/80 hover:text-white text-xl px-2"
          title="View rewards"
        >
          ⋯
        </button>
      </div>

      {/* Progress bar */}
      <div className="w-full bg-white/30 rounded-full h-3 mt-4 overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${progressPercent}%` }}
          transition={{ duration: 0.8 }}
          className="h-3 bg-white rounded-full"
        />
      </div>

      {/* Message */}
      <p className="text-xs mt-3 opacity-90">
        {streak.count > 0
          ? daysLeft === 0
            ? "🎉 You’ve hit a 7-day streak! Reward coming soon."
            : `🔥 ${daysLeft} day${daysLeft !== 1 ? "s" : ""} to your next milestone`
          : "Tap to start your BuzzStreak 🔥"}
      </p>

      {/* Check-in button */}
      <button
        onClick={handleCheckIn}
        disabled={checkedToday}
        className={`mt-4 w-full font-semibold py-2 rounded-xl shadow-md transition text-sm ${
          checkedToday
            ? "bg-white/40 text-gray-200 cursor-not-allowed"
            : "bg-white text-pink-600 hover:bg-pink-100"
        }`}
      >
        {checkedToday ? "✅ Checked In" : "Check In Today"}
      </button>

      {/* Rewards inside 3-dot only */}
      <AnimatePresence>
        {showRewards && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.4 }}
            className="mt-4 bg-white/20 rounded-2xl p-3 text-left text-xs backdrop-blur-sm overflow-hidden"
          >
            <div className="font-semibold mb-1 text-white/90">
              Upcoming Buzz Rewards
            </div>
            <ul className="space-y-1 text-white/90">
              <li>Day 1 - 🎉 Welcome back! Confetti</li>
              <li>Day 3 - ✨ Avatar Glow for 24h</li>
              <li>Day 7 - ⚡ 1-Day Discover Boost</li>
              <li>Day 14 - 🏅 BuzzChampion Badge</li>
              <li>Day 30 - 💖 LoyalHeart Title</li>
              <li>Day 50 - 🌈 Premium Trial / Wingman Bonus</li>
            </ul>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
