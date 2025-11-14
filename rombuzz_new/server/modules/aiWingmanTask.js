/**
 * ============================================================
 * 📁 File: modules/aiWingmanTask.js (MongoDB version)
 * 🤖 Purpose: Periodically send smart “AI Wingman” tips to users.
 * Runs automatically every 30 min, independent of API routes.
 *
 * Dependencies:
 *   - models/User.js (Mongoose)
 *   - sendNotification(), distanceKm()
 * ============================================================
 */

const User = require("../models/User");
const { sendNotification, distanceKm } = require("../utils/helpers");

function startAiWingmanTask() {
  setInterval(async () => {
    try {
      const users = await User.find({}, "id firstName email location interests hobbies").lean();
      if (!Array.isArray(users) || users.length < 2) return;

      // 🎯 Pick random target user
      const target = users[Math.floor(Math.random() * users.length)];
      if (!target?.location) return;

      // 🧭 Find nearby users within 10km
      const nearby = users.filter(
        (u) =>
          u.id !== target.id &&
          u.location &&
          distanceKm(u.location, target.location) < 10
      );

      let match = null;
      for (const u of nearby) {
        const sharedInterests = (target.interests || []).filter((i) =>
          (u.interests || []).includes(i)
        );
        const sharedHobbies = (target.hobbies || []).filter((h) =>
          (u.hobbies || []).includes(h)
        );
        if (sharedInterests.length || sharedHobbies.length) {
          match = { user: u, sharedInterests, sharedHobbies };
          break;
        }
      }

      // 💌 Compose AI Wingman message
      let message;
      if (match) {
        const name = match.user.firstName || "someone nearby";
        const common =
          match.sharedInterests[0] ||
          match.sharedHobbies[0] ||
          "similar vibes";
        message = `Wingman spotted ${name} nearby — you both love ${common}! 💞`;
      } else {
        const ideas = [
          "Wingman thinks your profile could use a fresh selfie 📸",
          "New people are buzzing in your area — go explore MicroBuzz 👀",
          "Add a voice intro to stand out 🎤",
          "Update your interests for better matches 💡",
        ];
        message = ideas[Math.floor(Math.random() * ideas.length)];
      }

      // 🚀 Send notification
      await sendNotification(target.id, {
        fromId: "system",
        type: "wingman",
        message,
        href: `/letsbuzz`,
      });

      console.log("🤖 Wingman tip →", target.firstName || target.email, message);
    } catch (err) {
      console.error("💥 AI Wingman task failed:", err.message || err);
    }
  }, 1000 * 60 * 30); // every 30 minutes
}

module.exports = { startAiWingmanTask };
