// =====================================================
// 💗 ROMBUZZ MAIN BACKEND ENTRY
// =====================================================
// Central API entry point for RomBuzz backend
// Handles all routes, middleware, and sockets.
// =====================================================

require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const http = require('http');
const shortid = require('shortid');
const sgMail = require('./config/sendgrid');
const upload = multer({ dest: 'uploads/' }); // ✅ used for avatar uploads fallback

// =======================
// 🪵 LOGGER (modularized)
// =======================
const { logInfo, logSuccess, logWarn, logError, logSocket } = require('./modules/logger');

// =======================
// ⚙️ GLOBAL CONFIG (Google + Feature Toggles)
// =======================
const { googleClient, FEATURE_TOGGLES } = require('./config/config');

// =======================
// 🌍 ENVIRONMENT CONFIG (centralized)
// =======================
const {
  PORT,
  JWT_SECRET,
  TOKEN_EXPIRES_IN,
  ADMIN_EMAIL,
  OBFUSCATION_MIN_METERS,
  OBFUSCATION_MAX_METERS,
  SHOW_PRIVATE,
  SHOW_RESTRICTED,
} = require('./config/env');

// ✅ ESM-safe fetch wrapper
const fetch = (...args) =>
  import('node-fetch').then(({ default: fetch }) => fetch(...args));

// =======================
// 🔐 JWT HELPER (modularized)
// =======================
const { signToken } = require('./utils/jwt');

// =======================
// 📦 DATABASE (modularized) — LowDB (legacy) + MongoDB init
// =======================
// 📦 DATABASE (modularized) — LowDB (legacy) + MongoDB init + User sync
const db = require("./models/db.lowdb");
require("./models/writeGuard")(db);
require("./modules/mongoInit").initMongo(); // ✅ non-blocking Mongo connection

// 🔄 Optional one-time user sync on startup
const { bulkSyncAllUsers } = require("./modules/userSync");
(async () => {
  try {
    await db.read();
    if (db.data?.users?.length) {
      await bulkSyncAllUsers(db.data.users);
    } else {
      console.log("⚙️  No users found in LowDB for sync");
    }
  } catch (err) {
    console.error("User bulk sync error:", err);
  }
})();

// =======================
// ☁️ CLOUDINARY CONFIG (modularized)
// =======================
const cloudinary = require('./config/cloudinary');

// =======================
// 💫 VIBE UTILITIES (modularized)
// =======================
const {
  PUBLIC_VIBES,
  PRIVATE_VIBES,
  RESTRICTED_VIBES,
  isAllowedVibeKey,
  isRestricted,
  hasPremium,
  isAgeVerified,
  canUseRestricted,
} = require('./utils/vibes');

// =======================
// 🧩 HELPER FUNCTIONS (modularized)
// =======================
const {
  baseSanitizeUser,
  isBlocked,
  msToDays,
  distanceKm,
  getRoomDoc,
  incMatchStreakOut,
  THIRTY_DAYS,
} = require('./utils/helpers');

// =======================
// 🔔 NOTIFICATION HELPERS (modularized)
// =======================
const { sendNotification, createNotification } = require('./utils/notifications');

// =======================
// 🔒 SECURITY & CORS CONFIG (modularized)
// =======================
const setupCors = require('./config/cors');
const { setupSecurity } = require('./config/security');

// =======================
// ⚡ SOCKET.IO SETUP (modularized)
// =======================
const { setupSocket } = require('./config/socket');
const { buzzLocks, onlineUsers } = require('./models/state');

// =======================
// 🧠 SOCKET CONNECTION HANDLER
// =======================
const { registerConnection } = require('./sockets/connection');

// =======================
// 🚀 EXPRESS APP INITIALIZATION
// =======================
const app = express();
const server = http.createServer(app);

// Middleware
setupCors(app);
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
setupSecurity(app);

// Socket.IO
const io = setupSocket(server);
registerConnection(io);

// =====================================================
// 📡 ROUTES (Modularized)
// =====================================================

// 🔐 AUTH & PROFILE
app.use('/api/auth', require('./routes/auth'));
app.use('/api', require('./routes/profile'));

// 👤 USERS & NOTIFICATIONS
app.use('/api/users', require('./routes/users'));
app.use('/api/notifications', require('./routes/notifications'));

// ⚙️ SETTINGS & ACCOUNT
app.use('/api/settings', require('./routes/settings'));
app.use('/api/account', require('./routes/account'));

// 📍 MICROBUZZ
app.use('/api/microbuzz', require('./routes/microbuzz'));

// 🐝 POSTS / LETSBUZZ
app.use('/api/posts', require('./routes/posts'));

// 🏠 FEED & UPLOADS
app.use('/api/feed', require('./routes/feed'));
app.use('/api', require('./routes/upload'));

// 📸 STORIES & PUBLIC PROFILES
app.use('/api/stories', require('./routes/stories'));
app.use('/api/users', require('./routes/publicProfile'));

// 🔍 DISCOVER
app.use('/api/discover', require('./routes/discover'));

// 💬 MESSAGES, MATCHES, SAFETY
app.use('/api/messages', require('./routes/messages'));
app.use('/api', require('./routes/likesMatches'));
app.use('/api', require('./routes/safety'));

// 🧠 AI WINGMAN & PREMIUM
app.use('/api', require('./routes/aiWingman'));
app.use('/api', require('./routes/premium'));

// 💬 CHAT ROOMS & SAFE MEET
app.use('/api', require('./routes/chatRooms'));
app.use('/api', require('./routes/meet'));

// 🧩 DEBUG ROUTES
app.use('/api', require('./routes/debug'));

// 🧩 ENHANCED LETSBUZZ POSTS SYSTEM
app.use('/api', require('./routes/buzzPosts'));
app.use('/api', require('./routes/buzzComments'));

// 💫 BUZZ STREAKS
app.use('/api', require('./routes/streak'));
logSuccess('✅ BuzzStreak routes initialized (match & daily check-in)');

// =======================
// 💓 HEALTH CHECK (modularized)
// =======================
app.use("/api", require("./modules/health"));
// =====================================================
// 🤖 BACKGROUND MODULES
// =====================================================
const { startAiWingmanTask } = require('./modules/aiWingmanTask');
startAiWingmanTask();

// 💞 Meet-in-Middle Sockets
const { registerMeetSockets } = require('./sockets/meetSocket');
registerMeetSockets(io);

// 🧾 System Startup Summary
const { logStartupSummary } = require('./modules/system');
logStartupSummary({ PORT, FEATURE_TOGGLES });

// =======================
// 🛡️ GLOBAL ERROR HANDLER
// =======================
const { errorHandler } = require("./modules/errorHandler");
app.use(errorHandler);

// =====================================================
// 🏁 START SERVER
// =====================================================
server.listen(PORT, () => {
logSuccess(`✅ Rombuzz API running on port ${PORT}`);
});
