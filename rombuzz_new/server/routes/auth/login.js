/**
 * ============================================================
 * 📁 File: routes/auth/login.js
 * 🧩 Handles email/password login & Google OAuth hybrid flow.
 * ============================================================
 */
const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const shortid = require("shortid");
const { signToken } = require("../../utils/jwt");
const { JWT_SECRET, TOKEN_EXPIRES_IN } = require("../../config/env");
const { baseSanitizeUser } = require("../../utils/helpers");
const { googleClient } = require("../../config/config");
const User = require("../../models/User");

// =======================
// EMAIL / PASSWORD LOGIN
// =======================
router.post("/login", async (req, res) => {
  console.log("🟢 Login API hit with body:", req.body);

  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email & password required" });
  }

  const emailLower = String(email || "").trim().toLowerCase();
  const user = await User.findOne({ email: emailLower }).lean();
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  console.log("DEBUG LOGIN →", {
    email: emailLower,
    hasPasswordHash: !!user.passwordHash,
  });

  let match = false;
  try {
    if (user.passwordHash && user.passwordHash.length > 0) {
      match = await bcrypt.compare(password, user.passwordHash);
      console.log("🔐 Bcrypt comparison:", match);
    }
  } catch (err) {
    console.error("bcrypt compare error:", err);
  }

  if (!match) {
    console.warn("⚠️ Login failed for", emailLower);
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const token = signToken({ id: user.id, email: user.email }, JWT_SECRET, TOKEN_EXPIRES_IN);
  res.json({ token, user: baseSanitizeUser(user) });
});

// =======================
// GOOGLE LOGIN / SIGNUP
// =======================
router.post("/google", async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: "Google token required" });

  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const emailLower = String(payload.email || "").toLowerCase();

    // 🔍 Try Mongo first
    let user = await User.findOne({ email: emailLower }).lean();
    const isNew = !user;

    // 🆕 Create if not found
    if (isNew) {
      const newGoogleUser = {
        id: shortid.generate(),
        email: emailLower,
        firstName: payload.given_name || "",
        lastName: payload.family_name || "",
        avatar: payload.picture || "",
        passwordHash: "",
        createdAt: Date.now(),
        profileComplete: false,
        hasOnboarded: false,
        bio: "",
        dob: null,
        gender: "",
        location: null,
        visibility: "active",
        media: [],
        posts: [],
        interests: [],
        hobbies: [],
        favorites: [],
        visibilityMode: "auto",
        fieldVisibility: {
          age: "public",
          height: "public",
          city: "public",
          orientation: "public",
          interests: "public",
          hobbies: "public",
          likes: "public",
          dislikes: "public",
          lookingFor: "public",
          voiceIntro: "public",
          photos: "matches",
        },
      };
      await User.create(newGoogleUser);
      user = newGoogleUser;
    }

    const jwtToken = signToken({ id: user.id, email: user.email }, JWT_SECRET, TOKEN_EXPIRES_IN);
    const isProfileComplete = Boolean(user.profileComplete);

    if (isNew || !isProfileComplete) {
      console.log("🧩 Returning INCOMPLETE_PROFILE for:", user.email);
      return res.json({
        status: "incomplete_profile",
        token: jwtToken,
        user: baseSanitizeUser(user),
      });
    }

    console.log("🟢 Returning OK for:", user.email);
    res.json({
      status: "ok",
      token: jwtToken,
      user: baseSanitizeUser(user),
    });
  } catch (err) {
    console.error("❌ Google login failed:", err);
    res.status(401).json({ error: "Google login failed" });
  }
});

console.log("✅ Auth: Login + Google routes initialized");
module.exports = router;
