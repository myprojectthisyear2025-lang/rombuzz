/**
 * ============================================================
 * 📁 File: routes/auth/otp.js
 * 🧩 Handles OTP send & verification (hybrid Mongo + LowDB)
 * ============================================================
 */
const express = require("express");
const router = express.Router();
const db = require("../../models/db.lowdb");
const sgMail = require("../../config/sendgrid");
const shortid = require("shortid");
const bcrypt = require("bcrypt");
const { signToken } = require("../../utils/jwt");
const { JWT_SECRET, TOKEN_EXPIRES_IN } = require("../../config/env");
const { baseSanitizeUser } = require("../../utils/helpers");
const User = require("../../models/User");

// =======================
// SEND VERIFICATION CODE
// =======================
router.post("/send-code", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });
  const emailLower = String(email).trim().toLowerCase();
  const code = Math.floor(100000 + Math.random() * 900000).toString();

  try {
    let mongoUser = await User.findOne({ email: emailLower });
    if (mongoUser) {
      mongoUser.verificationCode = code;
      mongoUser.codeExpiresAt = new Date(Date.now() + 10 * 60 * 1000);
      await mongoUser.save();
      console.log(`📧 OTP saved in Mongo for ${emailLower}`);
    } else {
      await db.read();
      let lowUser = db.data.users.find((u) => u.email === emailLower);
      if (lowUser) lowUser.verificationCode = code;
      else
        db.data.users.push({
          id: shortid.generate(),
          email: emailLower,
          verificationCode: code,
          codeExpiresAt: Date.now() + 10 * 60 * 1000,
        });
      await db.write();
      console.log(`📧 OTP saved in LowDB for ${emailLower}`);
    }

    await sgMail.send({
      to: emailLower,
      from: process.env.SENDGRID_FROM || "noreply@rombuzz.com",
      subject: "Your RomBuzz verification code",
      text: `Your RomBuzz verification code is: ${code}`,
      html: `<p>Your RomBuzz verification code is <strong>${code}</strong>. It expires in 10 minutes.</p>`,
    });

    res.json({ success: true });
  } catch (err) {
    console.error("❌ send-code hybrid error:", err);
    res.status(500).json({ error: "Failed to send verification code" });
  }
});

// =======================
// VERIFY CODE + REGISTER USER
// =======================
router.post("/register", async (req, res) => {
  try {
    const { email, code, firstName, lastName, password } = req.body;
    if (!email || !code) {
      return res.status(400).json({ error: "Email and code required" });
    }

    const emailLower = String(email || "").trim().toLowerCase();

    let mongoUser = await User.findOne({ email: emailLower });
    if (mongoUser) {
      if (
        mongoUser.verificationCode !== code ||
        (mongoUser.codeExpiresAt && mongoUser.codeExpiresAt < new Date())
      ) {
        return res.status(400).json({ error: "Invalid or expired code" });
      }

      mongoUser.passwordHash = password ? await bcrypt.hash(password, 10) : "";
      mongoUser.verificationCode = null;
      mongoUser.codeExpiresAt = null;
      mongoUser.firstName = firstName || mongoUser.firstName;
      mongoUser.lastName = lastName || mongoUser.lastName;
      mongoUser.isVerified = true;
      mongoUser.createdAt ||= new Date();
      await mongoUser.save();

      const token = signToken({ id: mongoUser.id, email: mongoUser.email }, JWT_SECRET, TOKEN_EXPIRES_IN);
      return res.json({ token, user: baseSanitizeUser(mongoUser) });
    }

    // LowDB fallback
    await db.read();
    const lowUser = db.data.users.find((u) => (u.email || "").toLowerCase() === emailLower);
    if (!lowUser) return res.status(404).json({ error: "No signup request found" });
    if (lowUser.verificationCode !== code)
      return res.status(400).json({ error: "Invalid verification code" });

    const passwordHash = password ? await bcrypt.hash(password, 10) : "";
    const newUser = {
      id: shortid.generate(),
      email: emailLower,
      firstName,
      lastName,
      passwordHash,
      createdAt: new Date(),
      isVerified: true,
    };

    await User.create(newUser);
    db.data.users = db.data.users.filter((u) => (u.email || "").toLowerCase() !== emailLower);
    await db.write();

    const token = signToken({ id: newUser.id, email: newUser.email }, JWT_SECRET, TOKEN_EXPIRES_IN);
    res.json({ token, user: baseSanitizeUser(newUser) });
  } catch (err) {
    console.error("❌ /register hybrid error:", err);
    res.status(500).json({ error: "Server error verifying code" });
  }
});

console.log("✅ Auth: OTP routes initialized");
module.exports = router;
