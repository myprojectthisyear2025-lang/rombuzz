/**
 * ============================================================
 * 📁 File: routes/auth/password.js
 * 🧩 Handles forgot-password and reset-password (Mongo only)
 * ============================================================
 */
const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const sgMail = require("../../config/sendgrid");
const User = require("../../models/User");
const PasswordReset = require("../../models/PasswordReset");

// =======================
// FORGOT PASSWORD — Send reset code
// =======================
router.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: "Email is required" });

    const emailLower = String(email).trim().toLowerCase();
    const user = await User.findOne({ email: emailLower }).lean();
    if (!user) return res.status(404).json({ error: "No user found with that email" });

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await PasswordReset.findOneAndUpdate(
      { email: emailLower },
      { code, expiresAt },
      { upsert: true, new: true }
    );

    if (!process.env.SENDGRID_API_KEY) {
      console.log(`📧 [DEV] Reset code for ${emailLower}: ${code}`);
      return res.json({ success: true, dev: true });
    }

    const msg = {
      to: emailLower,
      from: process.env.FROM_EMAIL || "myprojectthisyear2025@gmail.com",
      subject: "RomBuzz Password Reset Code",
      text: `Your RomBuzz reset code is ${code}. It expires in 10 minutes.`,
      html: `<p>Your RomBuzz reset code is <strong>${code}</strong>. It expires in 10 minutes.</p>`,
    };

    await sgMail.send(msg);
    console.log("📧 Sent password reset code to", emailLower);
    res.json({ success: true });
  } catch (err) {
    console.error("❌ forgot-password error:", err);
    res.status(500).json({ error: "Failed to send reset code" });
  }
});

// =======================
// RESET PASSWORD — Verify + update
// =======================
router.post("/reset-password", async (req, res) => {
  try {
    const { email, code, newPassword } = req.body || {};
    if (!email || !code || !newPassword)
      return res.status(400).json({ error: "Email, code, and new password required" });

    const emailLower = String(email).trim().toLowerCase();
    const record = await PasswordReset.findOne({ email: emailLower }).lean();
    if (!record) return res.status(400).json({ error: "No reset request found" });
    if (record.expiresAt < new Date()) return res.status(400).json({ error: "Code expired" });
    if (record.code !== code) return res.status(400).json({ error: "Invalid code" });

    const user = await User.findOne({ email: emailLower });
    if (!user) return res.status(404).json({ error: "User not found" });

    user.passwordHash = await bcrypt.hash(newPassword, 10);
    await user.save();
    await PasswordReset.deleteOne({ email: emailLower });

    res.json({ success: true, message: "Password reset successful" });
  } catch (err) {
    console.error("❌ reset-password error:", err);
    res.status(500).json({ error: "Failed to reset password" });
  }
});

console.log("✅ Auth: Password routes initialized");
module.exports = router;
