/**
 * ============================================================
 * 📁 File: routes/premium.js
 * 💎 Purpose: Handles premium subscriptions, verification (KYC),
 *             and restricted-area consent logic for RomBuzz users.
 *
 * Endpoints:
 *   GET  /api/premium/status               → Get current premium & KYC state
 *   POST /api/premium/consent              → Record restricted-area consent
 *   POST /api/premium/upgrade              → Mock upgrade to Plus tier (dev)
 *   POST /api/premium/verify/upload-id     → Upload ID document metadata
 *   POST /api/premium/verify/upload-selfie → Upload selfie verification photo
 *   POST /api/premium/verify/auto-approve  → Dev-only auto-approval helper
 *
 * Features:
 *   - Tracks premium tiers (free / plus / gold / elite)
 *   - Tracks KYC state (unverified / submitted / verified / rejected)
 *   - Calculates age from DOB to prevent under-18 verification
 *   - Records consent hashes for restricted-region compliance
 *   - Mock endpoints ready to integrate with payment or KYC APIs later
 *
 * Dependencies:
 *   - models/User.js        → MongoDB user schema
 *   - authMiddleware.js     → JWT validation
 *
 * Notes:
 *   - Replace mock “upgrade” & “auto-approve” endpoints with:
 *       → Stripe / PayPal for billing
 *       → Onfido / Persona / Stripe Identity for real KYC
 * ============================================================
 */

const express = require("express");
const router = express.Router();
const authMiddleware = require("../routes/auth-middleware");
const User = require("../models/User");

/* ======================
   Helpers
====================== */
function calcAgeFromDob(dobStr) {
  const d = new Date(dobStr);
  if (Number.isNaN(d.getTime())) return -1;
  const today = new Date();
  let age = today.getFullYear() - d.getFullYear();
  const m = today.getMonth() - d.getMonth();
  if (m < 0 || (m === 0 && today.getDate() < d.getDate())) age--;
  return age;
}

/* ======================
   PREMIUM / VERIFICATION ROUTES
====================== */

// ✅ GET → Premium / KYC / Consent Status
router.get("/premium/status", authMiddleware, async (req, res) => {
  try {
    const u = await User.findOne({ id: req.user.id }).lean();
    if (!u) return res.status(404).json({ error: "not found" });

    res.json({
      premiumTier: u.premiumTier || "free",
      kycStatus: u.kycStatus || "unverified",
      consent: u.consent || {
        restrictedAccepted: false,
        at: 0,
        textHash: "",
      },
    });
  } catch (err) {
    console.error("❌ GET /premium/status error:", err);
    res.status(500).json({ error: "Failed to fetch premium status" });
  }
});

// ✅ POST → Accept restricted-area consent
router.post("/premium/consent", authMiddleware, async (req, res) => {
  try {
    const { textHash = "terms-restricted-v1" } = req.body || {};
    const u = await User.findOne({ id: req.user.id });
    if (!u) return res.status(404).json({ error: "not found" });

    u.consent = { restrictedAccepted: true, at: Date.now(), textHash };
    await u.save();

    res.json({ ok: true, consent: u.consent });
  } catch (err) {
    console.error("❌ POST /premium/consent error:", err);
    res.status(500).json({ error: "Failed to record consent" });
  }
});

// ✅ POST → Mock upgrade (dev only)
router.post("/premium/upgrade", authMiddleware, async (req, res) => {
  try {
    const u = await User.findOne({ id: req.user.id });
    if (!u) return res.status(404).json({ error: "not found" });

    u.premiumTier = "plus";
    await u.save();

    res.json({ ok: true, premiumTier: u.premiumTier });
  } catch (err) {
    console.error("❌ POST /premium/upgrade error:", err);
    res.status(500).json({ error: "Failed to upgrade premium" });
  }
});

// ✅ POST → Upload ID metadata
router.post("/premium/verify/upload-id", authMiddleware, async (req, res) => {
  try {
    const { idUrl = "", dob = "" } = req.body || {};
    if (!idUrl || !dob)
      return res.status(400).json({ error: "idUrl and dob required" });

    const u = await User.findOne({ id: req.user.id });
    if (!u) return res.status(404).json({ error: "not found" });

    u.kyc = u.kyc || {};
    u.kyc.idUrl = idUrl;
    u.kyc.dob = dob;
    u.kyc.submittedAt = Date.now();
    u.kycStatus = "submitted";
    await u.save();

    res.json({
      ok: true,
      kycStatus: u.kycStatus,
      kyc: { idUrl, dob },
    });
  } catch (err) {
    console.error("❌ POST /premium/verify/upload-id error:", err);
    res.status(500).json({ error: "Failed to upload ID metadata" });
  }
});

// ✅ POST → Upload selfie verification
router.post("/premium/verify/upload-selfie", authMiddleware, async (req, res) => {
  try {
    const { selfieUrl = "" } = req.body || {};
    if (!selfieUrl)
      return res.status(400).json({ error: "selfieUrl required" });

    const u = await User.findOne({ id: req.user.id });
    if (!u) return res.status(404).json({ error: "not found" });

    u.kyc = u.kyc || {};
    u.kyc.selfieUrl = selfieUrl;
    u.kyc.selfieAt = Date.now();
    if (u.kycStatus === "unverified") u.kycStatus = "submitted";
    await u.save();

    res.json({
      ok: true,
      kycStatus: u.kycStatus,
      kyc: { selfieUrl },
    });
  } catch (err) {
    console.error("❌ POST /premium/verify/upload-selfie error:", err);
    res.status(500).json({ error: "Failed to upload selfie" });
  }
});

// ✅ POST → Auto-approve (dev-only)
router.post("/premium/verify/auto-approve", authMiddleware, async (req, res) => {
  try {
    const u = await User.findOne({ id: req.user.id });
    if (!u) return res.status(404).json({ error: "not found" });

    const dob = u?.kyc?.dob;
    const idUrl = u?.kyc?.idUrl;
    const selfieUrl = u?.kyc?.selfieUrl;

    if (!dob || !idUrl || !selfieUrl) {
      return res.status(400).json({
        error: "missing_documents",
        require: {
          dob: !!dob,
          idUrl: !!idUrl,
          selfieUrl: !!selfieUrl,
        },
      });
    }

    const age = calcAgeFromDob(dob);
    if (age < 0) return res.status(400).json({ error: "invalid_dob" });
    if (age < 18) {
      u.kycStatus = "rejected_minor";
      await u.save();
      return res.status(403).json({
        error: "underage",
        age,
        kycStatus: u.kycStatus,
      });
    }

    u.kycStatus = "verified";
    await u.save();

    res.json({ ok: true, kycStatus: u.kycStatus, age });
  } catch (err) {
    console.error("❌ POST /premium/verify/auto-approve error:", err);
    res.status(500).json({ error: "Failed to auto-approve KYC" });
  }
});

module.exports = router;
