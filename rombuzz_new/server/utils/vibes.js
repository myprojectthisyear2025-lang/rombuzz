/**
 * ================================================================
 * 📁 File: utils/vibes.js
 * 💫 Purpose:
 *   Centralized vibe-level filtering, access gating, and premium safety logic.
 *
 *   Handles which "vibes" (relationship modes) are visible or usable
 *   for users depending on privacy flags, premium tiers, and KYC verification.
 *
 * 🔍 Overview:
 *   - Defines the full set of public, private, and restricted vibes.
 *   - Provides utilities to validate, check premium tiers, and enforce consent.
 *   - Used in routes like `discover.js`, `users.js`, and `profile.js`.
 *
 * 🧠 Design Notes:
 *   - Environment flags (SHOW_PRIVATE, SHOW_RESTRICTED) are passed in at runtime.
 *   - Keeps all vibe-related logic consistent across backend modules.
 *
 *   © 2025 RomBuzz (Neptrixx Technologies)
 * ================================================================
 */

// ============================================================
// 💫 Vibe Category Definitions
// ============================================================
const PUBLIC_VIBES = new Set(["serious", "casual", "friends", "gymbuddy"]);
const PRIVATE_VIBES = new Set(["flirty", "chill", "timepass"]);
const RESTRICTED_VIBES = new Set(["ons", "threesome", "onlyfans"]);

// ============================================================
// 🧩 Validation Utilities
// ============================================================

/**
 * ✅ isAllowedVibeKey(v, SHOW_PRIVATE, SHOW_RESTRICTED)
 * Checks whether a given vibe is valid under the current feature flags.
 */
function isAllowedVibeKey(v, SHOW_PRIVATE, SHOW_RESTRICTED) {
  v = String(v || "").toLowerCase();
  return (
    PUBLIC_VIBES.has(v) ||
    (SHOW_PRIVATE && PRIVATE_VIBES.has(v)) ||
    (SHOW_RESTRICTED && RESTRICTED_VIBES.has(v))
  );
}

/**
 * 🔒 isRestricted(v)
 * Returns true if the vibe belongs to the restricted (explicit) category.
 */
function isRestricted(v) {
  return RESTRICTED_VIBES.has(String(v || "").toLowerCase());
}

// ============================================================
// 💎 Premium & Verification Checks
// ============================================================

/**
 * 💎 hasPremium(u)
 * Returns true if user has "plus" or "pro" subscription.
 */
function hasPremium(u) {
  return u && (u.premiumTier === "plus" || u.premiumTier === "pro");
}

/**
 * ✅ isAgeVerified(u)
 * Returns true if user completed KYC and age verification.
 */
function isAgeVerified(u) {
  return u && u.kycStatus === "verified";
}

/**
 * 🔞 canUseRestricted(u, SHOW_RESTRICTED)
 * Determines if user has access to restricted vibes.
 * Requires SHOW_RESTRICTED flag, premium status, age verification,
 * and explicit consent acceptance.
 */
function canUseRestricted(u, SHOW_RESTRICTED) {
  return (
    SHOW_RESTRICTED &&
    hasPremium(u) &&
    isAgeVerified(u) &&
    u?.consent?.restrictedAccepted
  );
}

// ============================================================
// 📦 Exports
// ============================================================
module.exports = {
  PUBLIC_VIBES,
  PRIVATE_VIBES,
  RESTRICTED_VIBES,
  isAllowedVibeKey,
  isRestricted,
  hasPremium,
  isAgeVerified,
  canUseRestricted,
};
