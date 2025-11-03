// frontend/src/pages/DeleteAccount.jsx
import React, { useEffect, useState } from "react";


//const API_BASE = "http://localhost:4000/api";
const API_BASE = process.env.REACT_APP_API_BASE || "https://rombuzz-api.onrender.com/api";

const token = () =>
  localStorage.getItem("token") ||
  sessionStorage.getItem("token") ||
  "";

export default function DeleteAccount() {
  const [user, setUser] = useState(null);
  const [password, setPassword] = useState("");
  const [pending, setPending] = useState(false);

  // ----------------------------
  // Load current user
  // ----------------------------
  const load = async () => {
    const t = token();
    if (!t) return;
    try {
      const r = await fetch(`${API_BASE}/profile/full`, {
        headers: { Authorization: `Bearer ${t}` },
      });
      const j = await r.json();
      setUser(j.user || null);
    } catch {
      setUser(null);
    }
  };

  useEffect(() => {
    load();
  }, []);

  // ----------------------------
  // 🔒 Deactivate account
  // ----------------------------
  const handleDeactivate = async () => {
    const t = token();
    if (!t) return alert("Login required");

    if (!window.confirm("Are you sure you want to deactivate your account?"))
      return;

    try {
      const res = await fetch(`${API_BASE}/account/deactivate`, {
        method: "PATCH",
        headers: { Authorization: `Bearer ${t}` },
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to deactivate");

      alert(
        "Your account has been deactivated. You can reactivate anytime by logging in again."
      );
      localStorage.clear();
      sessionStorage.clear();
      window.location.href = "/";
    } catch (err) {
      console.error(err);
      alert("Could not deactivate account.");
    }
  };

  // ----------------------------
  // 🗑️ Permanently delete account
  // ----------------------------
 // 🗑️ Permanently delete account
const handleDelete = async () => {
  const t = token();
  if (!t) return alert("Login required");

  if (
    !window.confirm(
      "⚠️ This will permanently delete your account and all data. Continue?"
    )
  )
    return;

  try {
    const res = await fetch(`${API_BASE}/account/delete`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${t}` },
    });

    // ✅ FIX: Read response once and parse as JSON
    const responseText = await res.text();
    console.log("🔍 DELETE RESPONSE:", res.status, responseText);
    
    let data;
    try {
      data = JSON.parse(responseText);
    } catch (parseError) {
      console.error("JSON parse error:", parseError);
      throw new Error("Invalid server response from server");
    }

    if (!res.ok) throw new Error(data.error || "Failed to delete");

    alert("Your account has been permanently deleted.");
    localStorage.clear();
    sessionStorage.clear();
    window.location.href = "/signup";

  } catch (err) {
    console.error("Delete error:", err);
    alert("Could not delete account: " + err.message);
  }
};

  // ----------------------------
  // ♻️ Auto-reactivate on login
  // (in case user logs in after deactivation)
  // ----------------------------
  useEffect(() => {
    const reactivateIfNeeded = async () => {
      const t = token();
      if (!t) return;
      try {
        const r = await fetch(`${API_BASE}/profile/full`, {
          headers: { Authorization: `Bearer ${t}` },
        });
        const j = await r.json();
        const u = j.user;
        if (u && u.visibility === "deactivated") {
          await fetch(`${API_BASE}/users/me`, {
            method: "PUT",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${t}`,
            },
            body: JSON.stringify({ visibility: "active" }),
          });
          console.log("✅ Auto-reactivated account");
        }
      } catch (e) {
        console.error("Reactivate check failed:", e);
      }
    };
    reactivateIfNeeded();
  }, []);

  // ----------------------------
  // UI
  // ----------------------------
  return (
    <div className="max-w-lg mx-auto mt-8 p-6 bg-white border rounded-2xl shadow">
      <h2 className="text-xl font-semibold mb-1">Manage Account</h2>
      <p className="text-sm text-gray-600 mb-6">
        You can temporarily deactivate your account or permanently delete it
        (this removes your data entirely).
      </p>

      {/* Deactivate section */}
      <div className="p-4 border rounded-xl bg-gray-50 mb-4">
        <div className="font-medium mb-1">Deactivate Account</div>
        <p className="text-sm text-gray-600">
          Your profile won’t be visible in Discover. You can reactivate anytime
          by logging in again.
        </p>
        <button
          onClick={handleDeactivate}
          className="mt-3 px-4 py-2 rounded bg-yellow-100 hover:bg-yellow-200 text-yellow-800 font-medium"
        >
          Deactivate
        </button>
      </div>

      {/* Delete section */}
      <div className="p-4 border rounded-xl bg-red-50">
        <div className="font-medium text-red-700 mb-1">
          Permanently Delete Account
        </div>
        <p className="text-sm text-red-700 mb-2">
          This will permanently remove your account, photos, matches, and chat
          history. This action cannot be undone.
        </p>

        <div className="grid gap-2 max-w-sm">
          <input
            type="password"
            className="border rounded px-3 py-2"
            placeholder="Confirm your password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <button
            onClick={handleDelete}
            className="px-4 py-2 rounded bg-red-600 hover:bg-red-700 text-white font-medium"
          >
            Delete Account
          </button>
        </div>
      </div>
    </div>
  );
}
