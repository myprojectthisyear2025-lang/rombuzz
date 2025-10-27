import React, { useState } from "react";
const API_BASE = "http://localhost:4000/api";
const token = () => localStorage.getItem("token") || sessionStorage.getItem("token") || "";

export default function Security() {
  const [oldPw, setOldPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [twoFA, setTwoFA] = useState(false);

  const changePw = async () => {
    if (!newPw) return alert("Enter a new password");
    const r = await fetch(`${API_BASE}/auth/change-password`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token()}` },
      body: JSON.stringify({ oldPassword: oldPw, newPassword: newPw }),
    });
    const j = await r.json();
    if (!r.ok) return alert(j.error || "Failed");
    setOldPw(""); setNewPw("");
    alert("Password updated ✔");
  };

  return (
    <div>
      <h3 className="text-lg font-semibold">Security & Login</h3>
      <p className="text-sm text-gray-600 mb-4">Protect your account</p>

      <div className="grid gap-4 max-w-lg">
        <div className="grid gap-1">
          <span className="text-sm text-gray-700">Current password</span>
          <input className="border rounded px-3 py-2" type="password" value={oldPw} onChange={(e) => setOldPw(e.target.value)} />
        </div>
        <div className="grid gap-1">
          <span className="text-sm text-gray-700">New password</span>
          <input className="border rounded px-3 py-2" type="password" value={newPw} onChange={(e) => setNewPw(e.target.value)} />
        </div>
        <button onClick={changePw} className="w-max px-4 py-2 rounded bg-rose-500 text-white">Update password</button>

        <label className="flex items-center gap-2 mt-6">
          <input type="checkbox" checked={twoFA} onChange={(e) => setTwoFA(e.target.checked)} />
          <span className="text-sm text-gray-700">Enable 2-step verification (TOTP / SMS)</span>
        </label>
        <p className="text-xs text-gray-500">UI only. Hook to your 2FA backend if available.</p>
      </div>
    </div>
  );
}
