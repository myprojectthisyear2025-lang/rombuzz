// src/pages/settings/index.js  (a.k.a. Account page)
import React, { useEffect, useMemo, useState } from "react";

const API_BASE = "http://localhost:4000/api";
const token = () => localStorage.getItem("token") || sessionStorage.getItem("token") || "";

function msToDays(ms) {
  return Math.max(0, Math.ceil(ms / (24*60*60*1000)));
}

export default function Account() {
  const [loading, setLoading] = useState(true);
  const [me, setMe] = useState(null);
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName]   = useState("");
  const [email, setEmail]         = useState("");

  // name cooldown
  const [nameChangedAt, setNameChangedAt] = useState(0);
  const [saveBusy, setSaveBusy] = useState(false);

  // email change 2-step
  const [newEmail, setNewEmail]   = useState("");
  const [code, setCode]           = useState("");
  const [emailStep, setEmailStep] = useState(1); // 1: enter & send code, 2: enter code & confirm
  const [emailBusy, setEmailBusy] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const r = await fetch(`${API_BASE}/users/me`, {
          headers: { Authorization: `Bearer ${token()}` },
        });
        const u = await r.json();
        setMe(u);
        setFirstName(u.firstName || "");
        setLastName(u.lastName || "");
        setEmail(u.email || "");
        setNameChangedAt(Number(u.nameChangedAt || 0));
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const now = Date.now();
  const canChangeName = useMemo(() => {
    if (!nameChangedAt) return true;
    const THIRTY_DAYS = 30 * 24 * 60 * 60 * 1000;
    return now - nameChangedAt >= THIRTY_DAYS;
  }, [nameChangedAt, now]);

  const daysLeft = useMemo(() => {
    const THIRTY_DAYS = 30 * 24 * 60 * 60 * 1000;
    if (!nameChangedAt) return 0;
    const diff = THIRTY_DAYS - (now - nameChangedAt);
    return diff > 0 ? msToDays(diff) : 0;
  }, [nameChangedAt, now]);

  const saveName = async () => {
    if (!canChangeName) {
      alert(`You can change your name again in ${daysLeft} day(s).`);
      return;
    }
    setSaveBusy(true);
    try {
      const resp = await fetch(`${API_BASE}/users/me`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token()}`,
        },
        body: JSON.stringify({ firstName, lastName }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        alert(data.error || "Failed to save name");
        return;
      }
      // server stamps nameChangedAt; refresh
      setNameChangedAt(Date.now());
      setMe((m) => ({ ...m, firstName, lastName }));
      // also update local storage user for navbar, etc.
      try {
        const authMe = await fetch(`${API_BASE}/auth/me`, {
          headers: { Authorization: `Bearer ${token()}` },
        }).then((r) => r.json());
        if (authMe?.user) {
          localStorage.setItem("user", JSON.stringify(authMe.user));
        }
      } catch {}
      alert("Name updated ✅");
    } catch (e) {
      console.error(e);
      alert("Could not save name");
    } finally {
      setSaveBusy(false);
    }
  };

  const sendEmailCode = async () => {
    if (!newEmail.trim()) {
      alert("Enter a new email first");
      return;
    }
    setEmailBusy(true);
    try {
      const r = await fetch(`${API_BASE}/account/request-email-change`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token()}`,
        },
        body: JSON.stringify({ newEmail: newEmail.trim() }),
      });
      const data = await r.json();
      if (!r.ok) {
        alert(data.error || "Failed to send code");
        return;
      }
      setEmailStep(2);
      alert("We sent a code to your new email. Check your inbox.");
    } catch (e) {
      console.error(e);
      alert("Failed to send code");
    } finally {
      setEmailBusy(false);
    }
  };

  const confirmEmailChange = async () => {
    if (!code.trim()) {
      alert("Enter the 6-digit code");
      return;
    }
    setEmailBusy(true);
    try {
      const r = await fetch(`${API_BASE}/account/confirm-email-change`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token()}`,
        },
        body: JSON.stringify({ code: code.trim() }),
      });
      const data = await r.json();
      if (!r.ok) {
        alert(data.error || "Invalid or expired code");
        return;
      }
      setEmail(data.email || newEmail.trim());
      setNewEmail("");
      setCode("");
      setEmailStep(1);

      // refresh cached user (navbar, etc.)
      try {
        const authMe = await fetch(`${API_BASE}/auth/me`, {
          headers: { Authorization: `Bearer ${token()}` },
        }).then((r) => r.json());
        if (authMe?.user) {
          localStorage.setItem("user", JSON.stringify(authMe.user));
        }
      } catch {}

      alert("Email updated ✅");
    } catch (e) {
      console.error(e);
      alert("Failed to confirm email change");
    } finally {
      setEmailBusy(false);
    }
  };

  if (loading) return <div>Loading…</div>;

  return (
    <div className="space-y-6">
      <div className="p-4 rounded-2xl bg-white/90 border shadow-sm">
        <div className="text-lg font-semibold text-gray-800 mb-1">Basic account information</div>
        <div className="text-xs text-gray-500 mb-4">Update your name and email.</div>

        {/* Name row */}
        <div className="grid gap-3 md:grid-cols-2">
          <div>
            <label className="block text-sm text-gray-700 mb-1">First name</label>
            <input
              className="w-full border rounded-lg px-3 py-2"
              value={firstName}
              onChange={(e) => setFirstName(e.target.value)}
              disabled={!canChangeName}
            />
          </div>
          <div>
            <label className="block text-sm text-gray-700 mb-1">Last name</label>
            <input
              className="w-full border rounded-lg px-3 py-2"
              value={lastName}
              onChange={(e) => setLastName(e.target.value)}
              disabled={!canChangeName}
            />
          </div>
        </div>

        {!canChangeName ? (
          <div className="mt-2 text-xs text-rose-600">
            You can change your name again in <b>{daysLeft}</b> day(s).
          </div>
        ) : null}

        <div className="mt-3">
          <button
            className="px-4 py-2 rounded-full bg-rose-600 text-white disabled:opacity-60"
            onClick={saveName}
            disabled={saveBusy || !canChangeName}
          >
            {saveBusy ? "Saving…" : "Save name"}
          </button>
        </div>
      </div>

      {/* Email change (2-step) */}
      <div className="p-4 rounded-2xl bg-white/90 border shadow-sm">
        <div className="text-lg font-semibold text-gray-800 mb-1">Email</div>
        <div className="text-sm text-gray-600">Current: <b>{email}</b></div>

        {emailStep === 1 && (
          <div className="mt-4 grid gap-3 md:grid-cols-[1fr_auto]">
            <div>
              <label className="block text-sm text-gray-700 mb-1">New email</label>
              <input
                type="email"
                className="w-full border rounded-lg px-3 py-2"
                placeholder="name@example.com"
                value={newEmail}
                onChange={(e) => setNewEmail(e.target.value)}
              />
            </div>
            <div className="flex items-end">
              <button
                className="px-4 py-2 rounded-full bg-rose-600 text-white disabled:opacity-60"
                onClick={sendEmailCode}
                disabled={emailBusy || !newEmail}
              >
                {emailBusy ? "Sending..." : "Send code"}
              </button>
            </div>
          </div>
        )}

        {emailStep === 2 && (
          <div className="mt-4 grid gap-3 md:grid-cols-[1fr_auto]">
            <div>
              <label className="block text-sm text-gray-700 mb-1">Enter code</label>
              <input
                className="w-full border rounded-lg px-3 py-2"
                placeholder="6-digit code"
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
              <div className="text-xs text-gray-500 mt-1">
                We sent the code to <b>{newEmail}</b>. It expires in 10 minutes.
              </div>
            </div>
            <div className="flex items-end gap-2">
              <button
                className="px-4 py-2 rounded-full bg-rose-600 text-white disabled:opacity-60"
                onClick={confirmEmailChange}
                disabled={emailBusy || !code}
              >
                {emailBusy ? "Confirming..." : "Confirm email"}
              </button>
              <button
                className="px-4 py-2 rounded-full border"
                onClick={() => { setEmailStep(1); setCode(""); }}
                disabled={emailBusy}
              >
                Back
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Phone (optional box you mentioned) */}
      <div className="p-4 rounded-2xl bg-white/90 border shadow-sm">
        <div className="text-lg font-semibold text-gray-800 mb-1">Phone (optional)</div>
        <div className="text-xs text-gray-500 mb-3">We won’t show your phone on your profile.</div>
        <PhoneEditor me={me} />
      </div>
    </div>
  );
}

function PhoneEditor({ me }) {
  const [val, setVal] = useState(me?.phone || "");
  const [busy, setBusy] = useState(false);

  const save = async () => {
    setBusy(true);
    try {
      const r = await fetch(`${API_BASE}/users/me`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token()}`,
        },
        body: JSON.stringify({ phone: val }),
      });
      const data = await r.json();
      if (!r.ok) {
        alert(data.error || "Failed to save phone");
        return;
      }
      alert("Phone saved ✅");
    } catch (e) {
      console.error(e);
      alert("Could not save phone");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid gap-3 md:grid-cols-[1fr_auto]">
      <input
        className="w-full border rounded-lg px-3 py-2"
        placeholder="+1 555 123 4567"
        value={val}
        onChange={(e) => setVal(e.target.value)}
      />
      <button
        className="px-4 py-2 rounded-full bg-rose-600 text-white disabled:opacity-60"
        onClick={save}
        disabled={busy}
      >
        {busy ? "Saving…" : "Save phone"}
      </button>
    </div>
  );
}
