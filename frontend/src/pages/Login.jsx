// src/pages/Login.jsx
import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import logo from "../assets/logo.png"; // ensure path is correct
import { GoogleLogin } from "@react-oauth/google";
import axios from "axios";

//const API_BASE = "http://localhost:4000/api";
const API_BASE = process.env.REACT_APP_API_BASE || "https://rombuzz-api.onrender.com/api";

const CLIENT_ID =
  process.env.REACT_APP_GOOGLE_CLIENT_ID
 || "579443399527-3q3lpblalkiqces1d0etdgjfj301b75l.apps.googleusercontent.com";
const Login = ({ setUser }) => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [showReset, setShowReset] = useState(false);
  const [confirmPass, setConfirmPass] = useState("");
  

const [resetEmail, setResetEmail] = useState("");
const [resetCode, setResetCode] = useState("");
const [newPass, setNewPass] = useState("");
const [resetStage, setResetStage] = useState("request"); // request | verify
const [resetMsg, setResetMsg] = useState("");

  const navigate = useNavigate();

  // === Email/Password Login ===
 const handleSubmit = async (e) => {
  e.preventDefault();
  setError("");
  setLoading(true);

  try {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: email.trim(), password }),
    });

    // Guard against HTML responses (e.g., server error pages)
    const ct = res.headers.get("content-type") || "";
    let payload;
    if (ct.includes("application/json")) {
      payload = await res.json();
    } else {
      const text = await res.text();
      payload = { error: text || "Server returned non-JSON response" };
    }

    if (!res.ok) {
      return setError(payload.error || "Invalid credentials");
    }

    const { token, user } = payload;
    if (!token || !user) {
      return setError("Malformed server response");
    }

    if (rememberMe) {
      localStorage.setItem("token", token);
      localStorage.setItem("user", JSON.stringify(user));
    } else {
      sessionStorage.setItem("token", token);
      sessionStorage.setItem("user", JSON.stringify(user));
    }

 if (setUser) setUser(user);
navigate("/", { replace: true });

  } catch (err) {
    console.error(err);
    setError(err.message || "Network error, please try again");
  } finally {
    setLoading(false);
  }
};


  // === Google Login (Token Flow) ===
const handleGoogleSuccess = async (credentialResponse) => {
  try {
    const cred = credentialResponse?.credential;
    if (!cred) throw new Error("Missing Google credential");

    const res = await axios.post(`${API_BASE}/auth/google`, {
      token: cred, // ✅ backend expects 'token'
    });

    const { token, user } = res.data || {};
    if (!token || !user) throw new Error("Invalid response from server");

    if (rememberMe) {
      localStorage.setItem("token", token);
      localStorage.setItem("user", JSON.stringify(user));
    } else {
      sessionStorage.setItem("token", token);
      sessionStorage.setItem("user", JSON.stringify(user));
    }

    if (setUser) setUser(user);
navigate("/", { replace: true });

  } catch (err) {
    console.error("Google login error:", err);
    const msg = err.response?.data?.error || err.message || "Google login failed";
    alert(msg);
  }
};


  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-gradient-to-r from-red-500 to-pink-500 px-4">
      {/* --- Logo + Tagline --- */}
      <div className="text-center mb-6">
        <img
          src={logo}
          alt="RomBuzz Logo"
          className="h-16 w-16 mx-auto animate-pulse-slow drop-shadow-lg"
        />
        <h1 className="text-3xl font-bold text-white mt-3">Welcome to RomBuzz</h1>
        <p className="text-white/80 text-sm">
          Connect with people nearby in real-time
        </p>
      </div>

      {/* --- Login Card --- */}
      <div className="bg-white rounded-2xl shadow-xl p-8 w-full max-w-sm">
        <h2 className="text-xl font-bold text-center text-red-600 mb-4">
          Login
        </h2>

        <form onSubmit={handleSubmit}>
          <input
            type="email"
            placeholder="Email"
            className="w-full p-3 mb-3 border rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-400"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />

          <div className="relative">
            <input
              type={showPassword ? "text" : "password"}
              placeholder="Password"
              className="w-full p-3 mb-3 border rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-400"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-3 top-3 text-sm text-gray-500"
            >
              {showPassword ? "Hide" : "Show"}
            </button>
          </div>

          <div className="flex items-center mb-3">
            <input
              type="checkbox"
              id="rememberMe"
              checked={rememberMe}
              onChange={(e) => setRememberMe(e.target.checked)}
              className="mr-2 accent-pink-600"
            />
            <label htmlFor="rememberMe" className="text-sm text-gray-700">
              Remember Me
            </label>
          </div>

          {error && (
            <p className="text-red-600 text-sm mb-3 text-center">{error}</p>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full py-3 bg-red-600 text-white rounded-lg hover:bg-red-700 transition"
          >
            {loading ? "Logging in..." : "Login"}
          </button>
        </form>

        {/* Divider */}
        <div className="flex items-center my-4">
          <div className="flex-1 h-px bg-gray-200"></div>
          <span className="px-2 text-sm text-gray-400">or</span>
          <div className="flex-1 h-px bg-gray-200"></div>
        </div>
{/* === Forgot Password Modal === */}
{showReset && (
  <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
    <div className="bg-white p-6 rounded-xl w-80 shadow-lg relative">
      <button
        className="absolute top-2 right-3 text-gray-400 hover:text-gray-700"
        onClick={() => {
          setShowReset(false);
          setResetEmail("");
          setResetCode("");
          setNewPass("");
          setResetMsg("");
          setResetStage("request");
        }}
      >
        ✕
      </button>

      <h3 className="text-lg font-semibold text-center text-pink-600 mb-3">
        Forgot Password
      </h3>

      {resetStage === "request" && (
        <>
          <input
            type="email"
            placeholder="Enter your registered email"
            className="w-full p-3 mb-3 border rounded-lg focus:ring-2 focus:ring-pink-400"
            value={resetEmail}
            onChange={(e) => setResetEmail(e.target.value)}
          />
          <button
            className="w-full py-2 bg-pink-600 text-white rounded-lg"
            onClick={async () => {
              setResetMsg("");
              try {
                const res = await axios.post(`${API_BASE}/auth/forgot-password`, {
                  email: resetEmail.trim(),
                });
                setResetMsg("Verification code sent to your email. Check Inbox or Spam");
                setResetStage("verify");
              } catch (err) {
                setResetMsg(
                  err.response?.data?.error || "Failed to send reset email"
                );
              }
            }}
          >
            Send Code
          </button>
        </>
      )}

     {resetStage === "verify" && (
  <>
    <input
      type="text"
      placeholder="Enter 6-digit code"
      className="w-full p-3 mb-2 border rounded-lg focus:ring-2 focus:ring-pink-400"
      value={resetCode}
      onChange={(e) => setResetCode(e.target.value)}
    />

    <div className="relative mb-2">
      <input
        type={showPassword ? "text" : "password"}
        placeholder="New password"
        className="w-full p-3 border rounded-lg focus:ring-2 focus:ring-pink-400"
        value={newPass}
        onChange={(e) => setNewPass(e.target.value)}
      />
      <button
        type="button"
        onClick={() => setShowPassword(!showPassword)}
        className="absolute right-3 top-3 text-sm text-gray-500"
      >
        {showPassword ? "Hide" : "Show"}
      </button>
    </div>

    <input
      type={showPassword ? "text" : "password"}
      placeholder="Confirm new password"
      className="w-full p-3 mb-3 border rounded-lg focus:ring-2 focus:ring-pink-400"
      value={confirmPass}
      onChange={(e) => setConfirmPass(e.target.value)}
    />

    <button
      className="w-full py-2 bg-pink-600 text-white rounded-lg"
      onClick={async () => {
        setResetMsg("");
        if (newPass.trim() !== confirmPass.trim()) {
          setResetMsg("Passwords do not match.");
          return;
        }
        try {
          const res = await axios.post(`${API_BASE}/auth/reset-password`, {
            email: resetEmail.trim(),
            code: resetCode.trim(),
            newPassword: newPass,
          });
          setResetMsg("✅ Password reset successful! Please login.");
          setTimeout(() => setShowReset(false), 1500);
        } catch (err) {
          setResetMsg(
            err.response?.data?.error || "Reset failed. Try again."
          );
        }
      }}
    >
      Reset Password
    </button>
  </>
)}


      {resetMsg && (
        <p className="text-sm text-center mt-3 text-gray-600">{resetMsg}</p>
      )}
    </div>
  </div>
)}

       {/* --- Google Login Button (RomBuzz style) --- */}
<div className="flex justify-center mb-2">
  <div className="w-full">
    <GoogleLogin
      onSuccess={handleGoogleSuccess}
      onError={() => alert("Google login failed")}
      useOneTap={false}
      theme="outline"
      text="signin_with"
      shape="pill"
      logo_alignment="left"
      size="large"
    />
    <style>{`
      div[role="button"][data-testid="google-login"] {
        background: linear-gradient(90deg, #ff3366, #ff6699);
        color: white !important;
        font-weight: 600;
        border: none !important;
        border-radius: 9999px !important;
        transition: all 0.3s ease;
      }
      div[role="button"][data-testid="google-login"]:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(255, 51, 102, 0.4);
      }
    `}</style>
  </div>
</div>


        <div className="flex justify-between mt-4 text-sm">
          {/* Forgot Password Modal trigger */}
<button
  onClick={() => setShowReset(true)}
  className="text-red-600 font-semibold hover:underline"
>
  Forgot password?
</button>


          <button
            onClick={() => navigate("/signup")}
            className="text-red-600 font-semibold hover:underline"
          >
            Sign up
          </button>
        </div>
      </div>
    </div>
  );
};

export default Login;

// Slow pulse animation for logo
const style = document.createElement("style");
style.innerHTML = `
@keyframes pulse-slow {
  0%, 100% { transform: scale(1); filter: drop-shadow(0 0 0px rgba(255,255,255,0.5)); }
  50% { transform: scale(1.08); filter: drop-shadow(0 0 8px rgba(255,255,255,0.8)); }
}
.animate-pulse-slow {
  animation: pulse-slow 2.5s infinite ease-in-out;
}
`;
document.head.appendChild(style);
