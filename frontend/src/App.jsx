//App.jsx


import React, { useEffect, useState } from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate,
  useLocation,
} from "react-router-dom";
import { GoogleOAuthProvider } from "@react-oauth/google";
import Store from "./pages/Story";

import Navbar from "./components/Navbar";
import Footer from "./components/Footer";
import Home from "./pages/Home";
import Profile from "./pages/Profile";
import Login from "./pages/Login";
import Discover from "./pages/Discover";
import Register from "./pages/Register";
import CompleteProfile from "./pages/CompleteProfile";
import MicroBuzz from "./pages/MicroBuzz";
import Chat from "./pages/Chat";
import NotificationsPage from "./pages/Notifications";
import LetsBuzz from "./pages/LetsBuzz";
import ViewProfile from "./pages/ViewProfile";
import SettingsLayout from "./pages/settings/SettingsLayout";
import ProfilePreview from "./pages/ProfilePreview";
import Account from "./pages/settings"; // index.jsx
import Security from "./pages/settings/Security";
import Privacy from "./pages/settings/Privacy";
import Notifications from "./pages/settings/Notifications";
import Visibility from "./pages/settings/Visibility";
import Blocking from "./pages/settings/Blocking";
import Location from "./pages/settings/Location";
import Payments from "./pages/settings/Payments";
import YourInfo from "./pages/settings/YourInfo";
import Help from "./pages/settings/Help";
import DeleteAccount from "./pages/settings/DeleteAccount";
import Signup from "./pages/Signup"; // ⬅️ Add this import near the top

const API_BASE = "https://rombuzz-api.onrender.com/api";

const GOOGLE_CLIENT_ID =
  "579443399527-3q3lpblalkiqces1d0etdgjfj301b75l.apps.googleusercontent.com";

// ✅ ProtectedRoute
function ProtectedRoute({ children }) {
  const token =
    localStorage.getItem("token") || sessionStorage.getItem("token");
  return token ? children : <Navigate to="/login" replace />;
}

// ✅ AppWrapper handles all routes + footer control
function AppWrapper() {
  const [loading, setLoading] = useState(true);
  const [user, setUser] = useState(null);
  const location = useLocation();

  // 🔍 Check token on startup
  useEffect(() => {
    const token =
      localStorage.getItem("token") || sessionStorage.getItem("token");
    if (!token) {
      setLoading(false);
      return;
    }

    fetch(`${API_BASE}/auth/me`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => {
        if (!res.ok) throw new Error("Invalid token");
        return res.json();
      })
      .then((data) => {
        if (data.user) {
          setUser(data.user);
          localStorage.setItem("user", JSON.stringify(data.user));
        }
      })
      .catch(() => {
        localStorage.removeItem("token");
        localStorage.removeItem("user");
        sessionStorage.removeItem("token");
        sessionStorage.removeItem("user");
        setUser(null);
      })
      .finally(() => setLoading(false));
  }, []);

  if (loading)
    return (
      <div className="flex justify-center items-center min-h-screen text-rose-600 text-lg font-semibold">
        Loading...
      </div>
    );

  // ✅ Show footer ONLY on homepage
  const showFooter = location.pathname === "/";

  return (
    <div className="flex flex-col min-h-screen bg-gradient-to-br from-rose-50 via-pink-50 to-rose-100 text-gray-900">
      <Navbar user={user} setUser={setUser} />

      <main className="flex-grow pt-16 pb-24 px-2 md:px-6 overflow-x-hidden">
        <Routes>
          {/* --- Public Routes --- */}
          <Route path="/" element={<Home />} />
          <Route path="/letsbuzz" element={<LetsBuzz />} />
          <Route
            path="/login"
            element={
              user ? <Navigate to="/discover" /> : <Login setUser={setUser} />
            }
          />

              <Route
                path="/signup"
                element={
                  user ? <Navigate to="/discover" /> : <Signup setUser={setUser} />
                }
              />



          {/* --- Protected Routes --- */}
          <Route
            path="/discover"
            element={
              <ProtectedRoute>
                <Discover user={user} setUser={setUser} />
              </ProtectedRoute>
            }
          />
         <Route
            path="/register"
            element={<Register user={user} setUser={setUser} />}
          />

          <Route
            path="/profile"
            element={
              <ProtectedRoute>
                <Profile user={user} setUser={setUser} />
              </ProtectedRoute>
            }
          />
          <Route
            path="/microbuzz"
            element={
              <ProtectedRoute>
                <MicroBuzz user={user} setUser={setUser} />
              </ProtectedRoute>
            }
          />
          <Route
            path="/chat"
            element={
              <ProtectedRoute>
                <Chat user={user} setUser={setUser} />
              </ProtectedRoute>
            }
          />
          <Route
            path="/chat/:userId"
            element={
              <ProtectedRoute>
                <Chat user={user} setUser={setUser} />
              </ProtectedRoute>
            }
          />
          <Route
            path="/notifications"
            element={
              <ProtectedRoute>
                <NotificationsPage user={user} setUser={setUser} />
              </ProtectedRoute>
            }
          />
          <Route
            path="/preview/:id"
            element={
              <ProtectedRoute>
                <ProfilePreview />
              </ProtectedRoute>
            }
          />
          <Route path="/store" element={<Store />} />

          <Route
            path="/settings/*"
            element={
              <ProtectedRoute>
                <SettingsLayout />
              </ProtectedRoute>
            }
          >
            <Route index element={<Account />} />
            <Route path="security" element={<Security />} />
            <Route path="privacy" element={<Privacy />} />
            <Route path="notifications" element={<Notifications />} />
            <Route path="visibility" element={<Visibility />} />
            <Route path="blocking" element={<Blocking />} />
            <Route path="location" element={<Location />} />
            <Route path="payments" element={<Payments />} />
            <Route path="your-info" element={<YourInfo />} />
            <Route path="help" element={<Help />} />
            <Route path="delete" element={<DeleteAccount />} />
          </Route>
          <Route
  path="/viewProfile/:userId"
  element={
    <ProtectedRoute>
      <ViewProfile />
    </ProtectedRoute>
  }
/>
     
     

<Route
  path="/view/:userId"
  element={
    <ProtectedRoute>
      <ViewProfile />
    </ProtectedRoute>
  }
/>

          {/* --- Fallback --- */}
          <Route path="*" element={<Navigate to="/" />} />
        </Routes>
      </main>

      {/* ✅ Footer only on homepage */}
      {showFooter && <Footer />}
    </div>
  );
}

// ✅ Root wrapper
export default function App() {
  return (
    <GoogleOAuthProvider clientId={GOOGLE_CLIENT_ID}>
      <Router>
        <AppWrapper />
      </Router>
    </GoogleOAuthProvider>
    
  );
}
