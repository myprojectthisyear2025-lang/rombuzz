// src/index.jsx
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";
import { GoogleOAuthProvider } from "@react-oauth/google";

// 👇 add this import
import { ensureSocketAuth } from "./socket";

// 👇 start the singleton socket before rendering
ensureSocketAuth();

const root = ReactDOM.createRoot(document.getElementById("root"));

root.render(
  <React.StrictMode>
    <GoogleOAuthProvider clientId="579443399527-u5djeobtcvp7uubimq2fq8e5f9t7fv4l.apps.googleusercontent.com">
      <App />
    </GoogleOAuthProvider>
  </React.StrictMode>
);
