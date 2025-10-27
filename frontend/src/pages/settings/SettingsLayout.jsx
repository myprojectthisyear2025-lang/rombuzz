import React from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import {
  FaUserCog, FaShieldAlt, FaLock, FaBell, FaUserShield,
  FaMapMarkerAlt, FaCreditCard, FaDownload, FaQuestionCircle, FaTrash
} from "react-icons/fa";

const NAV = [
  { to: "", label: "Account", icon: <FaUserCog /> },
  { to: "security", label: "Security & Login", icon: <FaShieldAlt /> },
  { to: "privacy", label: "Privacy", icon: <FaLock /> },
  { to: "notifications", label: "Notifications", icon: <FaBell /> },
  { to: "visibility", label: "Profile & Visibility", icon: <FaUserShield /> },
  { to: "blocking", label: "Blocking", icon: <FaUserShield /> },
  { to: "location", label: "Location", icon: <FaMapMarkerAlt /> },
  { to: "payments", label: "Payments", icon: <FaCreditCard /> },
  { to: "your-info", label: "Your information", icon: <FaDownload /> },
  { to: "help", label: "Help & Support", icon: <FaQuestionCircle /> },
  { to: "delete", label: "Delete Account", icon: <FaTrash />, danger: true },
];

export default function SettingsLayout() {
  // useLocation can be removed if you don't need it anywhere else
  useLocation();

  return (
    <div className="min-h-[70vh] bg-gradient-to-br from-rose-50 via-pink-50 to-rose-100 rounded-2xl p-4 md:p-6">
      <div className="max-w-6xl mx-auto bg-white rounded-2xl shadow-lg overflow-hidden grid grid-cols-1 md:grid-cols-[280px_1fr]">
        {/* Left rail */}
        <aside className="border-r bg-white">
          <h2 className="px-4 py-4 font-semibold text-gray-800">Settings</h2>
          <nav className="flex flex-col">
            {NAV.map((item) => {
              const absoluteTo =
                item.to === "" ? "/settings" : `/settings/${item.to}`;
              return (
                <NavLink
                  key={item.to || "root"}
                  end
                  to={absoluteTo}
                  className={({ isActive }) =>
                    `px-4 py-3 flex items-center gap-3 border-l-4 ${
                      isActive
                        ? "bg-rose-50 border-rose-500 text-rose-700"
                        : "border-transparent hover:bg-gray-50 text-gray-700"
                    } ${item.danger ? "text-red-600" : ""}`
                  }
                >
                  <span className="text-base">{item.icon}</span>
                  <span className="text-sm">{item.label}</span>
                </NavLink>
              );
            })}
          </nav>
          {/* removed the Path debug footer */}
        </aside>

        {/* Content */}
        <section className="p-4 md:p-6 bg-white">
          <Outlet />
        </section>
      </div>
    </div>
  );
}
