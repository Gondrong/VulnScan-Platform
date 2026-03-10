import React, { useEffect, useState } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { getToken, clearToken } from "./api";
import Sidebar from "./components/Sidebar.jsx";
import Topbar from "./components/Topbar.jsx";
import Login from "./pages/Login.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import Profiles from "./pages/Profiles.jsx";
import Jobs from "./pages/Jobs.jsx";
import JobDetail from "./pages/JobDetail.jsx";
import Credentials from "./pages/Credentials.jsx";
import Datasets from "./pages/Datasets.jsx";
import Settings from "./pages/Settings.jsx";

export default function App() {
  const [token, setTokenState] = useState(getToken());

  useEffect(() => {
    const t = setInterval(() => setTokenState(getToken()), 500);
    return () => clearInterval(t);
  }, []);

  function logout() {
    clearToken();
    setTokenState(null);
  }

  if (!token) return <Login />;

  return (
    <BrowserRouter>
      <div className="app-shell">
        <Sidebar onLogout={logout} />
        <div className="main-area">
          <Topbar />
          <div className="page-content">
            <Routes>
              <Route path="/" element={<Navigate to="/dashboard" />} />
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/profiles" element={<Profiles />} />
              <Route path="/jobs" element={<Jobs />} />
              <Route path="/jobs/:id" element={<JobDetail />} />
              <Route path="/credentials" element={<Credentials />} />
              <Route path="/datasets" element={<Datasets />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="*" element={<Navigate to="/dashboard" />} />
            </Routes>
          </div>
        </div>
      </div>
    </BrowserRouter>
  );
}
