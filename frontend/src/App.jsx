import React, { useEffect, useState } from "react";
import { BrowserRouter, Routes, Route, Link, Navigate } from "react-router-dom";
import { getToken, clearToken } from "./api";

import Login from "./pages/Login.jsx";
import Profiles from "./pages/Profiles.jsx";
import Jobs from "./pages/Jobs.jsx";
import JobDetail from "./pages/JobDetail.jsx";
import Credentials from "./pages/Credentials.jsx";
import Datasets from "./pages/Datasets.jsx";

export default function App(){
  const [token,setTokenState] = useState(getToken());

  useEffect(()=>{
    const t = setInterval(()=>setTokenState(getToken()), 500);
    return ()=>clearInterval(t);
  },[]);

  function logout(){
    clearToken();
    setTokenState(null);
  }

  return (
    <BrowserRouter>
      <div style={{ padding: 16, display:"flex", gap:16, alignItems:"center" }}>
        <b>VulnScan</b>
        {token && <>
          <Link to="/profiles">Profiles</Link>
          <Link to="/jobs">Jobs</Link>
          <Link to="/credentials">Credentials</Link>
          <Link to="/datasets">Datasets</Link>
          <button onClick={logout}>Logout</button>
        </>}
      </div>

      <div style={{ padding: 16 }}>
        <Routes>
          <Route path="/" element={token ? <Navigate to="/jobs"/> : <Login/>}/>
          <Route path="/profiles" element={token ? <Profiles/> : <Login/>}/>
          <Route path="/jobs" element={token ? <Jobs/> : <Login/>}/>
          <Route path="/jobs/:id" element={token ? <JobDetail/> : <Login/>}/>
          <Route path="/credentials" element={token ? <Credentials/> : <Login/>}/>
          <Route path="/datasets" element={token ? <Datasets/> : <Login/>}/>
        </Routes>
      </div>
    </BrowserRouter>
  );
}
