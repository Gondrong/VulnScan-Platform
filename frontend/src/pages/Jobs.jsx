import React, { useEffect, useState } from "react";
import { api } from "../api";
import { Link } from "react-router-dom";

export default function Jobs(){
  const [profiles,setProfiles] = useState([]);
  const [jobs,setJobs] = useState([]);
  const [target,setTarget] = useState("127.0.0.1");
  const [profileId,setProfileId] = useState("");
  const [err,setErr] = useState("");

  async function load(){
    const p = await api("/scan/profiles");
    setProfiles(p);
    if (!profileId && p[0]) setProfileId(String(p[0].id));
    setJobs(await api("/scan/jobs"));
  }
  useEffect(()=>{ load(); }, []);

  async function run(){
    setErr("");
    try{
      await api("/scan/jobs", { method:"POST", body:{ target, profile_id: Number(profileId) }});
      await load();
    }catch(e){ setErr(e.message||String(e)); }
  }

  return (
    <div>
      <h2>Jobs</h2>

      <div style={{ border:"1px solid #ddd", padding:12, borderRadius:12, maxWidth:700 }}>
        <h3>Run Scan</h3>
        <input value={target} onChange={e=>setTarget(e.target.value)} placeholder="target" style={{ width:"100%", marginBottom:8 }}/>
        <select value={profileId} onChange={e=>setProfileId(e.target.value)} style={{ width:"100%", marginBottom:8 }}>
          {profiles.map(p=> <option key={p.id} value={p.id}>{p.id} - {p.name}</option>)}
        </select>
        <button onClick={run}>Submit</button>
        {err && <div style={{ color:"crimson", marginTop:8 }}>{err}</div>}
      </div>

      <h3 style={{ marginTop:16 }}>History</h3>
      <table border="1" cellPadding="6">
        <thead><tr><th>ID</th><th>Target</th><th>Status</th><th>Open</th></tr></thead>
        <tbody>
          {jobs.map(j=>(
            <tr key={j.id}>
              <td>{j.id}</td>
              <td>{j.target}</td>
              <td>{j.status}</td>
              <td><Link to={`/jobs/${j.id}`}>detail</Link></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}