import React, { useEffect, useState } from "react";
import { api } from "../api";
import { useParams } from "react-router-dom";

export default function JobDetail(){
  const { id } = useParams();
  const [data,setData] = useState(null);

  async function load(){
    setData(await api(`/scan/jobs/${id}`));
  }
  useEffect(()=>{ load(); const t=setInterval(load, 2000); return ()=>clearInterval(t); }, [id]);

  if (!data) return <div>Loading...</div>;
  const job = data.job;
  const findings = data.findings || [];

  return (
    <div>
      <h2>Job #{job.id}</h2>
      <div>Target: {job.target}</div>
      <div>Status: {job.status}</div>

      <h3 style={{ marginTop:16 }}>Findings</h3>
      <table border="1" cellPadding="6">
        <thead><tr><th>Severity</th><th>Risk</th><th>Plugin</th><th>Title</th><th>KEV</th></tr></thead>
        <tbody>
          {findings.map(f=>(
            <tr key={f.id}>
              <td>{f.severity}</td>
              <td>{f.risk_score ?? ""}</td>
              <td>{f.plugin_id}</td>
              <td style={{ maxWidth:700 }}>{f.title}</td>
              <td>{String(f.is_kev)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
