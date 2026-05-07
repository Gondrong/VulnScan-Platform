import React, { useState, useEffect, useCallback } from "react";
import { Nav, Topbar } from "./design/Shell.jsx";
import { Dashboard } from "./design/Dashboard.jsx";
import { Jobs } from "./design/Jobs.jsx";
import { JobDetail, FindingDrawer } from "./design/JobDetail.jsx";
import { Assets, AssetDetail, Reports } from "./design/Assets.jsx";
import { Profiles, Credentials, Datasets, Settings } from "./design/PagesOther.jsx";
import { ThreatIntel } from "./design/ThreatIntel.jsx";
import { AttackGraph } from "./design/AttackGraph.jsx";
import { LoginPage } from "./design/Login.jsx";
import {
  getToken, logout as apiLogout,
  scanApi, credentialsApi, datasetsApi, assetsApi, reportsApi, threatIntelApi,
} from "./api.js";

export default function App() {
  const [authed, setAuthed] = useState(() => !!getToken());
  const [page, setPage] = useState("dashboard");
  const [settingsTab, setSettingsTab] = useState(null);
  const [openedJob, setOpenedJob] = useState(null);
  const [openedAsset, setOpenedAsset] = useState(null);
  const [drawerFinding, setDrawerFinding] = useState(null);
  const [counts, setCounts] = useState({});

  const refreshCounts = useCallback(async () => {
    if (!getToken()) return;
    try {
      const [jobs, profiles, creds, datasets, assets, reports, ti] = await Promise.all([
        scanApi.listJobs().catch(() => []),
        scanApi.listProfiles().catch(() => []),
        credentialsApi.list().catch(() => []),
        datasetsApi.list().catch(() => []),
        assetsApi.list().catch(() => []),
        reportsApi.list().catch(() => []),
        threatIntelApi.stats().catch(() => null),
      ]);
      setCounts(prev => ({
        jobs: jobs.length,
        profiles: profiles.length,
        credentials: creds.length,
        datasets: datasets.length,
        assets: assets.length,
        reports: reports.length,
        threat_kev: ti?.kev_count ?? prev.threat_kev,
      }));
    } catch {}
  }, []);

  useEffect(() => {
    if (!authed) return;
    refreshCounts();
    const t = setInterval(refreshCounts, 12000);
    return () => clearInterval(t);
  }, [authed, refreshCounts]);

  if (!authed) {
    return <LoginPage onLogin={() => setAuthed(true)}/>;
  }

  const crumbs = ((p) => {
    if (p === "dashboard")    return ["VulnScan", "Dashboard"];
    if (p === "assets")       return openedAsset ? ["VulnScan", "Assets", openedAsset.name] : ["VulnScan", "Assets"];
    if (p === "jobs")         return openedJob ? ["VulnScan", "Scans", `#${openedJob.id}`] : ["VulnScan", "Scan jobs"];
    if (p === "profiles")     return ["VulnScan", "Profiles"];
    if (p === "reports")      return ["VulnScan", "Reports"];
    if (p === "credentials")  return ["VulnScan", "Credentials"];
    if (p === "datasets")     return ["VulnScan", "Datasets"];
    if (p === "threat-intel") return ["VulnScan", "Threat Intel"];
    if (p === "attack-graph") return ["VulnScan", "Attack Graph"];
    if (p === "settings")     return ["VulnScan", "Settings"];
    return ["VulnScan"];
  })(page);

  function setPageWrap(p, tab) { setOpenedJob(null); setOpenedAsset(null); setSettingsTab(p === "settings" ? (tab || null) : null); setPage(p); }

  return (
    <div className="shell" data-screen-label={page}>
      <Nav page={page} setPage={setPageWrap} counts={counts} onSignOut={() => {
        apiLogout();
        setAuthed(false);
      }}/>
      <div className="main">
        <Topbar crumbs={crumbs} setPage={setPageWrap}/>
        <div className="page">
          {page === "dashboard"   && <Dashboard openDrawer={setDrawerFinding} setPage={setPageWrap}/>}
          {page === "assets" && !openedAsset && <Assets openAsset={setOpenedAsset}/>}
          {page === "assets" &&  openedAsset && <AssetDetail asset={openedAsset} back={() => setOpenedAsset(null)}/>}

          {page === "jobs" && !openedJob && <Jobs openJob={setOpenedJob}/>}
          {page === "jobs" &&  openedJob && <JobDetail job={openedJob} back={() => setOpenedJob(null)} openDrawer={setDrawerFinding}/>}
          {page === "profiles"    && <Profiles/>}
          {page === "reports"     && <Reports/>}
          {page === "credentials" && <Credentials/>}
          {page === "datasets"    && <Datasets/>}
          {page === "threat-intel"&& <ThreatIntel/>}
          {page === "attack-graph"&& <AttackGraph/>}
          {page === "settings"    && <Settings initialTab={settingsTab}/>}
        </div>
      </div>
      {drawerFinding && <FindingDrawer finding={drawerFinding} close={() => setDrawerFinding(null)}/>}
    </div>
  );
}
