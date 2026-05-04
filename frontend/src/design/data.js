// Mock data — realistic vulnerability scan data

const FINDINGS = [
  { id: 1421, severity: "critical", title: "Apache Struts 2 Remote Code Execution (CVE-2024-50379)", host: "api-prod-01.internal", plugin: "nvd_match", risk: 9.8, cvss: 9.8, kev: true, confidence: 0.95, sla: 2, port: 443, cve: "CVE-2024-50379", desc: "The Apache Struts 2 framework on this host is vulnerable to a remote code execution flaw via crafted multipart/form-data requests. The vulnerability stems from improper validation of file upload parameters and allows an unauthenticated attacker to execute arbitrary OS commands.", remediation: "Upgrade Apache Struts to 6.4.0 or later. As a temporary mitigation, deploy the OGNL evaluation filter (ognl-validation) in front of the application and restrict multipart upload size to 1MB.", evidence: "GET /struts2-showcase/ HTTP/1.1\nServer: Apache-Coyote/1.1 Struts2/2.5.30", compliance: ["NIST CM-7", "PCI 6.5.1", "ISO A.14.2.5", "CIS 2.3"] },
  { id: 1420, severity: "critical", title: "Exposed Kubernetes API on port 6443 (no auth)", host: "k8s-master.prod", plugin: "k8s_api", risk: 9.6, cvss: 9.4, kev: false, confidence: 0.99, sla: 2, port: 6443, desc: "The Kubernetes API server on this host accepts unauthenticated requests to /api/v1/namespaces. An attacker can list secrets, deploy pods, and pivot across the cluster.", remediation: "Enable RBAC and require client-cert or token authentication. Disable the anonymous-auth flag in the kube-apiserver manifest.", evidence: "$ curl -k https://k8s-master.prod:6443/api/v1/namespaces\n{\"kind\":\"NamespaceList\", \"items\":[...]}", compliance: ["NIST AC-3", "CIS K8s 1.2.1"] },
  { id: 1419, severity: "high", title: "JWT 'alg:none' bypass on /api/auth/refresh", host: "api-prod-01.internal", plugin: "jwt_scanner", risk: 8.4, cvss: 8.2, kev: false, confidence: 0.92, sla: 7, port: 443, desc: "The /api/auth/refresh endpoint accepts JWTs signed with alg:none, allowing token forgery without the signing key.", remediation: "Configure your JWT library to reject 'none' algorithms explicitly. Whitelist allowed algs (HS256/RS256). Rotate signing keys.", evidence: 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.', compliance: ["OWASP API2", "NIST IA-2"] },
  { id: 1418, severity: "high", title: "Outdated nginx 1.18.0 (multiple CVEs)", host: "web-edge-02.dmz", plugin: "deep_fingerprint", risk: 7.8, cvss: 7.5, kev: false, confidence: 0.88, sla: 7, port: 443, cve: "CVE-2023-44487", desc: "nginx 1.18.0 has known vulnerabilities including HTTP/2 rapid reset (CVE-2023-44487).", remediation: "Upgrade to nginx 1.24.0 or later. Enable rate limiting on HTTP/2 streams.", compliance: ["NIST SI-2"] },
  { id: 1417, severity: "high", title: "AWS S3 bucket 'vulnscan-backups' world-readable", host: "s3.amazonaws.com", plugin: "cloud_storage_misconfig", risk: 7.6, cvss: 7.5, kev: false, confidence: 1.0, sla: 7, port: 443, desc: "The S3 bucket allows public list and read. 47 backup files containing database dumps are exposed.", remediation: "Apply bucket policy denying * principal. Enable Block Public Access at the account level.", compliance: ["PCI 1.4", "CIS AWS 2.1.5"] },
  { id: 1416, severity: "medium", title: "Missing security header: Strict-Transport-Security", host: "web-edge-02.dmz", plugin: "security_headers", risk: 5.2, cvss: 5.0, kev: false, confidence: 1.0, sla: 30, port: 443, desc: "HSTS header is absent, exposing users to SSL stripping attacks." },
  { id: 1415, severity: "medium", title: "TLS 1.0 still enabled on /admin", host: "admin.internal", plugin: "tls_basic", risk: 5.0, cvss: 5.3, kev: false, confidence: 1.0, sla: 30, port: 443 },
  { id: 1414, severity: "medium", title: "GraphQL introspection enabled in production", host: "api-prod-01.internal", plugin: "graphql_scanner", risk: 4.8, cvss: 5.0, kev: false, confidence: 0.9, sla: 30, port: 443 },
  { id: 1413, severity: "medium", title: "SSH server allows weak diffie-hellman-group1-sha1", host: "bastion-01.internal", plugin: "ssh_audit", risk: 4.4, cvss: 4.3, kev: false, confidence: 1.0, sla: 30, port: 22 },
  { id: 1412, severity: "low", title: "Server header reveals version (Apache/2.4.41)", host: "web-edge-02.dmz", plugin: "http_fingerprint", risk: 2.6, cvss: 2.0, kev: false, confidence: 1.0, sla: 90, port: 80 },
  { id: 1411, severity: "low", title: "Cookie missing 'Secure' flag", host: "api-prod-01.internal", plugin: "security_headers", risk: 2.2, cvss: 2.5, kev: false, confidence: 1.0, sla: 90, port: 443 },
  { id: 1410, severity: "info", title: "Subdomain discovered: staging.vulnscan.io", host: "staging.vulnscan.io", plugin: "dns_enum", risk: 0, cvss: 0, kev: false, confidence: 1.0, sla: 365, port: 0 },
];

const JOBS = [
  { id: 1842, target: "10.20.0.0/16", scan_type: "internal", status: "running", profile: "Full Network Audit", created_at: "2026-04-28T09:14:00Z", duration: "8m 32s", progress: 64, findings: 0, plugins_run: 18, plugins_total: 31 },
  { id: 1841, target: "api-prod-01.internal", scan_type: "internal", status: "done", profile: "Web Application Deep", created_at: "2026-04-28T08:02:00Z", duration: "12m 04s", findings: 47, critical: 2, high: 6, medium: 14 },
  { id: 1840, target: "vulnscan.io", scan_type: "external", status: "done", profile: "External Surface", created_at: "2026-04-28T06:30:00Z", duration: "6m 11s", findings: 23, critical: 0, high: 2, medium: 8 },
  { id: 1839, target: "k8s-master.prod", scan_type: "internal", status: "done", profile: "Infrastructure Audit", created_at: "2026-04-28T03:11:00Z", duration: "4m 47s", findings: 18, critical: 1, high: 3, medium: 6 },
  { id: 1838, target: "10.20.5.0/24", scan_type: "internal", status: "failed", profile: "Quick Discovery", created_at: "2026-04-27T22:18:00Z", duration: "1m 02s", findings: 0, error: "Network unreachable: 10.20.5.0/24" },
  { id: 1837, target: "api.vulnscan.io", scan_type: "external", status: "done", profile: "API Scanner (OpenAPI)", created_at: "2026-04-27T18:45:00Z", duration: "9m 23s", findings: 31, critical: 1, high: 4, medium: 11 },
  { id: 1836, target: "iot-gateway.dmz", scan_type: "internal", status: "done", profile: "IoT / MQTT Audit", created_at: "2026-04-27T15:00:00Z", duration: "3m 12s", findings: 7, critical: 0, high: 1, medium: 3 },
  { id: 1835, target: "bastion-01.internal", scan_type: "internal", status: "queued", profile: "SSH Hardening", created_at: "2026-04-27T14:30:00Z", duration: "—", findings: 0 },
];

const PROFILES = [
  { id: 1, name: "Full Network Audit", desc: "All 51 plugins, deep + active checks", plugins: 51, jobs: 142, last_used: "2 hours ago", category: "Comprehensive" },
  { id: 2, name: "Web Application Deep", desc: "OWASP + JWT + GraphQL + API key + SSTI", plugins: 14, jobs: 89, last_used: "1 hour ago", category: "Web" },
  { id: 3, name: "External Surface", desc: "Safe non-intrusive checks for internet-facing", plugins: 12, jobs: 67, last_used: "5 hours ago", category: "External" },
  { id: 4, name: "Infrastructure Audit", desc: "SSH, SMB, SNMP, Docker, K8s, MQTT", plugins: 11, jobs: 34, last_used: "yesterday", category: "Infra" },
  { id: 5, name: "Quick Discovery", desc: "Port scan + fingerprint + CVE match only", plugins: 7, jobs: 218, last_used: "2 hours ago", category: "Recon" },
  { id: 6, name: "API Scanner (OpenAPI)", desc: "Spec-driven: BOLA, mass assignment, JWT", plugins: 15, jobs: 22, last_used: "yesterday", category: "API" },
  { id: 7, name: "IoT / MQTT Audit", desc: "MQTT broker enum + topic injection", plugins: 4, jobs: 8, last_used: "yesterday", category: "IoT" },
  { id: 8, name: "SSH Hardening", desc: "Key exchange, ciphers, banners only", plugins: 2, jobs: 19, last_used: "3 days ago", category: "Infra" },
];

const CREDENTIALS = [
  { id: 1, name: "prod-ssh-key", type: "ssh-key", desc: "Production bastion access", last_used: "1 hour ago", scope: "Internal" },
  { id: 2, name: "azure-sp-readonly", type: "oauth", desc: "Azure service principal (read-only)", last_used: "2 days ago", scope: "Cloud" },
  { id: 3, name: "github-token", type: "token", desc: "GitHub PAT for repo scanning", last_used: "yesterday", scope: "External" },
  { id: 4, name: "gcp-scanner-sa", type: "json-key", desc: "GCP service account for asset enum", last_used: "5 days ago", scope: "Cloud" },
  { id: 5, name: "smb-domain-admin", type: "username-password", desc: "AD domain credential (vault-managed)", last_used: "3 days ago", scope: "Internal" },
];

const DATASETS = [
  { id: "nvd",      name: "NVD",            desc: "NIST National Vulnerability Database", records: 217843, updated: "2 hours ago", status: "fresh", source: "nvd.nist.gov" },
  { id: "cve",      name: "CVE.org",        desc: "Multi-source CVSS (CNA + ADP)", records: 51208, updated: "2 hours ago", status: "fresh", source: "cve.org" },
  { id: "kev",      name: "CISA KEV",       desc: "Known Exploited Vulnerabilities", records: 1147, updated: "1 day ago", status: "fresh", source: "cisa.gov" },
  { id: "epss",     name: "EPSS",           desc: "Exploit Prediction Scoring System", records: 198302, updated: "today", status: "fresh", source: "first.org" },
  { id: "cms",      name: "CMS-CVE",        desc: "CMS-specific (WordPress, Drupal, …)", records: 5234, updated: "1 week ago", status: "stale", source: "generated" },
  { id: "compliance", name: "Compliance",   desc: "NIST 800-53 / PCI / CIS / ISO mapping", records: 47, updated: "static", status: "fresh", source: "static" },
];

const TIMELINE = [
  { t: "09:14:32", level: "info", msg: "Scan job #1842 dispatched to worker queue" },
  { t: "09:14:33", level: "ok",   msg: "Plugin port_scan starting (target 10.20.0.0/16, 65k ports)" },
  { t: "09:16:42", level: "ok",   msg: "Plugin port_scan completed — 1,847 hosts up, 12,403 ports open" },
  { t: "09:16:43", level: "ok",   msg: "Plugin http_fingerprint starting" },
  { t: "09:18:11", level: "ok",   msg: "Plugin http_fingerprint completed — 384 web services identified" },
  { t: "09:18:12", level: "ok",   msg: "Plugin nvd_match starting (CPE → CVE mapping)" },
  { t: "09:21:08", level: "warn", msg: "Plugin nvd_match: 3 CISA KEV matches detected" },
  { t: "09:21:09", level: "ok",   msg: "Plugin nvd_match completed — 142 CVEs matched" },
  { t: "09:21:10", level: "ok",   msg: "Plugin owasp_scanner starting" },
];

const sevWeek = [12, 18, 9, 21, 14, 26, 19, 22, 28, 17, 15, 23, 31, 24];

const ASSETS = [
  { id: "prod",        name: "Production",         parent: null,  desc: "Customer-facing production environments", owner: "Platform Team", targets: 47, critical: 3, high: 11, medium: 23, low: 18, last_scan: "4m ago",   risk: 8.4 },
  { id: "prod-api",    name: "Production · API",   parent: "prod", desc: "REST and GraphQL services", owner: "API Team", targets: 18, critical: 2, high: 4, medium: 9, low: 6, last_scan: "12m ago",  risk: 8.9 },
  { id: "prod-web",    name: "Production · Web",   parent: "prod", desc: "Web frontends and edge nodes", owner: "Web Team", targets: 12, critical: 0, high: 3, medium: 8, low: 5, last_scan: "1h ago",   risk: 6.8 },
  { id: "prod-infra",  name: "Production · Infra", parent: "prod", desc: "Kubernetes, databases, message queues", owner: "SRE", targets: 17, critical: 1, high: 4, medium: 6, low: 7, last_scan: "3h ago",   risk: 7.6 },
  { id: "staging",     name: "Staging",            parent: null, desc: "Pre-production environments", owner: "Platform Team", targets: 22, critical: 0, high: 2, medium: 8, low: 4, last_scan: "yesterday", risk: 4.2 },
  { id: "internal",    name: "Internal Tools",     parent: null, desc: "Bastions, admin panels, internal services", owner: "IT", targets: 14, critical: 0, high: 1, medium: 5, low: 3, last_scan: "2d ago",  risk: 3.8 },
  { id: "cloud",       name: "Cloud Storage",      parent: null, desc: "S3, Azure Blob, GCS audited weekly", owner: "Cloud Team", targets: 9, critical: 0, high: 1, medium: 0, low: 0, last_scan: "1w ago",   risk: 6.2 },
  { id: "iot",         name: "IoT & Edge",         parent: null, desc: "MQTT brokers and gateway devices", owner: "IoT Team",  targets: 6, critical: 0, high: 0, medium: 3, low: 2, last_scan: "3d ago",   risk: 2.6 },
];

const ASSET_TARGETS = {
  "prod-api": [
    { host: "api-prod-01.internal", type: "host", env: "prod",    findings: 47, last_scan: "12m ago" },
    { host: "api-prod-02.internal", type: "host", env: "prod",    findings: 12, last_scan: "12m ago" },
    { host: "api.vulnscan.io",      type: "domain", env: "prod",  findings: 31, last_scan: "yesterday" },
    { host: "10.20.10.0/24",        type: "cidr", env: "prod",    findings: 64, last_scan: "12m ago" },
  ],
};

const REPORTS = [
  { id: "R-1841", job_id: 1841, target: "api-prod-01.internal", profile: "Web Application Deep", asset: "Production · API", generated: "2 hours ago", findings: 47, formats: ["pdf", "csv", "json", "sarif"], size_pdf: "2.4 MB", template: "Executive + Technical" },
  { id: "R-1840", job_id: 1840, target: "vulnscan.io",          profile: "External Surface",     asset: "Production · Web", generated: "5 hours ago", findings: 23, formats: ["pdf", "csv", "json", "sarif"], size_pdf: "1.1 MB", template: "Executive Summary" },
  { id: "R-1839", job_id: 1839, target: "k8s-master.prod",      profile: "Infrastructure Audit", asset: "Production · Infra", generated: "8 hours ago", findings: 18, formats: ["pdf", "csv", "json", "sarif"], size_pdf: "1.8 MB", template: "Technical Detail" },
  { id: "R-1837", job_id: 1837, target: "api.vulnscan.io",      profile: "API Scanner (OpenAPI)", asset: "Production · API", generated: "yesterday", findings: 31, formats: ["pdf", "csv", "json", "sarif"], size_pdf: "1.6 MB", template: "Executive + Technical" },
  { id: "R-1836", job_id: 1836, target: "iot-gateway.dmz",      profile: "IoT / MQTT Audit",     asset: "IoT & Edge",       generated: "yesterday", findings:  7, formats: ["pdf", "csv", "json", "sarif"], size_pdf: "0.6 MB", template: "Technical Detail" },
];

export const MOCK = { FINDINGS, JOBS, PROFILES, CREDENTIALS, DATASETS, TIMELINE, sevWeek, ASSETS, ASSET_TARGETS, REPORTS };
