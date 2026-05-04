/**
 * remediation-fix.js
 * 
 * Drop this file into your frontend/ directory and add to index.html:
 *   <script src="remediation-fix.js"></script>
 * 
 * Place it BEFORE the closing </body> tag, AFTER the main <script>.
 * 
 * This script overrides renderFindings() to display the remediation
 * field in finding cards. It runs after the page loads so it safely
 * replaces the original function.
 */

(function() {
  'use strict';

  // Wait for the page to be ready
  function init() {
    if (typeof window.S === 'undefined' || typeof window.gi === 'undefined') {
      // Main app not loaded yet, retry
      setTimeout(init, 100);
      return;
    }
    
    // Override renderFindings
    window.renderFindings = renderFindingsWithRemediation;
    
    // Re-render if findings are already loaded
    if (window.S && window.S.allFindings && window.S.allFindings.length > 0) {
      renderFindingsWithRemediation();
    }
    
    console.log('[remediation-fix] Loaded: findings will now show remediation steps');
  }

  function formatRemediation(text) {
    if (!text) return '';
    var h = esc(text);
    // Replace [SECTION_NAME] with styled headers
    h = h.replace(/\[([^\]]+)\]/g, function(m, label) {
      var colors = {
        'REMEDIATION': '#34d399',
        'FIX': '#34d399',
        'AFFECTED VERSION': '#f59e0b',
        'AFFECTED COMPONENT': '#f59e0b',
        'CVE REFERENCE': '#60a5fa',
        'CVE DETAILS': '#60a5fa',
        'CISA KEV': '#ef4444',
        'CRITICAL — ACTIVELY EXPLOITED': '#ef4444',
        'CISA MANDATE': '#ef4444',
        'IMMEDIATE ACTIONS': '#f97316',
        'RANSOMWARE ALERT': '#ef4444',
        'SLA POLICY': '#94a3b8',
        'URGENCY': '#f97316',
        'GENERAL': '#94a3b8',
        'REFERENCES': '#60a5fa',
        'AFFECTED CMS': '#f59e0b',
        'AFFECTED': '#f59e0b',
        'COMPLIANCE': '#94a3b8',
        'NGINX': '#06b6d4',
        'APACHE': '#06b6d4',
        'IIS': '#06b6d4'
      };
      var c = colors[label] || '#94a3b8';
      return '<div style="margin-top:10px;margin-bottom:4px;font-family:var(--fm);font-size:.6rem;color:' + c + ';letter-spacing:.14em;font-weight:600">▸ ' + label + '</div>';
    });
    return h;
  }

  function renderFindingsWithRemediation() {
    var S = window.S;
    var gi = window.gi;
    var esc = window.esc;
    var severityBadge = window.severityBadge;

    var filtered = S.sevFilter === 'all'
      ? S.allFindings
      : S.allFindings.filter(function(f) { return f.severity === S.sevFilter; });

    var countEl = gi('finding-count-label');
    if (countEl) countEl.textContent = filtered.length + ' findings';

    var listEl = gi('findings-list');
    if (!listEl) return;

    if (filtered.length === 0) {
      listEl.innerHTML = '<div class="empty-state"><div class="empty-icon">◎</div>Run a scan to see findings · No findings match this filter</div>';
      return;
    }

    var html = '';
    for (var i = 0; i < filtered.length; i++) {
      var f = filtered[i];
      var rc = f.risk_score >= 9 ? '#f87171' : f.risk_score >= 7 ? '#f8923c' : f.risk_score >= 4 ? '#fbbf24' : '#34d399';
      var rp = f.risk_score ? Math.min(100, f.risk_score * 10) : 0;

      html += '<div class="fcard" id="fc-' + i + '">';

      // ── Header row ──
      html += '<div class="fcard-hdr" onclick="toggleFinding(' + i + ')">';
      html += '<div>' + severityBadge(f.severity) + '</div>';
      if (f.is_kev) html += '<span class="kev-tag">KEV</span>';
      html += ' <div class="fcard-title">' + esc(f.title) + '</div>';
      html += '<div style="font-family:var(--fm);font-size:.67rem;color:var(--text3);margin-right:10px;flex-shrink:0">' + esc(f.plugin_id || '') + '</div>';
      html += '<div class="fcard-risk-wrap" style="width:108px;flex-shrink:0">';
      html += '<div class="risk-track"><div class="risk-fill" style="width:' + rp + '%;background:' + rc + '"></div></div>';
      html += '<div class="risk-num" style="color:' + rc + '">' + (f.risk_score != null ? Number(f.risk_score).toFixed(1) : '–') + '</div>';
      html += '</div>';
      html += '<span class="fcard-arrow">›</span>';
      html += '</div>';

      // ── Body ──
      html += '<div class="fcard-body">';

      // Metrics
      html += '<div class="mi">';
      html += '<div class="mv"><div class="mk">Risk Score</div><div class="mv" style="color:' + rc + '">' + (f.risk_score != null ? Number(f.risk_score).toFixed(2) : '–') + '</div></div>';
      html += '<div class="mv"><div class="mk">CVSS Base</div><div class="mv">' + (f.cvss_base != null ? f.cvss_base : '–') + '</div></div>';
      html += '<div class="mv"><div class="mk">Job / Target</div><div class="mv" style="font-size:.7rem;word-break:break-all">#' + esc(f.jobId || '') + ' — ' + esc(f.jobTarget || '') + '</div></div>';
      html += '</div>';

      // Evidence
      if (f.evidence) {
        html += '<div class="fl" style="margin-top:8px;margin-bottom:5px">Evidence</div>';
        html += '<div class="terminal" style="max-height:64px;margin-bottom:12px">' + esc(f.evidence) + '</div>';
      }

      // Description
      if (f.description) {
        html += '<div class="fl" style="margin-top:8px;margin-bottom:5px">Description</div>';
        html += '<div style="font-size:.88rem;color:var(--text2);line-height:1.6">' + esc(f.description) + '</div>';
      }

      // ═══════════════════════════════════════════════
      // ═══ REMEDIATION — the key addition ═══════════
      // ═══════════════════════════════════════════════
      if (f.remediation && f.remediation.length > 0) {
        html += '<div style="margin:16px 0 12px;padding:16px 18px;background:rgba(52,211,153,0.05);border:1px solid rgba(52,211,153,0.2);border-radius:6px">';
        html += '<div style="font-family:var(--fm);font-size:.62rem;color:#34d399;letter-spacing:.2em;margin-bottom:12px;font-weight:700">⚕ REMEDIATION</div>';
        html += '<div style="font-size:.84rem;color:var(--text);line-height:1.8;white-space:pre-wrap">' + formatRemediation(f.remediation) + '</div>';
        html += '</div>';
      }

      // Suppress + SLA
      html += '<div style="margin-top:14px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">';
      if (f.sla_days) {
        html += '<span style="font-family:var(--fm);font-size:.58rem;color:#94a3b8;border:1px solid rgba(148,163,184,0.3);padding:2px 8px;border-radius:3px">SLA: ' + f.sla_days + ' days</span>';
      }
      if (f.fingerprint) {
        html += '<button class="btn btn-ghost btn-sm" onclick="suppressFinding(\'' + esc(f.fingerprint) + '\',event)">⊗ Suppress</button>';
      }
      html += '</div>';

      html += '</div></div>'; // close fcard-body, fcard
    }

    listEl.innerHTML = html;
  }

  // Make formatRemediation globally available
  window.formatRemediation = formatRemediation;

  // Initialize
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
