/**
 * MailAuth — Free SPF / DKIM / DMARC Checker
 * Client-side only. Uses Cloudflare DNS-over-HTTPS.
 */

(function () {
  "use strict";

  // ---------- Config ----------
  const DOH = "https://cloudflare-dns.com/dns-query";
  const MAX_DOMAIN_LENGTH = 253;
  const DOMAIN_REGEX = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

  // Common DKIM selectors (expanded)
  const DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2",
    "dkim", "mail", "email", "mandrill", "everlytickey1", "everlytickey2",
    "cm", "pm", "s1024", "s2048", "mx", "smtp", "postfix", "dkim1", "dkim2",
    "sig1", "sig2", "zoho", "protonmail", "fm1", "fm2", "fm3", "bigmailer"
  ];

  // ---------- DOM helpers ----------
  const $ = (id) => document.getElementById(id);

  function escapeHtml(str) {
    if (typeof str !== "string") return "";
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function setLoading(isLoading) {
    const btn = $("checkBtn");
    const text = $("btnText");
    const spinner = $("spinner");
    btn.disabled = isLoading;
    text.classList.toggle("hidden", isLoading);
    spinner.classList.toggle("hidden", !isLoading);
  }

  // ---------- DNS ----------
  async function dnsQuery(name, type = "TXT") {
    const url = `${DOH}?name=${encodeURIComponent(name)}&type=${type}`;
    const res = await fetch(url, {
      headers: { Accept: "application/dns-json" },
      cache: "no-store"
    });
    if (!res.ok) throw new Error("DNS query failed");
    return res.json();
  }

  function extractTXT(data) {
    if (!data || !Array.isArray(data.Answer)) return [];
    return data.Answer
      .filter((r) => r.type === 16)
      .map((r) => {
        let d = r.data || "";
        d = d.replace(/^"|"$/g, "").replace(/" "/g, "");
        return d;
      });
  }

  async function getSPF(domain) {
    const data = await dnsQuery(domain, "TXT");
    const records = extractTXT(data);
    return records.find((r) => r.toLowerCase().startsWith("v=spf1")) || null;
  }

  async function getDMARC(domain) {
    const data = await dnsQuery(`_dmarc.${domain}`, "TXT");
    const records = extractTXT(data);
    return records.find((r) => r.toLowerCase().startsWith("v=dmarc1")) || null;
  }

  async function getDKIM(domain) {
    const results = [];
    const chunks = [];
    for (let i = 0; i < DKIM_SELECTORS.length; i += 6) {
      chunks.push(DKIM_SELECTORS.slice(i, i + 6));
    }

    for (const chunk of chunks) {
      const promises = chunk.map(async (sel) => {
        try {
          const data = await dnsQuery(`${sel}._domainkey.${domain}`, "TXT");
          const records = extractTXT(data);
          const rec = records.find(
            (r) =>
              r.toLowerCase().includes("v=dkim1") ||
              r.toLowerCase().includes("k=rsa") ||
              r.toLowerCase().includes("p=")
          );
          if (rec) return { selector: sel, record: rec };
        } catch (_) {}
        return null;
      });
      const found = (await Promise.all(promises)).filter(Boolean);
      results.push(...found);
    }
    return results;
  }

  // ---------- Analysis ----------
  function analyzeSPF(spf) {
    if (!spf) {
      return {
        status: "fail",
        score: 0,
        title: "Missing",
        summary: "No SPF record found",
        record: null,
        issues: ["Anyone can send email claiming to be from this domain."]
      };
    }

    const issues = [];
    let score = 35;
    const lower = spf.toLowerCase();

    if (lower.includes("-all")) {
      score += 35;
    } else if (lower.includes("~all")) {
      score += 18;
      issues.push("Uses softfail (~all). Switch to -all after validating all legitimate senders.");
    } else if (lower.includes("+all")) {
      score = 5;
      issues.push("Dangerous: +all allows any server to send. Remove this immediately.");
    } else if (lower.includes("?all")) {
      score += 5;
      issues.push("Neutral (?all) provides almost no protection.");
    } else {
      issues.push("No clear terminating mechanism (-all / ~all) found.");
    }

    const mechanisms = (spf.match(/\b(include|a|mx|ptr|exists|redirect):/gi) || []).length;
    if (mechanisms > 8) {
      issues.push(`High number of mechanisms detected (~${mechanisms}). Risk of exceeding the 10 DNS lookup limit.`);
      score -= 12;
    }

    if (spf.includes("%{")) {
      issues.push("Contains SPF macros. Verify they resolve as expected.");
    }

    score = Math.max(0, Math.min(100, score));

    return {
      status: score >= 65 ? "pass" : score >= 30 ? "warn" : "fail",
      score,
      title: score >= 65 ? "Good" : score >= 30 ? "Needs work" : "Weak",
      summary: spf.length > 80 ? spf.slice(0, 77) + "…" : spf,
      record: spf,
      issues
    };
  }

  function analyzeDMARC(dmarc) {
    if (!dmarc) {
      return {
        status: "fail",
        score: 0,
        title: "Missing",
        summary: "No DMARC record found",
        record: null,
        issues: ["No policy against spoofing and no visibility into abuse."]
      };
    }

    const issues = [];
    let score = 25;
    const lower = dmarc.toLowerCase();

    if (lower.includes("p=reject")) {
      score += 40;
    } else if (lower.includes("p=quarantine")) {
      score += 28;
      issues.push("Policy is quarantine. Move to p=reject when ready.");
    } else if (lower.includes("p=none")) {
      score += 12;
      issues.push("Policy is p=none (monitoring only). It does not block spoofing.");
    } else {
      issues.push("No valid policy (p=) found.");
    }

    if (lower.includes("rua=")) {
      score += 15;
    } else {
      issues.push("No rua= address. You will not receive aggregate reports.");
    }

    if (lower.includes("sp=reject") || lower.includes("sp=quarantine")) {
      score += 10;
    } else if (!lower.includes("sp=")) {
      issues.push("No explicit subdomain policy (sp=). Subdomains may be unprotected.");
    }

    if (lower.includes("aspf=s") || lower.includes("adkim=s")) {
      score += 5;
    }

    if (lower.includes("pct=") && !lower.includes("pct=100")) {
      issues.push("pct is less than 100. Only a percentage of messages are under the policy.");
    }

    score = Math.max(0, Math.min(100, score));

    return {
      status: score >= 70 ? "pass" : score >= 35 ? "warn" : "fail",
      score,
      title: score >= 70 ? "Strong" : score >= 35 ? "Partial" : "Weak",
      summary: dmarc.length > 80 ? dmarc.slice(0, 77) + "…" : dmarc,
      record: dmarc,
      issues
    };
  }

  function analyzeDKIM(records) {
    if (!records || records.length === 0) {
      return {
        status: "warn",
        score: 25,
        title: "Not found",
        summary: "No common selectors responded",
        record: null,
        issues: [
          "No DKIM keys found on common selectors. You may still have a custom selector configured with your email provider."
        ]
      };
    }

    const issues = [];
    let score = 70;

    records.forEach((r) => {
      const pMatch = r.record.match(/p=([A-Za-z0-9+/=]+)/);
      if (pMatch && pMatch[1].length < 200) {
        issues.push(`Selector “${r.selector}” appears to use a short key.`);
        score -= 8;
      }
      if (r.record.includes("p=") && (r.record.match(/p=\s*;/) || r.record.includes("p=;"))) {
        issues.push(`Selector “${r.selector}” has an empty public key (revoked?).`);
        score -= 20;
      }
    });

    score = Math.max(0, Math.min(100, score + (records.length > 1 ? 8 : 0)));

    return {
      status: score >= 60 ? "pass" : "warn",
      score,
      title: `${records.length} selector${records.length > 1 ? "s" : ""} found`,
      summary: records.map((r) => r.selector).join(", "),
      record: records,
      issues
    };
  }

  function overallScore(spf, dkim, dmarc) {
    return Math.round(spf.score * 0.30 + dkim.score * 0.25 + dmarc.score * 0.45);
  }

  // ---------- Rendering ----------
  function statusBadge(status) {
    const map = {
      pass: { bg: "bg-emerald-500/15", text: "text-emerald-400", border: "border-emerald-500/25", label: "Pass" },
      warn: { bg: "bg-amber-500/15", text: "text-amber-400", border: "border-amber-500/25", label: "Warning" },
      fail: { bg: "bg-red-500/15", text: "text-red-400", border: "border-red-500/25", label: "Fail" }
    };
    const s = map[status] || map.fail;
    return `<span class="text-xs font-medium px-2 py-0.5 rounded-full border ${s.bg} ${s.text} ${s.border}">${s.label}</span>`;
  }

  function renderStatusCard(name, analysis) {
    return `
      <div class="glass rounded-xl p-4">
        <div class="flex items-center justify-between mb-2">
          <span class="text-sm font-medium text-zinc-300">${escapeHtml(name)}</span>
          ${statusBadge(analysis.status)}
        </div>
        <p class="text-sm text-zinc-400 mb-1">${escapeHtml(analysis.title)}</p>
        <p class="text-xs text-zinc-600 font-mono truncate" title="${escapeHtml(analysis.summary || '')}">${escapeHtml(analysis.summary || "—")}</p>
      </div>
    `;
  }

  function renderDetails(spf, dkim, dmarc) {
    let html = "";

    html += `
      <div class="glass rounded-xl p-4 sm:p-5">
        <div class="flex items-center justify-between mb-3">
          <h3 class="font-medium">SPF</h3>
          ${statusBadge(spf.status)}
        </div>
        <pre class="text-xs text-zinc-400 bg-black/40 p-3 rounded-lg overflow-x-auto mb-3">${escapeHtml(spf.record || "Not found")}</pre>
        ${spf.issues.length ? `<ul class="text-sm text-amber-400/90 space-y-1">${spf.issues.map(i => `<li class="flex gap-2"><span>•</span><span>${escapeHtml(i)}</span></li>`).join("")}</ul>` : `<p class="text-sm text-zinc-500">No major issues detected.</p>`}
      </div>
    `;

    html += `
      <div class="glass rounded-xl p-4 sm:p-5">
        <div class="flex items-center justify-between mb-3">
          <h3 class="font-medium">DMARC</h3>
          ${statusBadge(dmarc.status)}
        </div>
        <pre class="text-xs text-zinc-400 bg-black/40 p-3 rounded-lg overflow-x-auto mb-3">${escapeHtml(dmarc.record || "Not found")}</pre>
        ${dmarc.issues.length ? `<ul class="text-sm text-amber-400/90 space-y-1">${dmarc.issues.map(i => `<li class="flex gap-2"><span>•</span><span>${escapeHtml(i)}</span></li>`).join("")}</ul>` : `<p class="text-sm text-zinc-500">No major issues detected.</p>`}
      </div>
    `;

    if (dkim.record && dkim.record.length) {
      html += `
        <div class="glass rounded-xl p-4 sm:p-5">
          <div class="flex items-center justify-between mb-3">
            <h3 class="font-medium">DKIM</h3>
            ${statusBadge(dkim.status)}
          </div>
          <div class="space-y-3">
            ${dkim.record.map(r => `
              <div>
                <p class="text-xs text-brand-400 mb-1 font-mono">selector: ${escapeHtml(r.selector)}</p>
                <pre class="text-xs text-zinc-500 bg-black/40 p-3 rounded-lg overflow-x-auto">${escapeHtml(r.record.length > 160 ? r.record.slice(0, 157) + "…" : r.record)}</pre>
              </div>
            `).join("")}
          </div>
          ${dkim.issues.length ? `<ul class="mt-3 text-sm text-amber-400/90 space-y-1">${dkim.issues.map(i => `<li class="flex gap-2"><span>•</span><span>${escapeHtml(i)}</span></li>`).join("")}</ul>` : ""}
        </div>
      `;
    } else {
      html += `
        <div class="glass rounded-xl p-4 sm:p-5">
          <div class="flex items-center justify-between mb-3">
            <h3 class="font-medium">DKIM</h3>
            ${statusBadge(dkim.status)}
          </div>
          <p class="text-sm text-zinc-500">${escapeHtml(dkim.issues[0] || "No DKIM records found on common selectors.")}</p>
        </div>
      `;
    }

    return html;
  }

  function generateRecommendations(spf, dkim, dmarc, domain) {
    const recs = [];
    const safeDomain = escapeHtml(domain);

    if (!spf.record) {
      recs.push({
        level: "high",
        text: `Add an SPF record for <code class="bg-white/10 px-1 rounded text-xs">${safeDomain}</code>. Example starting point: <code class="bg-white/10 px-1 rounded text-xs">v=spf1 include:_spf.google.com ~all</code> (adjust for your providers), then move to <code class="bg-white/10 px-1 rounded text-xs">-all</code>.`
      });
    } else {
      spf.issues.forEach((i) => recs.push({ level: "medium", text: escapeHtml(i) }));
    }

    if (!dmarc.record) {
      recs.push({
        level: "high",
        text: `Publish a DMARC record at <code class="bg-white/10 px-1 rounded text-xs">_dmarc.${safeDomain}</code>. Start with monitoring: <code class="bg-white/10 px-1 rounded text-xs">v=DMARC1; p=none; rua=mailto:dmarc@${safeDomain}</code>`
      });
    } else {
      dmarc.issues.forEach((i) => recs.push({ level: "medium", text: escapeHtml(i) }));
    }

    dkim.issues.forEach((i) => recs.push({ level: "low", text: escapeHtml(i) }));

    if (recs.length === 0) {
      recs.push({
        level: "low",
        text: "Configuration looks solid. Keep reviewing your DMARC aggregate reports and consider enforcing p=reject if you have not already."
      });
    }

    return recs;
  }

  function renderRecommendations(recs) {
    return recs
      .map((r) => {
        const color =
          r.level === "high" ? "text-red-400" : r.level === "medium" ? "text-amber-400" : "text-zinc-400";
        return `<li class="${color} flex gap-2"><span class="mt-0.5">•</span><span>${r.text}</span></li>`;
      })
      .join("");
  }

  function updateScoreUI(score, label, domain) {
    $("scoreValue").textContent = score;
    $("scoreLabel").textContent = label;
    $("scoreDomain").textContent = domain;

    const circle = $("scoreCircle");
    const circumference = 2 * Math.PI * 42;
    const offset = circumference - (score / 100) * circumference;
    circle.style.strokeDashoffset = offset;

    if (score >= 75) circle.setAttribute("stroke", "#34d399");
    else if (score >= 45) circle.setAttribute("stroke", "#fbbf24");
    else circle.setAttribute("stroke", "#f87171");
  }

  // ---------- Main ----------
  async function runCheck(rawInput) {
    let domain = rawInput.trim().toLowerCase();
    domain = domain.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^www\./, "");

    if (!domain || domain.length > MAX_DOMAIN_LENGTH || !DOMAIN_REGEX.test(domain)) {
      $("errorText").textContent = "Please enter a valid domain name (e.g. example.com).";
      $("errorBox").classList.remove("hidden");
      $("results").classList.add("hidden");
      return;
    }

    setLoading(true);
    $("errorBox").classList.add("hidden");
    $("results").classList.add("hidden");

    try {
      const [spfRaw, dmarcRaw, dkimRaw] = await Promise.all([
        getSPF(domain),
        getDMARC(domain),
        getDKIM(domain)
      ]);

      const spf = analyzeSPF(spfRaw);
      const dmarc = analyzeDMARC(dmarcRaw);
      const dkim = analyzeDKIM(dkimRaw);
      const score = overallScore(spf, dkim, dmarc);

      let label = "";
      if (score >= 80) label = "Strong authentication posture";
      else if (score >= 60) label = "Good, with room to improve";
      else if (score >= 35) label = "Needs attention";
      else label = "Vulnerable to spoofing";

      updateScoreUI(score, label, domain);

      $("statusCards").innerHTML =
        renderStatusCard("SPF", spf) +
        renderStatusCard("DKIM", dkim) +
        renderStatusCard("DMARC", dmarc);

      $("details").innerHTML = renderDetails(spf, dkim, dmarc);

      const recs = generateRecommendations(spf, dkim, dmarc, domain);
      $("recommendations").innerHTML = renderRecommendations(recs);

      $("results").classList.remove("hidden");
    } catch (err) {
      console.error(err);
      $("errorText").textContent = "Unable to complete the DNS lookup. Please try again in a moment.";
      $("errorBox").classList.remove("hidden");
    } finally {
      setLoading(false);
    }
  }

  // ---------- Events ----------
  $("checkForm").addEventListener("submit", (e) => {
    e.preventDefault();
    const value = $("domainInput").value;
    if (value) runCheck(value);
  });

  const params = new URLSearchParams(window.location.search);
  const prefill = params.get("domain");
  if (prefill) {
    $("domainInput").value = prefill;
    runCheck(prefill);
  }
})();
