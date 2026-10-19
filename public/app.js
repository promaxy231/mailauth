/**
 * MailAuth — Free SPF / DKIM / DMARC / MX Checker
 * Client-side only. Uses Cloudflare DNS-over-HTTPS.
 */

(function () {
  "use strict";

  const DOH = "https://cloudflare-dns.com/dns-query";
  const MAX_DOMAIN_LENGTH = 253;
  const DOMAIN_REGEX = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

  const DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2",
    "dkim", "mail", "email", "mandrill", "everlytickey1", "everlytickey2",
    "cm", "pm", "s1024", "s2048", "mx", "smtp", "postfix", "dkim1", "dkim2",
    "sig1", "sig2", "zoho", "protonmail", "fm1", "fm2", "fm3", "bigmailer",
    "scph", "hs1", "hs2", "m1", "m2"
  ];

  const $ = (id) => document.getElementById(id);

  function escapeHtml(str) {
    if (typeof str !== "string") return "";
    return str
      .replace(/&/g, "&")
      .replace(/</g, "<")
      .replace(/>/g, ">")
      .replace(/"/g, """)
      .replace(/'/g, "&#39;");
  }

  function setLoading(isLoading) {
    const btn = $("checkBtn");
    const text = $("btnText");
    const spinner = $("spinner");
    if (!btn) return;
    btn.disabled = isLoading;
    text.classList.toggle("hidden", isLoading);
    spinner.classList.toggle("hidden", !isLoading);
  }

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
    const spfRecords = records.filter((r) => r.toLowerCase().startsWith("v=spf1"));
    return {
      primary: spfRecords[0] || null,
      all: spfRecords,
      multiple: spfRecords.length > 1
    };
  }

  async function getDMARC(domain) {
    const data = await dnsQuery(`_dmarc.${domain}`, "TXT");
    const records = extractTXT(data);
    return records.find((r) => r.toLowerCase().startsWith("v=dmarc1")) || null;
  }

  async function getMX(domain) {
    try {
      const data = await dnsQuery(domain, "MX");
      if (!data || !Array.isArray(data.Answer)) return [];
      return data.Answer
        .filter((r) => r.type === 15)
        .map((r) => {
          const parts = String(r.data || "").trim().split(/\s+/);
          const priority = parseInt(parts[0], 10);
          const host = (parts[1] || "").replace(/\.$/, "");
          return { priority: isNaN(priority) ? 0 : priority, host };
        })
        .filter((m) => m.host)
        .sort((a, b) => a.priority - b.priority);
    } catch (_) {
      return [];
    }
  }

  async function getDKIM(domain, extraSelector) {
    const selectors = [...DKIM_SELECTORS];
    if (extraSelector && !selectors.includes(extraSelector.toLowerCase())) {
      selectors.unshift(extraSelector.toLowerCase().trim());
    }

    const results = [];
    const chunks = [];
    for (let i = 0; i < selectors.length; i += 6) {
      chunks.push(selectors.slice(i, i + 6));
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

  function countSPFLookups(spf) {
    if (!spf) return 0;
    const matches = spf.match(/\b(include|a|mx|ptr|exists|redirect)(?=[:\s]|$)/gi) || [];
    return matches.length;
  }

  function analyzeSPF(spfData) {
    const spf = spfData.primary;
    if (!spf) {
      return {
        status: "fail",
        score: 0,
        title: "Missing",
        summary: "No SPF record found",
        record: null,
        issues: ["Anyone can send email claiming to be from this domain."],
        lookups: 0,
        suggested: "v=spf1 include:_spf.example.com -all"
      };
    }

    const issues = [];
    let score = 30;
    const lower = spf.toLowerCase();
    const lookups = countSPFLookups(spf);

    if (spfData.multiple) {
      issues.push("Multiple SPF records found. Only one is allowed — merge them into a single record.");
      score -= 25;
    }

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

    if (lookups > 10) {
      issues.push(`Exceeds the 10 DNS lookup limit (~${lookups} mechanisms). This causes permanent SPF failures.`);
      score -= 30;
    } else if (lookups > 8) {
      issues.push(`High lookup count (~${lookups}/10). Close to the hard limit.`);
      score -= 10;
    } else if (lookups > 0) {
      score += 5;
    }

    if (spf.includes("%{")) {
      issues.push("Contains SPF macros. Verify they resolve as expected.");
    }

    score = Math.max(0, Math.min(100, score));

    let suggested = null;
    if (lookups > 10 || lower.includes("+all") || !lower.includes("-all")) {
      let cleaned = spf.replace(/\s*[~+?]?all\s*$/i, "").trim();
      if (!cleaned.toLowerCase().startsWith("v=spf1")) cleaned = "v=spf1 " + cleaned;
      suggested = cleaned + " -all";
    }

    return {
      status: score >= 65 ? "pass" : score >= 30 ? "warn" : "fail",
      score,
      title: score >= 65 ? "Good" : score >= 30 ? "Needs work" : "Weak",
      summary: spf.length > 80 ? spf.slice(0, 77) + "…" : spf,
      record: spf,
      issues,
      lookups,
      suggested
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
        issues: ["No policy against spoofing and no visibility into abuse."],
        suggested: "v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com; fo=1"
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

    let suggested = null;
    if (lower.includes("p=none") || !lower.includes("rua=")) {
      suggested = "v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com; pct=100; fo=1";
    }

    return {
      status: score >= 70 ? "pass" : score >= 35 ? "warn" : "fail",
      score,
      title: score >= 70 ? "Strong" : score >= 35 ? "Partial" : "Weak",
      summary: dmarc.length > 80 ? dmarc.slice(0, 77) + "…" : dmarc,
      record: dmarc,
      issues,
      suggested
    };
  }

  function analyzeDKIM(records) {
    if (!records || records.length === 0) {
      return {
        status: "warn",
        score: 20,
        title: "Not found",
        summary: "No common selectors responded",
        record: null,
        issues: [
          "No DKIM keys found on common selectors. Enter your provider’s custom selector above and re-check."
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
      if ((r.record.includes("p=") && r.record.match(/p=\s*;/)) || r.record.includes("p=;")) {
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

  function analyzeMX(mxList) {
    if (!mxList || mxList.length === 0) {
      return {
        status: "fail",
        score: 0,
        title: "Missing",
        summary: "No MX records",
        record: null,
        issues: ["Domain cannot receive mail. Add MX records pointing to your mail provider."]
      };
    }

    const issues = [];
    let score = 80;
    const hosts = mxList.map((m) => m.host).join(", ");

    if (mxList.some((m) => !m.host || m.host === ".")) {
      issues.push("Null MX or invalid host detected.");
      score -= 30;
    }

    return {
      status: score >= 60 ? "pass" : "warn",
      score,
      title: `${mxList.length} host${mxList.length > 1 ? "s" : ""}`,
      summary: hosts.length > 60 ? hosts.slice(0, 57) + "…" : hosts,
      record: mxList,
      issues
    };
  }

  function overallScore(spf, dkim, dmarc, mx) {
    const total =
      (spf.score * 0.3) +
      (dkim.score * 0.25) +
      (dmarc.score * 0.3) +
      (mx.score * 0.15);
    return Math.round(total);
  }

  function statusBadge(status) {
    const map = {
      pass: "bg-emerald-500/15 text-emerald-400 border-emerald-500/25",
      warn: "bg-amber-500/15 text-amber-400 border-amber-500/25",
      fail: "bg-red-500/15 text-red-400 border-red-500/25"
    };
    return map[status] || map.warn;
  }

  function renderStatusCard(name, analysis) {
    return `
      <div class="glass rounded-xl p-4">
        <div class="flex items-center justify-between mb-2">
          <span class="text-sm font-medium text-zinc-300">${escapeHtml(name)}</span>
          <span class="text-[11px] font-medium px-2 py-0.5 rounded border ${statusBadge(analysis.status)}">
            ${escapeHtml(analysis.title)}
          </span>
        </div>
        <p class="text-xs text-zinc-500 leading-relaxed break-all">${escapeHtml(analysis.summary || "—")}</p>
        ${analysis.lookups !== undefined ? `<p class="text-[11px] text-zinc-600 mt-2">~${analysis.lookups} DNS lookups</p>` : ""}
      </div>
    `;
  }

  function renderDetails(spf, dkim, dmarc, mx) {
    const blocks = [];

    blocks.push(`
      <div class="glass rounded-xl p-4">
        <div class="flex items-center gap-2 mb-2">
          <h3 class="font-medium">MX</h3>
          <span class="text-[11px] font-medium px-2 py-0.5 rounded border ${statusBadge(mx.status)}">${escapeHtml(mx.title)}</span>
        </div>
        ${mx.record && mx.record.length
          ? `<ul class="text-xs text-zinc-400 space-y-1 font-mono">${mx.record.map((m) => `<li>${m.priority} ${escapeHtml(m.host)}</li>`).join("")}</ul>`
          : `<p class="text-sm text-zinc-500">${escapeHtml(mx.issues[0] || "No MX records")}</p>`}
        ${mx.issues.length ? `<ul class="mt-2 text-xs text-amber-400/90 space-y-1">${mx.issues.map((i) => `<li>• ${escapeHtml(i)}</li>`).join("")}</ul>` : ""}
      </div>
    `);

    blocks.push(`
      <div class="glass rounded-xl p-4">
        <div class="flex items-center gap-2 mb-2">
          <h3 class="font-medium">SPF</h3>
          <span class="text-[11px] font-medium px-2 py-0.5 rounded border ${statusBadge(spf.status)}">${escapeHtml(spf.title)}</span>
        </div>
        ${spf.record
          ? `<pre class="text-xs text-zinc-400 whitespace-pre-wrap break-all font-mono bg-black/30 rounded-lg p-3">${escapeHtml(spf.record)}</pre>`
          : `<p class="text-sm text-zinc-500">${escapeHtml(spf.issues[0] || "Missing")}</p>`}
        ${spf.lookups !== undefined ? `<p class="text-[11px] text-zinc-600 mt-2">Estimated DNS lookups: ~${spf.lookups} / 10</p>` : ""}
        ${spf.issues.length ? `<ul class="mt-2 text-xs text-amber-400/90 space-y-1">${spf.issues.map((i) => `<li>• ${escapeHtml(i)}</li>`).join("")}</ul>` : ""}
      </div>
    `);

    if (dkim.record && Array.isArray(dkim.record) && dkim.record.length) {
      blocks.push(`
        <div class="glass rounded-xl p-4">
          <div class="flex items-center gap-2 mb-3">
            <h3 class="font-medium">DKIM</h3>
            <span class="text-[11px] font-medium px-2 py-0.5 rounded border ${statusBadge(dkim.status)}">${escapeHtml(dkim.title)}</span>
          </div>
          <div class="space-y-3">
            ${dkim.record.map((r) => `
              <div>
                <p class="text-xs text-brand-400 mb-1 font-mono">selector: ${escapeHtml(r.selector)}</p>
                <pre class="text-xs text-zinc-400 whitespace-pre-wrap break-all font-mono bg-black/30 rounded-lg p-3">${escapeHtml(r.record)}</pre>
              </div>
            `).join("")}
          </div>
          ${dkim.issues.length ? `<ul class="mt-2 text-xs text-amber-400/90 space-y-1">${dkim.issues.map((i) => `<li>• ${escapeHtml(i)}</li>`).join("")}</ul>` : ""}
        </div>
      `);
    } else {
      blocks.push(`
        <div class="glass rounded-xl p-4">
          <div class="flex items-center gap-2 mb-2">
            <h3 class="font-medium">DKIM</h3>
            <span class="text-[11px] font-medium px-2 py-0.5 rounded border ${statusBadge(dkim.status)}">${escapeHtml(dkim.title)}</span>
          </div>
          <p class="text-sm text-zinc-500">${escapeHtml(dkim.issues[0] || "No DKIM records found on common selectors.")}</p>
        </div>
      `);
    }

    blocks.push(`
      <div class="glass rounded-xl p-4">
        <div class="flex items-center gap-2 mb-2">
          <h3 class="font-medium">DMARC</h3>
          <span class="text-[11px] font-medium px-2 py-0.5 rounded border ${statusBadge(dmarc.status)}">${escapeHtml(dmarc.title)}</span>
        </div>
        ${dmarc.record
          ? `<pre class="text-xs text-zinc-400 whitespace-pre-wrap break-all font-mono bg-black/30 rounded-lg p-3">${escapeHtml(dmarc.record)}</pre>`
          : `<p class="text-sm text-zinc-500">${escapeHtml(dmarc.issues[0] || "Missing")}</p>`}
        ${dmarc.issues.length ? `<ul class="mt-2 text-xs text-amber-400/90 space-y-1">${dmarc.issues.map((i) => `<li>• ${escapeHtml(i)}</li>`).join("")}</ul>` : ""}
      </div>
    `);

    $("details").innerHTML = blocks.join("");
  }

  function renderSuggested(spf, dmarc) {
    const box = $("suggestedBox");
    const content = $("suggestedContent");
    const items = [];

    if (spf.suggested) {
      items.push(`
        <div>
          <p class="text-xs text-zinc-500 mb-1">Suggested SPF (TXT @ root)</p>
          <div class="flex items-start gap-2">
            <pre class="flex-1 text-xs text-zinc-300 font-mono bg-black/40 rounded-lg p-3 break-all whitespace-pre-wrap">${escapeHtml(spf.suggested)}</pre>
            <button type="button" class="copy-suggested shrink-0 px-2.5 py-1.5 text-xs rounded-lg bg-brand-500/20 text-brand-400 border border-brand-500/30 hover:bg-brand-500/30" data-text="${escapeHtml(spf.suggested)}">Copy</button>
          </div>
        </div>
      `);
    }
    if (dmarc.suggested) {
      items.push(`
        <div>
          <p class="text-xs text-zinc-500 mb-1">Suggested DMARC (TXT @ _dmarc)</p>
          <div class="flex items-start gap-2">
            <pre class="flex-1 text-xs text-zinc-300 font-mono bg-black/40 rounded-lg p-3 break-all whitespace-pre-wrap">${escapeHtml(dmarc.suggested)}</pre>
            <button type="button" class="copy-suggested shrink-0 px-2.5 py-1.5 text-xs rounded-lg bg-brand-500/20 text-brand-400 border border-brand-500/30 hover:bg-brand-500/30" data-text="${escapeHtml(dmarc.suggested)}">Copy</button>
          </div>
          <p class="text-[11px] text-zinc-600 mt-1">Replace dmarc@yourdomain.com with a real mailbox you control.</p>
        </div>
      `);
    }

    if (items.length === 0) {
      box.classList.add("hidden");
      return;
    }
    content.innerHTML = items.join("");
    box.classList.remove("hidden");

    content.querySelectorAll(".copy-suggested").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const text = btn.getAttribute("data-text");
        try {
          await navigator.clipboard.writeText(text);
          const orig = btn.textContent;
          btn.textContent = "Copied";
          setTimeout(() => (btn.textContent = orig), 1500);
        } catch (_) {}
      });
    });
  }

  function generateRecommendations(spf, dkim, dmarc, mx, domain) {
    const recs = [];

    if (mx.status === "fail") {
      recs.push("Add MX records so the domain can receive mail. Point them to your provider (Google, Microsoft, etc.).");
    }
    if (spf.status === "fail" || !spf.record) {
      recs.push(`Publish a single SPF TXT record on ${domain}. Start with your provider’s include and end with -all.`);
    } else if (spf.lookups > 10) {
      recs.push("Flatten or remove unused SPF includes so the total stays under 10 DNS lookups.");
    } else if (spf.record.toLowerCase().includes("~all") || spf.record.toLowerCase().includes("+all")) {
      recs.push("Tighten the SPF terminator to -all after confirming every legitimate sender is listed.");
    }
    if (dkim.status !== "pass") {
      recs.push("Enable DKIM in your email provider and publish the key. Use the custom selector field if the key isn’t under a common name.");
    }
    if (dmarc.status === "fail" || !dmarc.record) {
      recs.push(`Add a DMARC record at _dmarc.${domain}. Start with p=none and a rua address, then move to quarantine/reject.`);
    } else if (dmarc.record.toLowerCase().includes("p=none")) {
      recs.push("Review aggregate reports, then raise DMARC policy to p=quarantine and eventually p=reject.");
    }
    if (!dmarc.record || !dmarc.record.toLowerCase().includes("rua=")) {
      recs.push("Add a rua= address so you receive DMARC aggregate reports.");
    }
    if (recs.length === 0) {
      recs.push("Authentication looks solid. Keep monitoring reports and re-check after any provider change.");
    }
    return recs;
  }

  function renderRecommendations(recs) {
    $("recommendations").innerHTML = recs
      .map((r) => `<li class="flex gap-2"><span class="text-brand-400 mt-0.5">→</span><span class="text-zinc-300">${escapeHtml(r)}</span></li>`)
      .join("");
  }

  function updateScoreUI(score, label, domain) {
    $("scoreValue").textContent = score;
    $("scoreLabel").textContent = label;
    $("scoreDomain").textContent = domain;
    const circle = $("scoreCircle");
    const offset = 264 - (264 * Math.min(100, Math.max(0, score))) / 100;
    circle.style.strokeDashoffset = offset;
    if (score >= 70) circle.setAttribute("stroke", "#34d399");
    else if (score >= 40) circle.setAttribute("stroke", "#fbbf24");
    else circle.setAttribute("stroke", "#f87171");
  }

  function normalizeDomain(input) {
    let d = (input || "").trim().toLowerCase();
    d = d.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/:.*$/, "");
    if (d.includes("@")) d = d.split("@").pop();
    return d;
  }

  async function runCheck(rawInput, customSelector) {
    const domain = normalizeDomain(rawInput);
    const errorBox = $("errorBox");
    const results = $("results");

    errorBox.classList.add("hidden");
    results.classList.add("hidden");

    if (!domain || domain.length > MAX_DOMAIN_LENGTH || !DOMAIN_REGEX.test(domain)) {
      $("errorText").textContent = "Enter a valid domain (e.g. example.com)";
      errorBox.classList.remove("hidden");
      return;
    }

    setLoading(true);

    try {
      const [spfData, dmarc, dkimRecords, mxList] = await Promise.all([
        getSPF(domain),
        getDMARC(domain),
        getDKIM(domain, customSelector),
        getMX(domain)
      ]);

      const spf = analyzeSPF(spfData);
      const dkim = analyzeDKIM(dkimRecords);
      const dmarcA = analyzeDMARC(dmarc);
      const mx = analyzeMX(mxList);

      const score = overallScore(spf, dkim, dmarcA, mx);
      let label = "Needs improvement";
      if (score >= 80) label = "Excellent";
      else if (score >= 65) label = "Good";
      else if (score >= 40) label = "Fair";

      updateScoreUI(score, label, domain);
      $("statusCards").innerHTML =
        renderStatusCard("MX", mx) +
        renderStatusCard("SPF", spf) +
        renderStatusCard("DKIM", dkim) +
        renderStatusCard("DMARC", dmarcA);

      renderDetails(spf, dkim, dmarcA, mx);
      renderSuggested(spf, dmarcA);
      renderRecommendations(generateRecommendations(spf, dkim, dmarcA, mx, domain));

      results.classList.remove("hidden");
      results.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (err) {
      $("errorText").textContent = "Lookup failed. Check your connection and try again.";
      errorBox.classList.remove("hidden");
      console.error(err);
    } finally {
      setLoading(false);
    }
  }

  $("checkForm").addEventListener("submit", (e) => {
    e.preventDefault();
    runCheck($("domainInput").value, $("selectorInput").value);
  });

  document.querySelectorAll(".example-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const d = btn.getAttribute("data-domain");
      $("domainInput").value = d;
      runCheck(d, $("selectorInput").value);
    });
  });
})();
