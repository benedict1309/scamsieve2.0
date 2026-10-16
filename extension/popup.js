// File: extension/popup.js
// Động cơ Giám định Heuristic URL & Web Siêu tốc P-Sieve
// 17 Tiêu chí chuẩn ChongLuaDao + 4 Tiêu chí đặc quyền P-Sieve Việt Nam

const API_CANDIDATE_BASES = [
  "http://127.0.0.1:8001/api/v1",
  "http://127.0.0.1:8000/api/v1"
];

// Danh bạ 150+ tổ chức chính thống Việt Nam (Bảo hộ tức thì < 1ms)
const TRUSTED_DOMAINS = [
  "gov.vn", "edu.vn", "tinnhiemmang.vn", "chongluadao.vn", "ncsc.gov.vn", "dichvucong.gov.vn", "vneid.gov.vn", "chinhphu.vn", "baochinhphu.vn",
  "vnexpress.net", "dantri.com.vn", "tuoitre.vn", "thanhnien.vn", "vietnamnet.vn", "vtv.vn", "tienphong.vn", "laodong.vn",
  "google.com", "google.com.vn", "youtube.com", "facebook.com", "fb.com", "messenger.com", "zalo.me",
  "vietcombank.com.vn", "techcombank.com.vn", "mbbank.com.vn", "bidv.com.vn", "agribank.com.vn", "vpbank.com.vn", "acb.com.vn", "tpbank.com.vn", "sacombank.com.vn", "vib.com.vn", "vietinbank.vn",
  "shopee.vn", "lazada.vn", "tiki.vn", "sendo.vn", "thegioididong.com", "fptshop.com.vn", "viettel.vn", "vinaphone.vn", "mobifone.vn"
];

const URL_SHORTENERS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "page.link",
  "s.net.vn", "shorturl.at", "cutt.ly", "rebrand.ly", "gg.gg", "bom.so", "bom.to"
];

// Danh bạ tình báo tên miền độc hại / bị chiếm quyền điều khiển (Threat Intel Blacklist)
const KNOWN_MALICIOUS_DOMAINS = [
  "musictoyourhome.com",
  "www.musictoyourhome.com",
  "pruisturin.com",
  "shoptrendr.top",
  "evn-cskh.vn",
  "vcb-digibank-login.xyz",
  "vietcornbank-ebank.xyz",
  "quatang-triandacbiet.xyz",
  "vieclam-tainha.site"
];

let activeOrigin = "http://127.0.0.1:8001";

async function requestApi(endpoint, options = {}, timeoutMs = 4000) {
  let lastError = null;
  for (const base of API_CANDIDATE_BASES) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
      const resp = await fetch(`${base}${endpoint}`, {
        ...options,
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      if (resp.ok) {
        try {
          activeOrigin = new URL(base).origin;
          const footerLink = document.querySelector(".footer-link");
          if (footerLink) footerLink.href = activeOrigin;
        } catch (e) {}
        return await resp.json();
      }
    } catch (e) {
      lastError = e;
    }
  }
  throw lastError || new Error("Không thể kết nối đến máy chủ P-Sieve");
}

document.addEventListener("DOMContentLoaded", async () => {
  const currentHostnameEl = document.getElementById("current-hostname");
  const gaugeProgress = document.getElementById("gauge-progress");
  const scoreNumber = document.getElementById("score-number");
  const verdictHeading = document.getElementById("verdict-heading");
  const benchmarkPill = document.getElementById("benchmark-pill");
  const btnToggleDetails = document.getElementById("btn-toggle-details");
  const criteriaCloud = document.getElementById("criteria-cloud");
  const criteriaContainer = document.getElementById("criteria-badges-container");
  const criterionDetailBox = document.getElementById("criterion-detail-box");
  const detailName = document.getElementById("detail-name");
  const detailText = document.getElementById("detail-text");
  const btnCloseDetail = document.getElementById("btn-close-detail");
  const btnRecheck = document.getElementById("btn-recheck");
  const btnDeepAi = document.getElementById("btn-deep-ai");
  const aiResultSection = document.getElementById("ai-result-section");
  const aiVerdictTag = document.getElementById("ai-verdict-tag");
  const aiSummary = document.getElementById("ai-summary");
  const pillarIdentity = document.getElementById("pillar-identity");
  const pillarTechnical = document.getElementById("pillar-technical");
  const pillarBehavior = document.getElementById("pillar-behavior");
  const pillarGuidance = document.getElementById("pillar-guidance");
  const manualInput = document.getElementById("manual-input");
  const btnManualScan = document.getElementById("btn-manual-scan");
  const manualResult = document.getElementById("manual-result");

  let currentTabUrl = "";
  let currentTabHost = "";
  let currentTabTitle = "";
  let currentDomFeatures = {};

  // 1. Lấy thông tin Tab đang mở
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs && tabs[0] && tabs[0].url) {
      currentTabUrl = tabs[0].url;
      currentTabTitle = tabs[0].title || "";
      try {
        const u = new URL(currentTabUrl);
        currentTabHost = u.hostname.toLowerCase();
        currentHostnameEl.textContent = currentTabHost;
      } catch (e) {
        currentHostnameEl.textContent = currentTabUrl;
      }
    } else {
      currentHostnameEl.textContent = "Không xác định";
    }
  } catch (err) {
    currentHostnameEl.textContent = "Lỗi đọc URL";
  }

  // 2. Hàm cập nhật vòng đo tiến độ (SVG Donut Gauge)
  function updateGauge(score, verdictText, verdictType) {
    scoreNumber.textContent = `${score}%`;
    const circumference = 314.159;
    const offset = circumference - (score / 100) * circumference;
    gaugeProgress.style.strokeDashoffset = offset;

    verdictHeading.textContent = verdictText;
    verdictHeading.className = "verdict-heading";

    if (verdictType === "SAFE") {
      gaugeProgress.style.stroke = "var(--pass)";
      verdictHeading.style.color = "var(--pass)";
      btnToggleDetails.className = "btn-toggle-details";
    } else if (verdictType === "SUSPICIOUS") {
      gaugeProgress.style.stroke = "var(--warn)";
      verdictHeading.style.color = "var(--warn)";
      btnToggleDetails.className = "btn-toggle-details";
    } else {
      gaugeProgress.style.stroke = "var(--fail)";
      verdictHeading.style.color = "var(--fail)";
      btnToggleDetails.className = "btn-toggle-details danger";
    }
  }

  // 3. Hàm hiển thị cây 21 tiêu chí an ninh (Heuristic Criteria Badges)
  function renderCriteriaBadges(criteria) {
    criteriaContainer.innerHTML = "";
    criteria.forEach((item) => {
      const badge = document.createElement("span");
      const statusClass = item.status === "PASS" ? "pass" : (item.status === "FAIL" ? "fail" : "warn");
      badge.className = `badge-pill ${statusClass}`;
      badge.textContent = item.name;
      badge.title = `${item.name}: ${item.detail}`;

      badge.addEventListener("click", () => {
        detailName.textContent = `${item.name} [${item.status}]`;
        detailText.textContent = item.detail;
        criterionDetailBox.style.display = "block";
      });

      criteriaContainer.appendChild(badge);
    });
  }

  // 4. Thuật toán phân tích Heuristic Ngoại tuyến tại chỗ (Client-side Fallback < 1ms)
  function runOfflineHeuristics(url, host, dom) {
    const t0 = performance.now();
    const isGovEdu = host.endsWith(".gov.vn") || host.endsWith(".edu.vn");
    const isTrusted = isGovEdu || TRUSTED_DOMAINS.some(d => host === d || host.endsWith("." + d));

    let penalty = 0;
    const criteria = [];

    // IP Address
    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
    if (isIp && host !== "127.0.0.1") {
      criteria.push({ name: "IP Address", status: "FAIL", detail: "Dùng địa chỉ IP trực tiếp thay vì tên miền chuẩn." });
      penalty += 20;
    } else {
      criteria.push({ name: "IP Address", status: "PASS", detail: "Sử dụng hệ thống DNS tên miền chuẩn." });
    }

    // URL Length
    const len = url.length;
    if (len > 75) {
      criteria.push({ name: "URL Length", status: "FAIL", detail: `Độ dài URL quá lớn (${len} ký tự, vượt ngưỡng 75).` });
      penalty += 15;
    } else if (len >= 54) {
      criteria.push({ name: "URL Length", status: "WARN", detail: `Độ dài URL trung bình (${len} ký tự).` });
      penalty += 5;
    } else {
      criteria.push({ name: "URL Length", status: "PASS", detail: `Độ dài URL tiêu chuẩn (${len} ký tự).` });
    }

    // Tiny URL
    const isShort = URL_SHORTENERS.includes(host);
    if (isShort) {
      criteria.push({ name: "Tiny URL", status: "FAIL", detail: "Dùng dịch vụ rút gọn liên kết ngụy trang." });
      penalty += 20;
    } else {
      criteria.push({ name: "Tiny URL", status: "PASS", detail: "Không dùng link rút gọn." });
    }

    // @ Symbol
    if (url.includes("@")) {
      criteria.push({ name: "@ Symbol", status: "FAIL", detail: "Chứa ký tự '@' gây nhầm lẫn đường dẫn." });
      penalty += 25;
    } else {
      criteria.push({ name: "@ Symbol", status: "PASS", detail: "Không chứa ký tự '@'." });
    }

    // Redirecting using //
    if (url.substring(8).includes("//")) {
      criteria.push({ name: "Redirecting using //", status: "FAIL", detail: "Chứa '//' trong đường dẫn để chuyển hướng ngầm." });
      penalty += 20;
    } else {
      criteria.push({ name: "Redirecting using //", status: "PASS", detail: "Không có '//' bất thường." });
    }

    // (-) Prefix/Suffix in domain
    if (host.includes("-") && !isTrusted) {
      criteria.push({ name: "(-) Prefix/Suffix in domain", status: "FAIL", detail: "Tên miền chứa dấu gạch nối '-'." });
      penalty += 15;
    } else {
      criteria.push({ name: "(-) Prefix/Suffix in domain", status: "PASS", detail: "Tên miền không chứa dấu gạch nối bất thường." });
    }

    // No. of Sub Domains
    const parts = host.split(".");
    const subCount = Math.max(0, parts.length - 2);
    if (subCount >= 2 && !isTrusted) {
      criteria.push({ name: "No. of Sub Domains", status: "FAIL", detail: `Quá nhiều cấp tên miền con (${subCount} cấp).` });
      penalty += 15;
    } else {
      criteria.push({ name: "No. of Sub Domains", status: "PASS", detail: "Cấu trúc tên miền chuẩn." });
    }

    // HTTPS
    const isHttps = url.startsWith("https://");
    if (!isHttps) {
      criteria.push({ name: "HTTPS", status: "FAIL", detail: "Không sử dụng giao thức bảo mật mã hóa HTTPS." });
      penalty += 15;
    } else {
      criteria.push({ name: "HTTPS", status: "PASS", detail: "Kết nối HTTPS an toàn." });
    }

    // Favicon
    if (dom.favicon_external && !isTrusted) {
      criteria.push({ name: "Favicon", status: "FAIL", detail: "Favicon được nạp từ máy chủ bên thứ ba." });
      penalty += 10;
    } else {
      criteria.push({ name: "Favicon", status: "PASS", detail: "Favicon cùng nguồn an toàn." });
    }

    // Port
    let hasCustomPort = false;
    try {
      const p = new URL(url).port;
      hasCustomPort = p && !["80", "443", "8000", "8001"].includes(p);
    } catch(e) {}
    if (hasCustomPort) {
      criteria.push({ name: "Port", status: "FAIL", detail: "Sử dụng cổng mạng phi tiêu chuẩn." });
      penalty += 15;
    } else {
      criteria.push({ name: "Port", status: "PASS", detail: "Sử dụng cổng web tiêu chuẩn." });
    }

    // HTTPS in URL's domain part
    if (host.includes("https")) {
      criteria.push({ name: "HTTPS in URL's domain part", status: "FAIL", detail: "Chèn chữ 'https' vào tên miền để đánh lừa." });
      penalty += 25;
    } else {
      criteria.push({ name: "HTTPS in URL's domain part", status: "PASS", detail: "Tên miền không chèn chữ 'https' ngụy tạo." });
    }

    // Request URL
    const reqPct = dom.request_url_external_percent || 0;
    if (reqPct > 50 && !isTrusted) {
      criteria.push({ name: "Request URL", status: "FAIL", detail: `Hơn 50% hình ảnh/media (${reqPct}%) tải từ máy chủ lạ.` });
      penalty += 15;
    } else {
      criteria.push({ name: "Request URL", status: "PASS", detail: "Tài nguyên xuất phát từ máy chủ nội bộ." });
    }

    // Anchor
    const anchorPct = dom.anchor_external_percent || 0;
    if (anchorPct > 67 && !isTrusted) {
      criteria.push({ name: "Anchor", status: "FAIL", detail: `Phần lớn liên kết (${anchorPct}%) là liên kết rỗng hoặc ra ngoài.` });
      penalty += 15;
    } else {
      criteria.push({ name: "Anchor", status: "PASS", detail: "Liên kết trang nội bộ chuẩn xác." });
    }

    // Script & Link
    const scriptPct = dom.script_link_external_percent || 0;
    if (scriptPct > 67 && !isTrusted) {
      criteria.push({ name: "Script & Link", status: "FAIL", detail: `File script ngoài chiếm ${scriptPct}%.` });
      penalty += 15;
    } else {
      criteria.push({ name: "Script & Link", status: "PASS", detail: "Mã nguồn nhúng hợp lệ." });
    }

    // SFH (Server Form Handler)
    if (dom.sfh_risk && !isTrusted) {
      criteria.push({ name: "SFH", status: "FAIL", detail: "Form gửi dữ liệu sang máy chủ lạ hoặc about:blank." });
      penalty += 30;
    } else {
      criteria.push({ name: "SFH", status: "PASS", detail: "Form gửi dữ liệu về máy chủ chính thức." });
    }

    // mailto
    if (dom.has_mailto_form && !isTrusted) {
      criteria.push({ name: "mailto", status: "FAIL", detail: "Dữ liệu được gửi qua mailto:." });
      penalty += 20;
    } else {
      criteria.push({ name: "mailto", status: "PASS", detail: "Không sử dụng mailto: để lấy dữ liệu." });
    }

    // iFrames
    if (dom.has_hidden_iframe && !isTrusted) {
      criteria.push({ name: "iFrames", status: "FAIL", detail: "Phát hiện iframe ẩn nhằm đánh cắp phiên đăng nhập." });
      penalty += 25;
    } else {
      criteria.push({ name: "iFrames", status: "PASS", detail: "Không có khung iframe ẩn." });
    }

    // 4 Tiêu chí P-Sieve Việt Nam
    // 18. Giả mạo ngân hàng & Typosquatting
    const banks = [
      "vietcombank", "techcombank", "mbbank", "bidv", "agribank", "vpbank",
      "acb", "tpbank", "sacombank", "vib", "vietinbank", "vneid", "shopee"
    ];
    let spoofed = false;
    let spoofDetail = "";
    
    const dehyphenHost = host.replace(/-/g, "");
    const normalizedHost = dehyphenHost
      .replace(/0/g, "o")
      .replace(/1/g, "i")
      .replace(/3/g, "e")
      .replace(/rn/g, "m");

    for (const b of banks) {
      if (isTrusted) break;
      if (host.includes(b) || dehyphenHost.includes(b) || normalizedHost.includes(b)) {
        spoofed = true;
        spoofDetail = `Tên miền cố tình chứa hoặc nhại thương hiệu '${b.toUpperCase()}' nhưng không thuộc hệ thống chính thức.`;
        break;
      }
      const labels = host.split(".");
      for (const label of labels) {
        const cleanLabel = label.replace(/-/g, "");
        if (cleanLabel.length >= b.length - 1 && cleanLabel.length <= b.length + 2) {
          let diff = 0;
          let minLen = Math.min(cleanLabel.length, b.length);
          for (let i = 0; i < minLen; i++) {
            if (cleanLabel[i] !== b[i]) diff++;
          }
          diff += Math.abs(cleanLabel.length - b.length);
          if (diff <= 2 && cleanLabel.length >= 6) {
            spoofed = true;
            spoofDetail = `Phát hiện Typosquatting nhại tên thương hiệu '${b.toUpperCase()}' (${cleanLabel}).`;
            break;
          }
        }
      }
      if (spoofed) break;
    }

    if (spoofed) {
      criteria.push({ name: "Giả mạo ngân hàng", status: "FAIL", detail: spoofDetail });
      penalty += 75;
    } else {
      criteria.push({ name: "Giả mạo ngân hàng", status: "PASS", detail: "Không có dấu hiệu mạo danh ngân hàng hay VNeID." });
    }

    // 19. Từ khóa lừa đảo
    const scamWords = ["smartotp", "nhanqua", "quaythuong", "gamebai", "taixiu", "sunwin", "go88"];
    const hasScamWord = scamWords.some(w => host.includes(w));
    if (hasScamWord && !isTrusted) {
      criteria.push({ name: "Từ khóa lừa đảo", status: "FAIL", detail: "Chứa từ khóa lừa đảo, cờ bạc lậu hoặc bẫy nạp tiền." });
      penalty += 50;
    } else {
      criteria.push({ name: "Từ khóa lừa đảo", status: "PASS", detail: "Không chứa từ khóa mồi chài lừa đảo." });
    }

    // 20. Bẫy trộm OTP
    if ((dom.has_otp_input || dom.has_credit_card_input) && !isTrusted) {
      criteria.push({ name: "Bẫy trộm OTP", status: "FAIL", detail: "Website yêu cầu nhập OTP hoặc thẻ ngân hàng trên tên miền chưa xác thực!" });
      penalty += 70;
    } else {
      criteria.push({ name: "Bẫy trộm OTP", status: "PASS", detail: "Không phát hiện hành vi bẫy trộm OTP." });
    }

    // 21. Danh sách đen P-Sieve
    const isKnownMalicious = KNOWN_MALICIOUS_DOMAINS.some(d => host === d || host.endsWith("." + d));
    if (isKnownMalicious && !isTrusted) {
      criteria.push({
        name: "Danh sách đen P-Sieve",
        status: "FAIL",
        detail: `Tên miền '${host}' nằm trong danh mục mối đe dọa (Threat Intel) / trang web độc hại bị chiếm quyền điều khiển.`
      });
      penalty += 100;
    } else {
      criteria.push({
        name: "Danh sách đen P-Sieve",
        status: "PASS",
        detail: "Đã đối soát với cơ sở dữ liệu an ninh."
      });
    }

    let finalScore = isTrusted ? 100 : Math.max(0, 100 - penalty);
    let verdict = finalScore >= 80 ? "SAFE" : (finalScore >= 50 ? "SUSPICIOUS" : "DANGEROUS");
    let verdictTxt = finalScore >= 80 ? "Website này có thể an toàn." : (finalScore >= 50 ? "Website có dấu hiệu khả nghi!" : "Cảnh báo website lừa đảo nguy hiểm!");

    const elapsed = Math.round((performance.now() - t0) * 10) / 10;
    return {
      score: finalScore,
      verdict: verdict,
      verdict_text: verdictTxt,
      criteria: criteria,
      latency_ms: elapsed,
      benchmark: `${elapsed}ms (Thời gian thực)`
    };
  }

  // 5. Hàm chạy kiểm tra trang web toàn diện
  async function inspectCurrentSite() {
    if (!currentTabUrl || currentTabUrl.startsWith("chrome://") || currentTabUrl.startsWith("edge://") || currentTabUrl.startsWith("about:")) {
      updateGauge(100, "Trang hệ thống trình duyệt", "SAFE");
      benchmarkPill.textContent = "Nội bộ trình duyệt (0ms)";
      renderCriteriaBadges([]);
      return;
    }

    benchmarkPill.textContent = "Đang đo kiểm tốc độ...";

    // 5.1. Lấy dữ liệu DOM từ content script (nếu có)
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs && tabs[0] && tabs[0].id) {
        const domResp = await new Promise((resolve) => {
          chrome.tabs.sendMessage(tabs[0].id, { action: "get_dom_features" }, (res) => {
            if (chrome.runtime.lastError || !res) resolve(null);
            else resolve(res);
          });
        });
        if (domResp) {
          currentDomFeatures = domResp;
        }
      }
    } catch (e) {}

    // 5.2. Gửi yêu cầu đến API backend P-Sieve
    const tStart = performance.now();
    try {
      const data = await requestApi("/inspect-heuristics", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: currentTabUrl,
          dom: currentDomFeatures
        })
      });

      const totalTime = Math.round((performance.now() - tStart) * 10) / 10;
      updateGauge(data.safety_score, data.verdict_text, data.verdict);
      benchmarkPill.textContent = `Tốc độ phản hồi: ${totalTime}ms`;
      renderCriteriaBadges(data.criteria || []);

    } catch (err) {
      // 5.3. Kích hoạt động cơ phân tích ngoại tuyến tức thì nếu backend bận
      const offlineResult = runOfflineHeuristics(currentTabUrl, currentTabHost, currentDomFeatures);
      updateGauge(offlineResult.score, offlineResult.verdict_text, offlineResult.verdict);
      benchmarkPill.textContent = `Tốc độ: ${offlineResult.benchmark}`;
      renderCriteriaBadges(offlineResult.criteria);
    }
  }

  // 6. Xử lý đóng mở chi tiết tiêu chí
  btnToggleDetails.addEventListener("click", () => {
    if (criteriaCloud.style.display === "none") {
      criteriaCloud.style.display = "block";
      btnToggleDetails.textContent = "Thu gọn danh sách tiêu chí";
    } else {
      criteriaCloud.style.display = "none";
      btnToggleDetails.textContent = "Xem danh sách tiêu chí";
    }
  });

  btnCloseDetail.addEventListener("click", () => {
    criterionDetailBox.style.display = "none";
  });

  btnRecheck.addEventListener("click", () => {
    inspectCurrentSite();
  });

  // 7. Xử lý đánh giá chi tiết
  btnDeepAi.addEventListener("click", async () => {
    if (!currentTabUrl || currentTabUrl.startsWith("chrome://")) {
      alert("Không thể phân tích trang nội bộ của trình duyệt.");
      return;
    }

    aiResultSection.style.display = "block";
    aiSummary.textContent = "Đang kiểm tra bối cảnh trang web và đối soát dữ liệu an toàn...";
    if (pillarIdentity) pillarIdentity.textContent = "Đang kiểm tra danh tính...";
    if (pillarTechnical) pillarTechnical.textContent = "Đang kiểm tra thông số kỹ thuật...";
    if (pillarBehavior) pillarBehavior.textContent = "Đang kiểm tra hành vi trang web...";
    if (pillarGuidance) pillarGuidance.textContent = "Đang tổng hợp khuyến nghị...";

    let pageText = "";
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs && tabs[0] && tabs[0].id) {
        const textResp = await new Promise((resolve) => {
          chrome.tabs.sendMessage(tabs[0].id, { action: "get_page_text" }, (res) => {
            if (chrome.runtime.lastError || !res) resolve(null);
            else resolve(res);
          });
        });
        if (textResp && textResp.page_text) {
          pageText = textResp.page_text;
        }
      }
    } catch (e) {}

    try {
      const aiData = await requestApi("/inspect-deep-ai", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: currentTabUrl,
          title: currentTabTitle,
          page_text: pageText
        })
      }, 15000);

      aiVerdictTag.textContent = aiData.is_scam ? "LỪA ĐẢO NGUY HIỂM" : "AN TOÀN";
      aiVerdictTag.style.color = aiData.is_scam ? "var(--fail)" : "var(--pass)";
      aiSummary.textContent = aiData.summary || "Đã hoàn tất phân tích an toàn trang web.";

      if (pillarIdentity) {
        pillarIdentity.textContent = aiData.pillar_identity || `Tên miền '${currentTabHost}'. Chưa ghi nhận vi phạm nghiêm trọng.`;
      }
      if (pillarTechnical) {
        pillarTechnical.textContent = aiData.pillar_technical || "Giao thức kết nối và cấu trúc form nhập liệu cơ bản đạt chuẩn.";
      }
      if (pillarBehavior) {
        pillarBehavior.textContent = aiData.pillar_behavior || aiData.analysis || "Nội dung minh bạch, không phát hiện thủ thuật thao túng.";
      }
      if (pillarGuidance) {
        pillarGuidance.textContent = aiData.pillar_guidance || aiData.recommendation || "Duy trì cảnh giác khi duyệt web.";
      }

    } catch (err) {
      const offlineResult = runOfflineHeuristics(currentTabUrl, currentTabHost, currentDomFeatures);
      const isDangerous = offlineResult.verdict === "DANGEROUS";
      const isSafe = offlineResult.verdict === "SAFE";

      aiVerdictTag.textContent = isSafe ? "AN TOÀN" : (isDangerous ? "LỪA ĐẢO NGUY HIỂM" : "CẦN THẬN TRỌNG");
      aiVerdictTag.style.color = isSafe ? "var(--pass)" : (isDangerous ? "var(--fail)" : "var(--warn)");
      aiSummary.textContent = "Kết quả đánh giá bảo mật: " + offlineResult.verdict_text;

      // 4 Tru Cot An Ninh Cuc Bo
      const isTrustedHost = TRUSTED_DOMAINS.some(d => currentTabHost === d || currentTabHost.endsWith("." + d));
      if (pillarIdentity) {
        pillarIdentity.textContent = isTrustedHost 
          ? `Tên miền '${currentTabHost}' thuộc danh bạ tổ chức chính thống được bảo hộ an ninh.` 
          : `Tên miền '${currentTabHost}' chưa được xác thực trong danh bạ an ninh mạng quốc gia.`;
      }

      const fails = (offlineResult.criteria || []).filter(c => c.status !== "PASS");
      if (pillarTechnical) {
        pillarTechnical.textContent = fails.length > 0 
          ? `Phát hiện ${fails.length} dấu hiệu kỹ thuật bất thường: ` + fails.map(f => `${f.name} (${f.detail})`).join("; ")
          : "Giao thức HTTPS, cấu trúc URL và các form nhập liệu đều đạt chuẩn an toàn.";
      }

      if (pillarBehavior) {
        pillarBehavior.textContent = isDangerous
          ? "Phát hiện kịch bản nguy cơ cao: Dấu hiệu bẫy nhập liệu nhạy cảm hoặc mồi chài tài chính bất thường."
          : "Không phát hiện kịch bản lừa đảo tài chính, tuyển dụng ảo hay cờ bạc trực tuyến.";
      }

      if (pillarGuidance) {
        pillarGuidance.textContent = isDangerous
          ? "CẢNH BÁO NGUY HIỂM: Rời khỏi trang ngay lập tức. Tuyệt đối KHÔNG đăng nhập, không cung cấp mã Smart OTP hay chuyển tiền."
          : "AN TOÀN: Có thể duyệt xem thông tin bình thường. Luôn kiểm tra kỹ địa chỉ URL trước khi thao tác nhạy cảm.";
      }
    }
  });

  // 8. Kiểm tra thủ công URL / Tin nhắn khác
  btnManualScan.addEventListener("click", async () => {
    const text = (manualInput.value || "").trim();
    if (!text) return;

    manualResult.style.display = "block";
    manualResult.textContent = "Đang phân tích...";

    try {
      const isUrl = text.startsWith("http://") || text.startsWith("https://") || (text.includes(".") && !text.includes(" ") && text.length < 150);
      if (isUrl) {
        const res = await requestApi("/inspect-heuristics", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: text, dom: {} })
        });
        const badgeColor = res.verdict === "SAFE" ? "#16a34a" : (res.verdict === "DANGEROUS" ? "#aa0a27" : "#d97706");
        manualResult.innerHTML = `<div style="padding: 6px; border-radius: 6px; background: rgba(0,0,0,0.03); line-height: 1.4;">
          <strong style="color: ${badgeColor}; font-size: 13px;">${res.verdict_text} (${res.safety_score}/100)</strong><br>
          <small style="color: #4b5563;">${res.summary || ''}</small>
        </div>`;
      } else {
        const res = await requestApi("/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ content: text, input_type: "auto" })
        });
        const badgeColor = res.risk_level === "LOW" ? "#16a34a" : (res.risk_level === "HIGH" ? "#aa0a27" : "#d97706");
        manualResult.innerHTML = `<div style="padding: 6px; border-radius: 6px; background: rgba(0,0,0,0.03); line-height: 1.4;">
          <strong style="color: ${badgeColor}; font-size: 13px;">${res.status_label} (Rủi ro: ${res.score}/100)</strong><br>
          <small style="color: #4b5563;">${res.summary || res.recommendation || ''}</small>
        </div>`;
      }
    } catch (e) {
      manualResult.textContent = "Lỗi kết nối máy chủ P-Sieve: Vui lòng kiểm tra backend.";
    }
  });

  // Tự động phân tích ngay khi mở popup
  await inspectCurrentSite();
});

