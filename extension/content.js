// File: extension/content.js
// Giám sát an ninh trang web theo thời gian thực (Deep DOM Real-time Web Shield)

(async function () {
  const currentUrl = window.location.href;
  const currentHost = window.location.hostname.toLowerCase();

  // Bo qua cac trang noi bo hoac localhost dev (ngoai tru phong thu nghiem an ninh /test-shield hoac test_lab)
  const isTestingPage = currentUrl.includes("test-shield") || currentUrl.includes("test_lab");
  if (
    !isTestingPage && (
      currentUrl.startsWith("chrome://") ||
      currentUrl.startsWith("edge://") ||
      currentUrl.startsWith("about:") ||
      currentUrl.startsWith("http://127.0.0.1") ||
      currentUrl.startsWith("http://localhost")
    )
  ) {
    return;
  }

  // Danh mục trang web chính thống đã xác thực (Bảo hộ toàn diện)
  const TRUSTED_DOMAINS = [
    // Cổng thông tin Chính phủ & Cơ quan Nhà nước
    "tinnhiemmang.vn", "chongluadao.vn", "ncsc.gov.vn", "dichvucong.gov.vn", "vneid.gov.vn", "chinhphu.vn", "baochinhphu.vn",
    // Báo chí & Truyền hình chính thống
    "vnexpress.net", "dantri.com.vn", "tuoitre.vn", "thanhnien.vn", "vietnamnet.vn", "vtv.vn", "tienphong.vn", "laodong.vn", "soha.vn", "kenh14.vn", "znews.vn",
    // Công nghệ & Lập trình
    "stackoverflow.com", "github.com", "gitlab.com", "leetcode.com", "codeforces.com", "hackerrank.com", "w3schools.com", "kaggle.com", "geeksforgeeks.org", "npmjs.com", "pypi.org", "python.org", "developer.mozilla.org", "coursera.org", "udemy.com", "wikipedia.org",
    // Mạng xã hội & Nền tảng lớn
    "google.com", "google.com.vn", "youtube.com", "gmail.com", "facebook.com", "fb.com", "messenger.com", "instagram.com", "threads.net", "claude.ai", "claude.com", "anthropic.com", "openai.com", "chatgpt.com", "telegram.org", "tiktok.com", "twitter.com", "x.com", "microsoft.com", "apple.com",
    // Ngân hàng & Ví điện tử Việt Nam
    "vietcombank.com.vn", "techcombank.com.vn", "mbbank.com.vn", "bidv.com.vn", "agribank.com.vn", "vpbank.com.vn", "acb.com.vn", "tpbank.com.vn", "sacombank.com.vn", "vib.com.vn", "vietinbank.vn", "hdbank.com.vn", "shb.com.vn", "momo.vn", "zalopay.vn", "vnpay.vn", "zalo.me",
    // Bán lẻ & Viễn thông
    "thegioididong.com", "dienmayxanh.com", "fptshop.com.vn", "cellphones.com.vn", "hoanghamobile.com", "bachhoaxanh.com", "shopee.vn", "lazada.vn", "tiki.vn", "sendo.vn", "viettel.vn", "vinaphone.vn", "mobifone.vn"
  ];

  const isTrustedSite = !isTestingPage && (
    currentHost.endsWith(".gov.vn") ||
    currentHost.endsWith(".edu.vn") ||
    TRUSTED_DOMAINS.some(d => currentHost === d || currentHost.endsWith("." + d))
  );

  // 1. Trích xuất đặc trưng DOM giao diện trang web (17 Tiêu chí ChongLuaDao + P-Sieve)
  function extractPageFeatures() {
    const inputs = Array.from(document.querySelectorAll("input"));
    const forms = Array.from(document.querySelectorAll("form"));

    let hasPassword = false;
    let hasOtp = false;
    let hasCreditCard = false;

    const otpRegex = /(otp|ma-otp|ma_otp|xacthuc|token|verification|verify-code)/i;
    const cardRegex = /(card|credit|debit|cvv|cvc|expir|sothe|so_the)/i;

    for (const input of inputs) {
      const type = (input.type || "").toLowerCase();
      const name = (input.name || "").toLowerCase();
      const id = (input.id || "").toLowerCase();
      const placeholder = (input.placeholder || "").toLowerCase();
      const labelText = (input.labels && input.labels[0] ? input.labels[0].innerText : "").toLowerCase();
      const allAttr = `${name} ${id} ${placeholder} ${labelText}`;

      if (type === "password") {
        hasPassword = true;
      }
      if (otpRegex.test(allAttr)) {
        hasOtp = true;
      }
      if (cardRegex.test(allAttr)) {
        hasCreditCard = true;
      }
    }

    // Tiêu chí SFH (Server Form Handler) & mailto
    let sfhRisk = false;
    let hasMailtoForm = false;
    const formActionDomains = [];
    for (const form of forms) {
      const rawAction = (form.getAttribute("action") || "").trim().toLowerCase();
      if (!rawAction || rawAction === "about:blank" || rawAction === "#") {
        sfhRisk = true;
      } else if (rawAction.startsWith("mailto:")) {
        hasMailtoForm = true;
        sfhRisk = true;
      } else {
        try {
          const u = new URL(form.action, window.location.href);
          if (u.hostname && !formActionDomains.includes(u.hostname)) {
            formActionDomains.push(u.hostname);
          }
          if (u.hostname && u.hostname !== currentHost && !u.hostname.endsWith("." + currentHost)) {
            sfhRisk = true;
          }
        } catch (e) {}
      }
    }

    // Tiêu chí Favicon
    let faviconExternal = false;
    const iconLink = document.querySelector('link[rel~="icon"]') || document.querySelector('link[rel~="shortcut icon"]');
    if (iconLink && iconLink.href) {
      try {
        const iconHost = new URL(iconLink.href).hostname.toLowerCase();
        if (iconHost && iconHost !== currentHost && !iconHost.endsWith("." + currentHost)) {
          faviconExternal = true;
        }
      } catch (e) {}
    }

    // Tiêu chí Request URL (% external media/images)
    const mediaEls = Array.from(document.querySelectorAll("img, video, audio, source"));
    let extMedia = 0;
    mediaEls.forEach(el => {
      const src = el.src || el.currentSrc;
      if (src) {
        try {
          const h = new URL(src).hostname.toLowerCase();
          if (h && h !== currentHost && !h.endsWith("." + currentHost)) extMedia++;
        } catch (e) {}
      }
    });
    const requestUrlExternalPercent = mediaEls.length > 0 ? Math.round((extMedia / mediaEls.length) * 100) : 0;

    // Tiêu chí Anchor (% empty or external)
    const anchors = Array.from(document.querySelectorAll("a"));
    let riskyAnchors = 0;
    anchors.forEach(a => {
      const href = (a.getAttribute("href") || "").trim();
      if (!href || href === "#" || href === "#;" || href.startsWith("javascript:")) {
        riskyAnchors++;
      } else {
        try {
          const h = new URL(a.href).hostname.toLowerCase();
          if (h && h !== currentHost && !h.endsWith("." + currentHost)) riskyAnchors++;
        } catch (e) {}
      }
    });
    const anchorExternalPercent = anchors.length > 0 ? Math.round((riskyAnchors / anchors.length) * 100) : 0;

    // Tiêu chí Script & Link (% external scripts and stylesheets)
    const scriptLinks = Array.from(document.querySelectorAll('script[src], link[rel="stylesheet"]'));
    let extScripts = 0;
    scriptLinks.forEach(el => {
      const url = el.src || el.href;
      if (url) {
        try {
          const h = new URL(url).hostname.toLowerCase();
          if (h && h !== currentHost && !h.endsWith("." + currentHost)) extScripts++;
        } catch (e) {}
      }
    });
    const scriptLinkExternalPercent = scriptLinks.length > 0 ? Math.round((extScripts / scriptLinks.length) * 100) : 0;

    // Tiêu chí iFrames (Hidden / invisible iframes)
    let hasHiddenIframe = false;
    const iframes = Array.from(document.querySelectorAll("iframe"));
    iframes.forEach(f => {
      try {
        const style = window.getComputedStyle(f);
        const w = f.offsetWidth || parseInt(f.getAttribute("width") || "100");
        const h = f.offsetHeight || parseInt(f.getAttribute("height") || "100");
        if (style.display === "none" || style.visibility === "hidden" || w === 0 || h === 0 || f.getAttribute("frameborder") === "0") {
          hasHiddenIframe = true;
        }
      } catch (e) {}
    });

    let textSnippet = "";
    try {
      const h1 = document.querySelector("h1");
      const main = document.querySelector("main") || document.body;
      textSnippet = (h1 ? h1.innerText + " " : "") + (main ? main.innerText.slice(0, 400) : "");
      textSnippet = textSnippet.replace(/\s+/g, " ").trim();
    } catch (e) {}

    return {
      url: window.location.href,
      title: document.title || "",
      has_password_input: hasPassword,
      has_otp_input: hasOtp,
      has_credit_card_input: hasCreditCard,
      form_action_domains: formActionDomains,
      favicon_external: faviconExternal,
      request_url_external_percent: requestUrlExternalPercent,
      anchor_external_percent: anchorExternalPercent,
      script_link_external_percent: scriptLinkExternalPercent,
      sfh_risk: sfhRisk,
      has_mailto_form: hasMailtoForm,
      has_hidden_iframe: hasHiddenIframe,
      text_snippet: textSnippet.slice(0, 500),
    };
  }

  // 2. Lắng nghe yêu cầu từ popup.js với bộ quét DOM sâu (Deep DOM Scanner)
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "get_dom_features") {
      sendResponse(extractPageFeatures());
    } else if (request.action === "get_page_text") {
      // 2.1. Trích xuất siêu dữ liệu SEO & OpenGraph
      const getMeta = (name) => {
        const el = document.querySelector(`meta[name="${name}"], meta[property="${name}"]`);
        return el ? (el.getAttribute("content") || "").trim() : "";
      };
      const metaDesc = getMeta("description") || getMeta("og:description");
      const metaTitle = getMeta("og:title") || document.title || "";

      // 2.2. Trích xuất các tiêu đề chính (H1, H2, H3)
      const headings = Array.from(document.querySelectorAll("h1, h2, h3"))
        .map(h => (h.innerText || "").trim())
        .filter(t => t.length > 0)
        .slice(0, 6)
        .join(" | ");

      // 2.3. Trích xuất thuộc tính các ô nhập liệu (Forms & Inputs)
      const inputs = Array.from(document.querySelectorAll("input, textarea, select"));
      const inputSummaries = inputs.map(inp => {
        const type = (inp.type || "text").toLowerCase();
        const name = inp.name || inp.id || "";
        const ph = inp.placeholder || "";
        return `${type}:${name}${ph ? '(' + ph + ')' : ''}`;
      }).filter(s => s.length > 0).slice(0, 10).join(", ");

      // 2.4. Trích xuất các nút bấm hành động (Call-to-Action Buttons)
      const buttons = Array.from(document.querySelectorAll("button, input[type='submit'], a.btn, a.button"))
        .map(b => (b.innerText || b.value || "").trim())
        .filter(t => t.length > 0 && t.length < 50)
        .slice(0, 8)
        .join(" | ");

      // 2.5. Trích xuất đoạn văn bản nội dung cốt lõi
      const paragraphs = Array.from(document.querySelectorAll("p, article, section"))
        .map(p => (p.innerText || "").trim())
        .filter(t => t.length > 15)
        .slice(0, 6)
        .join(" ");

      // 2.6. Đặc trưng DOM kỹ thuật
      const domFeatures = extractPageFeatures();

      // Hợp nhất thành bối cảnh an ninh có cấu trúc cao (Structured Threat Context)
      const parts = [];
      if (metaTitle) parts.push(`Tiêu đề trang: ${metaTitle}`);
      if (headings) parts.push(`Tiêu đề mục: ${headings}`);
      if (metaDesc) parts.push(`Mô tả: ${metaDesc}`);
      if (inputSummaries) parts.push(`Trường nhập liệu: ${inputSummaries}`);
      if (buttons) parts.push(`Nút hành động: ${buttons}`);
      if (paragraphs) parts.push(`Nội dung văn bản: ${paragraphs.slice(0, 800)}`);

      let combinedContext = parts.join("\n");
      if (!combinedContext.trim() && document.body) {
        combinedContext = (document.body.innerText || "").slice(0, 1500).replace(/\s+/g, " ").trim();
      }

      sendResponse({
        url: window.location.href,
        title: metaTitle || document.title || "",
        page_text: combinedContext,
        dom_features: domFeatures,
        has_otp: domFeatures.has_otp_input,
        has_password: domFeatures.has_password_input,
        has_credit_card: domFeatures.has_credit_card_input,
        sfh_risk: domFeatures.sfh_risk
      });
    }
    return true;
  });

  // 3. TÍNH NĂNG 2: CHẶN VÀ CẢNH BÁO FORM NHẠY CẢM TRÊN TÊN MIỀN LẠ (In-page Sensitive Input Shield)
  if (!isTrustedSite) {
    function setupSensitiveInputListener() {
      const otpRegex = /(otp|ma-otp|ma_otp|xacthuc|token|verification|verify-code)/i;
      const cardRegex = /(card|credit|debit|cvv|cvc|expir|sothe|so_the)/i;

      document.addEventListener("focusin", (e) => {
        const target = e.target;
        if (!target || target.tagName !== "INPUT") return;

        // Kiểm tra xem đã tắt cảnh báo trong phiên làm việc này chưa
        if (sessionStorage.getItem("psieve_shield_dismissed") === "true") return;

        const type = (target.type || "").toLowerCase();
        const name = (target.name || "").toLowerCase();
        const id = (target.id || "").toLowerCase();
        const placeholder = (target.placeholder || "").toLowerCase();
        const allAttr = `${name} ${id} ${placeholder}`;

        let sensitiveType = null;
        if (type === "password") {
          sensitiveType = "MẬT KHẨU";
        } else if (otpRegex.test(allAttr)) {
          sensitiveType = "MÃ XÁC THỰC OTP";
        } else if (cardRegex.test(allAttr)) {
          sensitiveType = "THÔNG TIN THẺ NGÂN HÀNG / CVV";
        }

        if (sensitiveType) {
          showSensitiveShieldBanner(sensitiveType);
        }
      }, true);
    }

    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", setupSensitiveInputListener);
    } else {
      setupSensitiveInputListener();
    }
  }

  function showSensitiveShieldBanner(sensitiveType) {
    if (document.getElementById("psieve-sensitive-shield")) return;

    const banner = document.createElement("div");
    banner.id = "psieve-sensitive-shield";
    banner.style.cssText = `
      position: fixed;
      bottom: 20px;
      right: 20px;
      max-width: 440px;
      background-color: #aa0a27;
      color: #FFFFFF;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 13px;
      line-height: 1.5;
      padding: 16px 18px;
      border-radius: 8px;
      z-index: 999999999;
      box-shadow: 0 8px 24px rgba(0,0,0,0.4);
      border: 2px solid #FFFFFF;
    `;

    const titleEl = document.createElement("div");
    titleEl.style.cssText = "font-weight: 900; font-size: 14px; margin-bottom: 8px; letter-spacing: 0.5px; text-transform: uppercase;";
    titleEl.textContent = "CANH BAO AN NINH P-SIEVE: TRANG WEB CHUA XAC THUC";

    const descEl = document.createElement("div");
    descEl.style.cssText = "margin-bottom: 12px; font-weight: 500;";
    descEl.textContent = `Trang web này (${currentHost}) chưa được xác thực trong danh bạ tổ chức chính thống. Bạn đang thao tác tại ô nhập [${sensitiveType}]. Tuyệt đối KHÔNG cung cấp nếu chưa kiểm chứng rõ danh tính người sở hữu!`;

    const btnRow = document.createElement("div");
    btnRow.style.cssText = "display: flex; gap: 10px; justify-content: flex-end;";

    const leaveBtn = document.createElement("button");
    leaveBtn.textContent = "Rời khỏi trang này";
    leaveBtn.style.cssText = `
      background-color: #FFFFFF;
      color: #aa0a27;
      border: none;
      padding: 6px 12px;
      border-radius: 4px;
      font-weight: 700;
      font-size: 12px;
      cursor: pointer;
    `;
    leaveBtn.onclick = function () {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.location.href = "about:blank";
      }
    };

    const continueBtn = document.createElement("button");
    continueBtn.textContent = "Tôi hiểu rủi ro, tiếp tục";
    continueBtn.style.cssText = `
      background-color: rgba(255,255,255,0.2);
      color: #FFFFFF;
      border: 1px solid #FFFFFF;
      padding: 6px 12px;
      border-radius: 4px;
      font-weight: 600;
      font-size: 12px;
      cursor: pointer;
    `;
    continueBtn.onclick = function () {
      sessionStorage.setItem("psieve_shield_dismissed", "true");
      banner.remove();
    };

    btnRow.appendChild(leaveBtn);
    btnRow.appendChild(continueBtn);

    banner.appendChild(titleEl);
    banner.appendChild(descEl);
    banner.appendChild(btnRow);
    document.body.appendChild(banner);
  }

  // 4. Tu dong kiem tra trang web qua Service Worker (Khong lo loi Mixed Content)
  const domPayload = extractPageFeatures();

  try {
    chrome.runtime.sendMessage(
      { action: "inspect_page", payload: domPayload },
      (response) => {
        if (chrome.runtime.lastError || !response || !response.success || !response.data) {
          return;
        }
        const data = response.data;
        if (data.is_scam && data.score >= 70) {
          const reasonText = (data.reasons && data.reasons.length > 0)
            ? data.reasons.join(" | ")
            : "Phat hien dau hieu gia mao thuong hieu hoac bay danh cap thong tin";
          showPhishingAlertBanner(data.score, reasonText);
        }
      }
    );
  } catch (err) {
    // Bo qua neu Service Worker tam thoi khong phan hoi
  }

  function showPhishingAlertBanner(score, detailReason) {
    if (document.getElementById("psieve-warning-banner")) return;

    const banner = document.createElement("div");
    banner.id = "psieve-warning-banner";
    banner.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      background-color: #aa0a27;
      color: #FFFFFF;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 13.5px;
      font-weight: 700;
      padding: 12px 20px;
      z-index: 999999999;
      display: flex;
      align-items: center;
      justify-content: space-between;
      box-shadow: 0 4px 16px rgba(0,0,0,0.4);
      border-bottom: 2px solid #FFFFFF;
      box-sizing: border-box;
    `;

    const textSpan = document.createElement("span");
    textSpan.style.cssText = "line-height: 1.4; padding-right: 15px;";
    textSpan.textContent = `CANH BAO AN NINH P-SIEVE (Rui ro ${score}/100): ${detailReason}. TUYET DOI KHONG dang nhap hoac cung cap ma OTP.`;

    const btnGroup = document.createElement("div");
    btnGroup.style.cssText = "display: flex; gap: 8px; flex-shrink: 0;";

    const leaveBtn = document.createElement("button");
    leaveBtn.textContent = "Roi khoi trang";
    leaveBtn.style.cssText = `
      background-color: #FFFFFF;
      color: #aa0a27;
      border: none;
      padding: 6px 14px;
      border-radius: 4px;
      font-weight: 800;
      font-size: 12px;
      cursor: pointer;
      white-space: nowrap;
    `;
    leaveBtn.onclick = function () {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.location.href = "about:blank";
      }
    };

    const closeBtn = document.createElement("button");
    closeBtn.textContent = "Dong";
    closeBtn.style.cssText = `
      background-color: rgba(255,255,255,0.2);
      color: #FFFFFF;
      border: 1px solid #FFFFFF;
      padding: 6px 12px;
      border-radius: 4px;
      font-weight: 600;
      font-size: 12px;
      cursor: pointer;
      white-space: nowrap;
    `;
    closeBtn.onclick = function () {
      banner.remove();
    };

    btnGroup.appendChild(leaveBtn);
    btnGroup.appendChild(closeBtn);
    banner.appendChild(textSpan);
    banner.appendChild(btnGroup);
    document.body.prepend(banner);
  }
})();

