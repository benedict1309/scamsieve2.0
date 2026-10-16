// File: extension/background.js
// He thong Giam dinh An ninh & Tien ich P-Sieve (Manifest V3)
// Ho tro Service Worker khong lo loi Mixed Content hoac chan mang cuc bo

const API_CANDIDATE_BASES = [
  "http://127.0.0.1:8001/api/v1",
  "http://127.0.0.1:8000/api/v1"
];

// Danh ba ten mien tin cay quoc gia va to chuc lon Viet Nam
const TRUSTED_DOMAINS = [
  "gov.vn", "edu.vn", "tinnhiemmang.vn", "chongluadao.vn", "ncsc.gov.vn",
  "dichvucong.gov.vn", "vneid.gov.vn", "chinhphu.vn", "baochinhphu.vn",
  "vnexpress.net", "dantri.com.vn", "tuoitre.vn", "thanhnien.vn", "vietnamnet.vn",
  "vtv.vn", "tienphong.vn", "laodong.vn", "soha.vn", "kenh14.vn", "znews.vn",
  "google.com", "google.com.vn", "youtube.com", "facebook.com", "fb.com",
  "messenger.com", "zalo.me", "github.com", "stackoverflow.com", "wikipedia.org",
  "vietcombank.com.vn", "techcombank.com.vn", "mbbank.com.vn", "bidv.com.vn",
  "agribank.com.vn", "vpbank.com.vn", "acb.com.vn", "tpbank.com.vn",
  "sacombank.com.vn", "vib.com.vn", "vietinbank.vn", "hdbank.com.vn", "shb.com.vn",
  "shopee.vn", "lazada.vn", "tiki.vn", "sendo.vn", "thegioididong.com",
  "dienmayxanh.com", "fptshop.com.vn", "viettel.vn", "vinaphone.vn", "mobifone.vn",
  "vnptmoney.vn", "tv360.vn", "viettelstore.vn", "homecredit.vn", "vtmoney.vn"
];

// Danh ba tinh bao ten mien doc hai / bi chiem quyen dieu khien
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

// Bo nho dem ket qua giam dinh URL nham toi uu toc do (< 0.1ms)
const URL_VERDICT_CACHE = new Map();

// Ham thuc thi truy van an toan qua cac cong backend
async function fetchApi(endpoint, body = null, method = "GET") {
  let lastError = null;
  for (const base of API_CANDIDATE_BASES) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3500);
      const options = {
        method,
        headers: { "Content-Type": "application/json" },
        signal: controller.signal
      };
      if (body) {
        options.body = JSON.stringify(body);
      }
      const resp = await fetch(`${base}${endpoint}`, options);
      clearTimeout(timeoutId);
      if (resp.ok) {
        return await resp.json();
      }
    } catch (e) {
      lastError = e;
    }
  }
  throw lastError || new Error("Khong the ket noi den may chu P-Sieve");
}

// 1. Khoi tao Menu chuot phai (Context Menu)
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "psieve-check-selection",
    title: "Kiem tra van ban da chon voi P-Sieve",
    contexts: ["selection"]
  });

  chrome.contextMenus.create({
    id: "psieve-check-link",
    title: "Kiem tra lien ket nay voi P-Sieve",
    contexts: ["link"]
  });
});

// 2. Xu ly su kien click Menu chuot phai
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  let targetContent = "";
  if (info.menuItemId === "psieve-check-selection" && info.selectionText) {
    targetContent = info.selectionText.trim();
  } else if (info.menuItemId === "psieve-check-link" && info.linkUrl) {
    targetContent = info.linkUrl.trim();
  }

  if (!targetContent) return;

  try {
    const data = await fetchApi("/scan", { content: targetContent, input_type: "auto" }, "POST");
    let notifTitle = "P-Sieve: Noi Dung An Toan";
    if (data.risk_level === "HIGH") {
      notifTitle = "P-Sieve: CANH BAO NGUY CO LUA DAO";
    } else if (data.risk_level === "MEDIUM") {
      notifTitle = "P-Sieve: CAN THAN TRONG";
    }

    const notifMessage = `Diem rui ro: ${data.score}/100\n${data.status_label}\n${data.recommendation}`;
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon48.png",
      title: notifTitle,
      message: notifMessage,
      priority: 2
    });
  } catch (err) {
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon48.png",
      title: "P-Sieve: Loi ket noi",
      message: "Khong the ket noi den may chu P-Sieve (cong 8001/8000). Vui long kiem tra backend.",
      priority: 1
    });
  }
});

// 3. Ham cap nhat Huy hieu tren thanh cong cu (Extension Badge)
async function updateTabBadge(tabId, url) {
  if (!url || url.startsWith("chrome://") || url.startsWith("edge://") || url.startsWith("about:")) {
    chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }

  try {
    const u = new URL(url);
    const host = u.hostname.toLowerCase();

    // Kiem tra danh ba tin cay cuc bo (0ms)
    const isGovEdu = host.endsWith(".gov.vn") || host.endsWith(".edu.vn");
    if (isGovEdu || TRUSTED_DOMAINS.some(d => host === d || host.endsWith("." + d))) {
      chrome.action.setBadgeText({ tabId, text: "SAFE" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#16a34a" });
      return;
    }

    // Kiem tra danh ba doc hai cuc bo (0ms)
    if (KNOWN_MALICIOUS_DOMAINS.some(d => host === d || host.endsWith("." + d))) {
      chrome.action.setBadgeText({ tabId, text: "DANGER" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#aa0a27" });
      return;
    }

    // Kiem tra bo nho dem (0.01ms)
    if (URL_VERDICT_CACHE.has(url)) {
      const cached = URL_VERDICT_CACHE.get(url);
      applyBadge(tabId, cached.score, cached.is_scam);
      return;
    }

    // Kiem tra qua heuristic nhanh
    const res = await fetchApi("/inspect-heuristics", { url, dom: {} }, "POST");
    const isScam = res.verdict === "DANGEROUS";
    const score = 100 - res.safety_score;
    URL_VERDICT_CACHE.set(url, { score, is_scam: isScam });
    applyBadge(tabId, score, isScam);
  } catch (e) {
    // Khong chan luong neu backend chua san sang
  }
}

function applyBadge(tabId, score, isScam) {
  if (isScam || score >= 70) {
    chrome.action.setBadgeText({ tabId, text: "DANGER" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#aa0a27" });
  } else if (score >= 40) {
    chrome.action.setBadgeText({ tabId, text: "WARN" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#d97706" });
  } else {
    chrome.action.setBadgeText({ tabId, text: "OK" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#16a34a" });
  }
}

// 4. Lang nghe thay doi URL tren tab
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    updateTabBadge(tabId, tab.url);
  }
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab && tab.url) {
      updateTabBadge(activeInfo.tabId, tab.url);
    }
  } catch (e) {}
});

// 5. Cung cap Proxy API qua Message Passing cho Content Script (Tranh Mixed Content)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "inspect_page") {
    fetchApi("/inspect-page", request.payload, "POST")
      .then((data) => {
        if (sender && sender.tab && sender.tab.id && request.payload && request.payload.url) {
          URL_VERDICT_CACHE.set(request.payload.url, { score: data.score, is_scam: data.is_scam });
          applyBadge(sender.tab.id, data.score, data.is_scam);
        }
        sendResponse({ success: true, data });
      })
      .catch((err) => {
        sendResponse({ success: false, error: err.message });
      });
    return true; // Cho phep phan hoi bat dong bo
  }

  if (request.action === "inspect_heuristics") {
    fetchApi("/inspect-heuristics", request.payload, "POST")
      .then((data) => sendResponse({ success: true, data }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (request.action === "scan_content") {
    fetchApi("/scan", request.payload, "POST")
      .then((data) => sendResponse({ success: true, data }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }
});
