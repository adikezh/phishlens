// PhishLens Outlook task pane (F-4.1.6). Reads the current item as EML via
// Office.js (getAsFileAsync when available, otherwise headers + body) and POSTs
// it to /v1/analyze. The add-in can use the PhishLens SSO cookie or a key
// entered by the operator; no credential is shipped in this static bundle.
/* global Office */
const BASE_URL = window.location.origin;
const KEY_STORAGE = "phishlens.outlook.api-key";
let lastSubmissionID = "";

function setStatus(t) { document.getElementById("status").textContent = t; }

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function render(resp) {
  const r = resp.result || {};
  const verdict = r.verdict || "needs_review";
  const signals = (r.signals || []).slice(0, 6).map(s => `<div class="signal">${escapeHtml(s.explanation || s.id)}</div>`).join("");
  const rec = (r.recommendations || []).map(x => `<li>${escapeHtml(x)}</li>`).join("");
  const llm = r.llm ? `<p><b>ИИ-объяснение:</b> ${escapeHtml(r.llm.summary || "")}</p>` : "";
  document.getElementById("result").innerHTML =
    `<p><span class="verdict ${verdict}">${verdict}</span> &nbsp; ${r.score}/100</p>${signals}${llm}<ul>${rec}</ul>`;
}

async function analyze(payload) {
  setStatus("Анализ…");
  const headers = { "Content-Type": "application/json" };
  const key = document.getElementById("api-key").value.trim();
  if (key) headers["X-API-Key"] = key;
  const res = await fetch(`${BASE_URL}/v1/analyze`, {
    method: "POST",
    headers,
    credentials: "include",
    body: JSON.stringify(Object.assign({ channel: "outlook" }, payload)),
  });
  if (!res.ok) { setStatus("Ошибка: " + res.status); return; }
  const data = await res.json();
  if (res.status === 202 && res.headers.get("Location")) {
    setStatus("Анализ продолжается…");
    let current = data;
    for (let i = 0; i < 30 && !current.result; i += 1) {
      await new Promise(resolve => setTimeout(resolve, 1000));
      const poll = await fetch(new URL(res.headers.get("Location"), BASE_URL), { credentials: "include", headers: key ? { "X-API-Key": key } : {} });
      if (!poll.ok) { setStatus("Ошибка polling: " + poll.status); return; }
      current = await poll.json();
    }
    if (!current.result) { setStatus("Анализ ещё выполняется; откройте результат по ID " + current.id); return; }
    Object.assign(data, current);
  }
  lastSubmissionID = data.id || "";
  setStatus(`Готово за ${(data.result || {}).duration_ms || 0} мс`);
  render(data);
  document.getElementById("report").disabled = false;
}

function fallback(item) {
  item.body.getAsync(Office.CoercionType.Text, r => {
    const text = `From: ${item.from ? item.from.emailAddress : ""}\nSubject: ${item.subject}\n\n${r.value}`;
    analyze({ text });
  });
}

function readOfficeFile(file) {
  return new Promise((resolve, reject) => {
    const slices = [];
    let pending = file.sliceCount;
    if (!pending) { reject(new Error("пустой MIME-файл")); return; }
    for (let i = 0; i < file.sliceCount; i += 1) {
      file.getSliceAsync(i, result => {
        if (result.status !== Office.AsyncResultStatus.Succeeded) { reject(result.error || new Error("не удалось прочитать MIME-файл")); return; }
        slices[i] = result.value.data;
        pending -= 1;
        if (pending === 0) resolve(slices.join(""));
      });
    }
  });
}

Office.onReady(() => {
  document.getElementById("api-key").value = localStorage.getItem(KEY_STORAGE) || "";
  document.getElementById("save-key").onclick = () => {
    localStorage.setItem(KEY_STORAGE, document.getElementById("api-key").value.trim());
    setStatus("Ключ сохранён в этом браузере.");
  };
  document.getElementById("check").onclick = () => {
    const item = Office.context.mailbox.item;
    // Preferred: full MIME via getAsFileAsync (Mailbox 1.14+); fallback: body text.
    if (item.getAsFileAsync) {
      item.getAsFileAsync(r => {
        if (r.status === Office.AsyncResultStatus.Succeeded) readOfficeFile(r.value).then(eml_base64 => analyze({ eml_base64 })).catch(() => fallback(item));
        else fallback(item);
      });
    } else {
      fallback(item);
    }
  };
  document.getElementById("report").onclick = async () => {
    if (!lastSubmissionID) return;
    const headers = {};
    const key = document.getElementById("api-key").value.trim();
    if (key) headers["X-API-Key"] = key;
    const res = await fetch(`${BASE_URL}/v1/submissions/${encodeURIComponent(lastSubmissionID)}/report`, {
      method: "POST", headers, credentials: "include",
    });
    setStatus(res.ok ? "Отправлено в очередь ИБ" : "Не удалось отправить в очередь: " + res.status);
  };
});
