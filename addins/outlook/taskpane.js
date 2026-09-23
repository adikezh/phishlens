// PhishLens Outlook task pane (F-4.1.6). Reads the current item as EML via
// Office.js (getAsFileAsync when available, otherwise headers + body) and POSTs
// it to /v1/analyze. BASE_URL and API key are injected by the admin at deploy time.
/* global Office */
const BASE_URL = window.location.origin;
const API_KEY = ""; // TODO: per-tenant key from manifest settings / SSO token (F-4.7.4)
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
  if (API_KEY) headers["X-API-Key"] = API_KEY;
  const res = await fetch(`${BASE_URL}/v1/analyze`, {
    method: "POST",
    headers,
    body: JSON.stringify(Object.assign({ channel: "outlook" }, payload)),
  });
  if (!res.ok) { setStatus("Ошибка: " + res.status); return; }
  const data = await res.json();
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

Office.onReady(() => {
  document.getElementById("check").onclick = () => {
    const item = Office.context.mailbox.item;
    // Preferred: full MIME via getAsFileAsync (Mailbox 1.14+); fallback: body text.
    if (item.getAsFileAsync) {
      item.getAsFileAsync(r => {
        if (r.status === Office.AsyncResultStatus.Succeeded) analyze({ eml_base64: r.value });
        else fallback(item);
      });
    } else {
      fallback(item);
    }
  };
  document.getElementById("report").onclick = async () => {
    if (!lastSubmissionID) return;
    const headers = {};
    if (API_KEY) headers["X-API-Key"] = API_KEY;
    const res = await fetch(`${BASE_URL}/v1/submissions/${encodeURIComponent(lastSubmissionID)}/report`, {
      method: "POST", headers,
    });
    setStatus(res.ok ? "Отправлено в очередь ИБ" : "Не удалось отправить в очередь: " + res.status);
  };
});
