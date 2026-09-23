// PhishLens Gmail add-on (F-4.1.7): sends the raw message to /v1/analyze and shows the verdict.
// Configure PHISHLENS_URL / PHISHLENS_KEY in Script Properties for the Workspace deployment.
const BASE_URL = PropertiesService.getScriptProperties().getProperty("PHISHLENS_URL");
const API_KEY = PropertiesService.getScriptProperties().getProperty("PHISHLENS_KEY") || "";

function onGmailMessage(e) {
  const messageId = e.gmail.messageId;
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  const raw = GmailApp.getMessageById(messageId).getRawContent();
  const headers = API_KEY ? { "X-API-Key": API_KEY } : {};
  const resp = UrlFetchApp.fetch(BASE_URL + "/v1/analyze", {
    method: "post",
    contentType: "application/json",
    headers: headers,
    payload: JSON.stringify({ eml_base64: Utilities.base64Encode(raw), channel: "gmail" }),
    muteHttpExceptions: true,
  });
  const data = JSON.parse(resp.getContentText());
  const r = data.result || {};
  const section = CardService.newCardSection()
    .addWidget(CardService.newKeyValue().setTopLabel("Вердикт").setContent((r.verdict || "?") + " · " + (r.score || 0) + "/100"));
  (r.signals || []).slice(0, 5).forEach(function (s) {
    section.addWidget(CardService.newTextParagraph().setText("• " + s.explanation));
  });
  (r.recommendations || []).forEach(function (x) {
    section.addWidget(CardService.newTextParagraph().setText("→ " + x));
  });
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("PhishLens"))
    .addSection(section)
    .build();
}
