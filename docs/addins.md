# Add-ins

## Outlook (F-4.1.6)
1. Разверните сервис с публичным HTTPS `server.base_url`.
2. В addins/outlook/manifest.xml замените BASE_URL; иконки положите в addins/outlook/icon-{64,128}.png.
3. M365 admin center → Integrated apps → Upload custom app → manifest (или sideload для теста).
4. Панель берёт письмо через getAsFileAsync (Mailbox 1.14+) и шлёт `POST /v1/analyze {eml_base64, channel: outlook}`.
   После анализа кнопка «Сообщить в ИБ» вызывает `POST /v1/submissions/{id}/report`;
   ключ API задаётся администратором или заменяется SSO-токеном в Business.
Статика отдаётся сервисом по `/addins/outlook/`.

## Gmail (F-4.1.7)
addins/gmail/Code.gs + appsscript.json: Apps Script add-on, Script Properties PHISHLENS_URL, PHISHLENS_KEY.
Публикация через Google Workspace Marketplace SDK (internal).

## Telegram (F-4.1.8) — TODO
internal/ingest/telegram: привязка чата к организации по коду, текст/скриншот → вердикт.
