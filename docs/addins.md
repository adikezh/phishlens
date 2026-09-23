# Add-ins

## Outlook (F-4.1.6)
1. Разверните сервис с публичным HTTPS `server.base_url`.
2. В addins/outlook/manifest.xml замените BASE_URL на публичный HTTPS-адрес
   сервиса. Иконки уже входят в репозиторий: `icon-64.png` и `icon-128.png`.
3. M365 admin center → Integrated apps → Upload custom app → manifest (или sideload для теста).
4. Панель берёт письмо через getAsFileAsync (Mailbox 1.14+) и шлёт `POST /v1/analyze {eml_base64, channel: outlook}`.
   После анализа кнопка «Сообщить в ИБ» вызывает `POST /v1/submissions/{id}/report`;
   ключ API вводится оператором в панели и хранится только в localStorage
   add-in либо запрос использует SSO-cookie; MIME slices собираются в один
   base64 payload, а `202 Accepted` опрашивается до готового результата.
   Ribbon command объявлен в `manifest.xml` через VersionOverrides.
Статика отдаётся сервисом по `/addins/outlook/`.

## Gmail (F-4.1.7)
addins/gmail/Code.gs + appsscript.json: Apps Script add-on, Script Properties PHISHLENS_URL, PHISHLENS_KEY.
Публикация через Google Workspace Marketplace SDK (internal).

## Telegram (F-4.1.8)
`internal/ingest/telegram` реализует Bot API long polling, привязку чата к
организации по `/start <код>`, текст/скриншот → общий analyzer → verdict.

## IMAP (F-4.1.4)
`internal/ingest/imap` uses IMAPS polling for `UNSEEN` messages, bounds each
message to 25 MiB, analyzes the complete `.eml`, marks successful messages as
seen and can move them to `processed_folder`. SMTP verdict replies require
explicit `smtp_host`, `smtp_from` and optional authentication settings.

## Microsoft Graph (F-4.1.5)
`internal/ingest/graph` uses client-credentials OAuth and the mailbox delta
endpoint, downloads each new message as MIME with a 25 MiB bound, analyzes it,
marks it read and persists the delta cursor in `state_file` (mode 0600 on
Unix). Configure Azure application permissions before enabling it.
Для Gmail Apps Script задайте Script Properties `PHISHLENS_URL` и
`PHISHLENS_KEY`, затем разверните `addins/gmail/Code.gs` как Gmail add-on.
Логотип манифеста берётся из публичного GitHub raw URL и может быть заменён
на URL корпоративного HTTPS-хоста при публикации.
