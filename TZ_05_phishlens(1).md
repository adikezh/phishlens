# ТЗ №5 — PhishLens (Go)

| Поле | Значение |
|---|---|
| Кодовое имя | `phishlens` |
| Репозиторий | `github.com/<you>/phishlens` |
| Язык | Go 1.23+ |
| Тип | Self-hosted веб-сервис + API + плагины (Outlook/Gmail add-in, Telegram-бот) |
| Лицензия | Core — AGPL-3.0 (чтобы SaaS-конкуренты не забрали); коммерческая лицензия для встраивания и enterprise |
| Целевой заказчик | ИБ-отделы компаний 50–5 000 сотрудников в РК/СНГ, MSSP, вузы; поставщики security awareness |

---

## 1. Продуктовое описание

### 1.1 Проблема
Сотрудник получает подозрительное письмо и либо кликает, либо пишет в ИБ «это фишинг?». ИБ разбирает такие обращения вручную: заголовки, ссылки, вложения — 10–20 минут на письмо. Коммерческие шлюзы фильтруют на входе, но не объясняют пользователю, и не работают для писем, которые уже прошли, для скриншотов из мессенджеров, и для локальных брендов (Kaspi, Halyk, eGov, Kaspi Pay, Beeline).

### 1.2 Решение
Сервис «отправь письмо — получи вердикт и объяснение за 5 секунд». Принимает текст, `.eml`/`.msg`, скриншот, пересланное письмо на служебный адрес или через add-in в Outlook/Gmail. Комбинирует детерминированные проверки (заголовки, SPF/DKIM/DMARC, домены, ссылки, вложения), репутационные источники, анализ сходства с брендами (включая казахстанские) и LLM для объяснения на языке сотрудника. ИБ получает очередь обращений, статистику, и данные для обучения сотрудников.

### 1.3 Что продаётся
- **Community**: веб-интерфейс, API, текст/.eml/скриншот, базовые эвристики, один LLM-провайдер, SQLite.
- **Business** (ключ/подписка): Outlook и Gmail add-in «Report phishing», ящик-приёмник (IMAP/Graph), очередь для ИБ, RBAC, SSO, отчёты, локальный vision/LLM, кастомные бренды, интеграция с SIEM/SOAR, sandbox-детонация ссылок.
- **Услуги**: настройка под корпоративную почту, добавление локальных брендов, обучение сотрудников с реальными кейсами компании.

### 1.4 Сценарии
1. Сотрудник нажимает «Сообщить о фишинге» в Outlook → через 5 с видит вердикт с подсветкой, письмо попадает в очередь ИБ.
2. Аналитик открывает очередь: 12 обращений, 3 реально фишинг с одинаковым доменом → одной кнопкой создаёт правило блокировки в шлюзе (через webhook) и инцидент в SIEM.
3. Бухгалтер присылает скриншот из WhatsApp «Kaspi просит подтвердить перевод» → сервис распознаёт бренд, домен-двойник, срочность → вердикт «фишинг» с объяснением на русском.
4. CISO смотрит месячный отчёт: количество обращений, доля подтверждённого фишинга, топ имитируемых брендов, отделы с наибольшей активностью — для awareness-программы.

---

## 2. Архитектура

```
 Входы                         Ядро анализа                          Выходы
┌────────────┐               ┌──────────────────────┐             ┌──────────────┐
│ Web UI     │               │ 1. Parser            │             │ Web UI       │
│ REST API   │──────────────▶│    eml/msg/text/img  │             │ Очередь ИБ   │
│ Outlook    │               │ 2. Feature extract   │             │ Отчёты       │
│ Gmail      │               │    headers, urls,    │────────────▶│ SIEM/SOAR    │
│ IMAP inbox │               │    attachments, text │             │ Webhook      │
│ Telegram   │               │ 3. Heuristics (60+)  │             │ Email-ответ  │
└────────────┘               │ 4. Reputation        │             └──────────────┘
                             │    (DNS, TI, RDAP)   │
                             │ 5. Brand similarity  │
                             │ 6. LLM explain       │
                             │ 7. Scoring & verdict │
                             └──────────────────────┘
```

**Принципы:**
- Анализ — конвейер стадий; каждая стадия добавляет `Signal` (признак с весом, доказательством и объяснением). Вердикт вычисляется из сигналов, LLM — только объясняет и ловит семантику (BEC, social engineering), но не может сам поставить `clean` при сильных технических сигналах.
- Всё, что уходит во внешние сервисы (LLM, TI), проходит через редакцию PII; полный офлайн-режим с локальными моделями.
- Письма по умолчанию не хранятся дольше времени анализа (Community); в Business — хранение с шифрованием и ретенцией по политике.

---

## 3. Модель данных

```go
type Submission struct {
    ID          string       // ULID
    Channel     string       // web | api | outlook | gmail | imap | telegram
    SubmittedBy string       // email/user id (опционально)
    Kind        string       // text | eml | msg | image
    ReceivedAt  time.Time
    Message     *ParsedMail  // см. ниже
    Result      *Analysis
    Status      string       // analyzed | in_review | confirmed_phish | confirmed_clean | escalated
    ReviewedBy  string
    OrgID       string
}

type ParsedMail struct {
    Headers      map[string][]string
    From, ReplyTo, ReturnPath Address   // Display, Addr, Domain
    To, CC       []Address
    Subject      string
    Date         time.Time
    Received     []ReceivedHop         // парсинг цепочки Received
    AuthResults  AuthResults           // SPF, DKIM, DMARC, ARC, источник (header/own check)
    TextBody, HTMLBody string
    Links        []Link                // Href, Text, Domain, IsIP, IsShortener, Punycode, Mismatch, Redirects []string
    Attachments  []Attachment          // Name, MIME, Size, SHA256, Ext, MacroDetected, IsArchive, NestedNames
    Images       []InlineImage         // для detection «текст в картинке»
    Language     string
    OCRText      string                // для image-входа
}

type Signal struct {
    ID          string   // "header.replyto_mismatch"
    Category    string   // header | auth | domain | link | attachment | content | brand | reputation | semantic
    Weight      int      // −30 … +40
    Confidence  float64
    Evidence    string   // конкретный фрагмент
    Explanation string   // человеческое объяснение (локализовано)
    Source      string   // heuristic | dns | ti | llm
}

type Analysis struct {
    Score          int        // 0–100
    Verdict        string     // phishing | suspicious | clean | needs_review
    Confidence     float64
    Signals        []Signal
    AttackType     string     // credential_harvesting | malware | bec | invoice_fraud | extortion | spam | none
    Brand          *BrandMatch // Name, Method(domain_similarity|logo|keyword), Score
    LLM            *LLMExplain // Summary, Highlights []Span, RecommendedAction, Model, PromptHash, Latency
    Recommendations []string
    DurationMs     int
}
```

**Хранилище:** SQLite/PostgreSQL, `sqlc`. Таблицы: `submissions`, `analyses`, `signals`, `brands`, `allowlist`, `blocklist`, `reputation_cache`, `users`, `orgs`, `api_keys`, `audit`. Тела писем и вложения — только в Business, зашифрованы (AES-GCM, ключ из KMS/env), ретенция по политике.

---

## 4. Функциональные требования

### 4.1 Входы
- **F-4.1.1** Web: textarea (сырой текст или вставленное письмо с заголовками), drag-and-drop `.eml`/`.msg`/PNG/JPG/PDF-скриншот, лимит 25 МБ.
- **F-4.1.2** REST: `POST /v1/analyze` (multipart или JSON `{text}` / `{eml_base64}` / `{image_base64}`), синхронно ≤ 10 с, иначе `202` + `GET /v1/analyses/{id}`.
- **F-4.1.3** `.msg` (Outlook) парсинг — CFB/OLE2 → MAPI-свойства.
- **F-4.1.4** IMAP-приёмник (Business): ящик `phish@company.kz`, пересланные письма (`.eml` вложение или inline-forward) разбираются, ответ отправителю с вердиктом.
- **F-4.1.5** Microsoft Graph приёмник (Business) — тот же сценарий для M365 без IMAP.
- **F-4.1.6** Outlook add-in (Office.js, статический бандл, хостится сервисом) — кнопка «Проверить / Сообщить», показывает результат в панели.
- **F-4.1.7** Gmail add-on (Apps Script, вызывает API) — аналогично.
- **F-4.1.8** Telegram-бот: переслать текст/скриншот — получить вердикт; привязка бота к организации через код.
- **F-4.1.9** Скриншоты: OCR + извлечение видимых URL/кнопок. Локально — `tesseract` через `gosseract` (ru/en/kz traineddata) или vision-LLM (Ollama `llava`/`qwen2-vl`, либо облачный провайдер). Выбор в конфиге.

### 4.2 Детерминированные эвристики (минимум 60 сигналов; ниже — обязательные группы)
**Заголовки и аутентификация**
- H-01 Display name содержит email, не совпадающий с `From` addr.
- H-02 `Reply-To` домен ≠ `From` домен.
- H-03 `Return-Path` домен ≠ `From` домен (при отсутствии известного ESP).
- H-04 `Authentication-Results`: SPF fail/softfail, DKIM fail/none, DMARC fail; при отсутствии заголовка — **собственная проверка**: SPF по `Received`-IP, DKIM-подпись по DNS, DMARC-политика домена.
- H-05 Цепочка `Received` содержит IP из TI/ботнет-списков или несовместимую географию с заявленным отправителем.
- H-06 `Message-ID` домен ≠ `From` домен; отсутствие `Message-ID`.
- H-07 Заголовок `X-Mailer`/`User-Agent` из списка массовых рассыльщиков при персональном письме.
- H-08 `Date` в будущем или расхождение > 24 ч с первым `Received`.

**Домены**
- D-01 Домен отправителя зарегистрирован < 30 дней (RDAP, кеш 7 дней).
- D-02 Домен в TI-списках (URLhaus, OpenPhish, PhishTank, локальный blocklist).
- D-03 Punycode / смешанные скрипты (кириллица+латиница) в домене.
- D-04 Сходство с брендом: расстояние Дамерау-Левенштейна ≤ 2, homoglyph-нормализация (`kaspi` vs `kasрi`), typosquat-паттерны (`kaspi-bank-kz.com`, `halyk.secure-login.ru`), поддомен бренда на чужом домене.
- D-05 Бесплатный почтовый домен при подписи от имени организации.
- D-06 TLD из рискового списка (`.zip`, `.top`, `.xyz`, …) с весом по статистике.

**Ссылки**
- L-01 Текст ссылки — URL/домен, не совпадающий с `href`.
- L-02 IP-адрес вместо домена; нестандартный порт.
- L-03 Сокращатели (список 40+), разворачивание по HEAD с лимитом 5 редиректов (Business: через sandbox-прокси).
- L-04 `@` в URL, длинные base64/hex сегменты, data: URI.
- L-05 Ссылка ведёт на форму логина (по HTML-ответу: `<input type=password>`) на домене ≠ бренда.
- L-06 Много ссылок на разные домены; ссылки на облачные хостинги форм (Google Forms, Typeform) с запросом пароля.
- L-07 Отслеживающие пиксели + отсутствие ссылки отписки при рекламном контенте.
- L-08 QR-код в письме/скриншоте → декодирование (`makiuchi-d/gozxing`) и анализ URL (quishing).

**Вложения**
- A-01 Опасные расширения (`.exe .scr .js .vbs .hta .iso .img .lnk .html .htm .docm .xlsm .one`), двойные расширения, RTL-override в имени.
- A-02 Архив (zip/rar/7z) с паролем или с исполняемым внутри (листинг без распаковки на диск).
- A-03 Office-документ с макросами (`oletools`-подобная проверка VBA-стрима в Go).
- A-04 PDF со ссылками/JS/формами.
- A-05 Хеш вложения в VirusTotal/MalwareBazaar (по конфигу).
- A-06 HTML-вложение с формой/JS (HTML-smuggling).

**Контент**
- C-01 Словари срочности/угроз/финансов на ru/en/kz (`срочно`, `заблокирован`, `в течение 24 часов`, `шұғыл`, `verify`, `wire`) — взвешенно, с учётом плотности.
- C-02 Запрос учётных данных / кода из SMS / данных карты.
- C-03 Обращение «Уважаемый клиент» без имени при бренде, который знает имя.
- C-04 Несоответствие языка: бренд казахстанский, письмо на английском, или машинный перевод (эвристики + LLM).
- C-05 Подпись от руководителя + просьба о переводе/покупке сертификатов + «не могу говорить» (BEC-паттерн).
- C-06 Изменение банковских реквизитов в счёте (invoice fraud), ИИН/БИН формат-чек.
- C-07 Скрытый текст (font-size 0, цвет фона, `display:none`) для обхода фильтров.
- C-08 Текст в картинке при отсутствии текста в теле.

**Репутация**
- R-01 IP отправителя: AbuseIPDB, Spamhaus ZEN (DNSBL), Talos (по конфигу).
- R-02 Домены ссылок: Google Safe Browsing (Update API), URLhaus, локальные списки.
- R-03 Организация allowlist/blocklist (домены, отправители) — переопределяют скор.

Каждая эвристика — отдельный файл с тестом и документацией `docs/signals/<id>.md` (что, почему, вес, ложные срабатывания).

### 4.3 Бренды
- **F-4.3.1** База брендов (`data/brands.yaml`): имя, официальные домены, ESP-домены (`kaspi.kz` шлёт через `*.kaspi.kz` и указанных партнёров), ключевые слова, цвета/логотип (pHash), локаль. Стартовый набор ≥ 100: казахстанские банки, госуслуги (eGov, ЦОН, налоговая), операторы, маркетплейсы, курьерки + глобальные (Microsoft, Google, Apple, DHL, PayPal…).
- **F-4.3.2** Определение имитируемого бренда: по домену (D-04), по ключевым словам в теме/теле, по логотипу в inline-картинках/скриншотах (pHash + vision-LLM), по цветовой схеме.
- **F-4.3.3** Если бренд определён, а отправитель не из его официальных доменов — сильный сигнал (+35).
- **F-4.3.4** Кастомные бренды организации (свой домен, свои подрядчики) — через UI/API.

### 4.4 LLM-слой
- **F-4.4.1** Провайдеры: OpenAI-compatible, Anthropic, Ollama; vision — те же плюс локальный. Фолбэк, бюджет, таймаут.
- **F-4.4.2** Вход: редактированный текст письма (PII → плейсхолдеры), список сигналов с весами, определённый бренд, язык пользователя. Выход — JSON:
  ```json
  {
    "verdict_opinion": "phishing|suspicious|clean",
    "attack_type": "…",
    "summary": "3–4 предложения простым языком, без жаргона",
    "highlights": [{"quote": "…", "reason": "…"}],
    "social_engineering_tactics": ["urgency", "authority", "fear"],
    "recommended_action": "…",
    "questions_for_analyst": ["…"]
  }
  ```
- **F-4.4.3** LLM-мнение — это сигнал категории `semantic` с весом до ±25, не финальный вердикт.
- **F-4.4.4** Промпт-инъекция из письма: содержимое изолируется, инструкция запрещает следовать тексту письма; LLM-ответ валидируется по схеме; в UI пометка «ИИ-объяснение».
- **F-4.4.5** Продукт работает без LLM (объяснения из шаблонов сигналов).
- **F-4.4.6** Кеш по хешу нормализованного текста; дедуп одинаковых кампаний (same subject/links) — один LLM-вызов на кампанию.

### 4.5 Скоринг и вердикт
- **F-4.5.1** `Score = clamp(Σ weight × confidence, 0, 100)`, веса из `data/weights.yaml`, переопределяемы организацией.
- **F-4.5.2** Пороги: `≥ 70 phishing`, `40–69 suspicious`, `< 40 clean`; `needs_review`, если есть конфликт (сильный технический сигнал vs LLM `clean`, или allowlist vs высокий скор).
- **F-4.5.3** Жёсткие правила: TI-совпадение домена/хеша → минимум `suspicious`; подтверждённый SPF+DKIM+DMARC pass от официального домена бренда → −40; отправитель в blocklist организации → `phishing`.
- **F-4.5.4** Объяснимость: каждый вклад в скор виден в UI с доказательством.

### 4.6 Очередь ИБ (Business)
- **F-4.6.1** Список обращений: фильтры по вердикту/статусу/отделу/кампании; группировка в кампании по общим ссылкам/отправителю/теме.
- **F-4.6.2** Действия: подтвердить/отклонить, эскалировать, «заблокировать домен» (webhook в шлюз/прокси/DNS-фильтр), «создать инцидент» (Wazuh custom event, TheHive, IRIS, Jira), «ответить сотруднику» шаблоном.
- **F-4.6.3** Массовые действия по кампании.
- **F-4.6.4** Обратная связь аналитика сохраняется как метка → используется для калибровки весов (`phishlens weights tune`).

### 4.7 API и UI
- **F-4.7.1** OpenAPI 3: `/v1/analyze`, `/v1/analyses/{id}`, `/v1/submissions`, `/v1/brands`, `/v1/lists/{allow|block}`, `/v1/stats`, `/v1/webhooks`, `/health`, `/metrics`.
- **F-4.7.2** UI (templ + htmx + Tailwind, без SPA): страница анализа (ввод слева / результат справа, шкала риска, сигналы с раскрытием доказательств, письмо с подсветкой, сырые заголовки, кнопка «Сообщить в ИБ»), очередь, кампании, бренды, списки, настройки, дашборд.
- **F-4.7.3** Три встроенных демо-примера (Kaspi-фишинг, BEC от директора, чистое письмо от банка с валидными заголовками) для показа.
- **F-4.7.4** Аутентификация: анонимный режим по конфигу (демо), API-ключи, Business — OIDC, роли `user/analyst/admin`, организации.
- **F-4.7.5** Локализация UI и объяснений: ru/en/kz.

### 4.8 Отчёты и awareness
- **F-4.8.1** `phishlens report --period month --format md|docx|pdf`: обращения, подтверждённый фишинг, топ брендов, топ тактик, время реакции, отделы.
- **F-4.8.2** Экспорт подтверждённых кейсов как обезличенные примеры для обучения сотрудников (HTML-карточки «что выдало фишинг»).
- **F-4.8.3** Экспорт IOC (домены, URL, хеши) в STIX 2.1 / MISP-формат.

### 4.9 Интеграции безопасности
- **F-4.9.1** Wazuh: отправка события через API/syslog с полями вердикта — попадает в твой SIEM-пайплайн (и в Triage Agent из ТЗ №3).
- **F-4.9.2** Webhook (HMAC) для SOAR.
- **F-4.9.3** Sandbox (Business): детонация ссылок в headless Chromium (`chromedp`) в изолированном контейнере: скриншот страницы, финальный URL, наличие формы логина, схожесть страницы с брендом (pHash/vision).

---

## 5. Нефункциональные требования

| Категория | Требование |
|---|---|
| Производительность | Анализ текста без внешних вызовов ≤ 300 мс; полный (DNS, TI, LLM) ≤ 8 с p95; 50 параллельных анализов на 2 ядрах |
| Ресурсы | ≤ 300 МБ RSS без локальных моделей; OCR/vision — отдельный опциональный контейнер |
| Надёжность | Внешние сервисы с таймаутами и circuit breaker; недоступность TI/LLM не ломает вердикт (деградация с пометкой) |
| Наблюдаемость | `/metrics` (анализы, вердикты, латентность стадий, ошибки внешних API, LLM tokens/cost), zerolog JSON, OpenTelemetry опционально |
| Безопасность | Письма и вложения обрабатываются в памяти/tmpfs; вложения никогда не исполняются; парсеры с лимитами (zip-bomb, размер, глубина); PII-редакция перед внешними вызовами; шифрование хранилища; аудит; TLS; rate-limit по ключу/IP |
| Приватность | Community — письма не сохраняются (только сигналы и скор без текста), настраиваемо; политика ретенции; удаление по запросу (`DELETE /v1/submissions/{id}`) |
| Совместимость | Linux amd64/arm64, Docker/Helm; Outlook (M365, 2019+), Gmail Workspace |
| Локализация | ru/en/kz (UI, объяснения, словари) |

---

## 6. Стек (Go)

| Назначение | Библиотека |
|---|---|
| CLI/конфиг | `cobra`, `viper`, `validator` |
| HTTP/API | `chi`, `oapi-codegen`; UI — `templ` + htmx + Tailwind |
| Парсинг почты | stdlib `net/mail`, `mime`, `mime/multipart`; `emersion/go-message`; `.msg` — `richardlehane/mscfb` + свой MAPI-парсер |
| HTML | `golang.org/x/net/html`, `microcosm-cc/bluemonday` (санитизация для отображения) |
| SPF/DKIM/DMARC | `emersion/go-msgauth`, `blitiri.com.ar/go/spf` |
| DNS/RDAP | `miekg/dns`, `openrdap/rdap` |
| Сходство строк | `adrg/strutil` (Damerau-Levenshtein, Jaro-Winkler), собственная homoglyph-таблица |
| QR | `makiuchi-d/gozxing` |
| OCR | `otiai10/gosseract` (cgo) — в отдельном контейнере; либо vision-LLM |
| pHash | `corona10/goimagehash` |
| Архивы | `archive/zip`, `nwaples/rardecode`, `bodgit/sevenzip` — только листинг |
| Office макросы | `richardlehane/mscfb` + поиск VBA-стрима; OOXML — `archive/zip` + `vbaProject.bin` |
| PDF | `pdfcpu/pdfcpu` (анализ ссылок/JS без рендера) |
| Sandbox | `chromedp/chromedp` |
| IMAP/Graph | `emersion/go-imap/v2`, `microsoftgraph/msgraph-sdk-go` |
| Telegram | `go-telegram/bot` |
| LLM | собственный клиент; JSON Schema валидация `santhosh-tekuri/jsonschema` |
| БД | `modernc.org/sqlite` / `pgx`, `sqlc`, `golang-migrate` |
| Крипто | stdlib `crypto/aes` GCM, `golang.org/x/crypto` |
| Circuit breaker | `sony/gobreaker` |
| Метрики/логи | `prometheus/client_golang`, `zerolog` |
| Отчёты | `nguyenthenguyen/docx`, `johnfercher/maroto` |
| Тесты | `testify`, `testcontainers-go`, `go-vcr` |
| Сборка | `goreleaser`, `Taskfile` |

---

## 7. Структура репозитория

```
phishlens/
├── cmd/phishlens/main.go
├── internal/
│   ├── app/ config/ domain/
│   ├── ingest/          # web, api, imap, graph, telegram
│   ├── parse/           # eml, msg, text, image(ocr), html, links, attachments
│   ├── signals/         # одна папка на категорию, один файл на сигнал
│   │   ├── header/ auth/ domain/ link/ attachment/ content/ brand/ reputation/ semantic/
│   │   └── registry.go
│   ├── brands/          # загрузка brands.yaml, matcher, logo phash
│   ├── reputation/      # dnsbl, safebrowsing, urlhaus, openphish, abuseipdb, vt, rdap, cache
│   ├── llm/             # providers, prompts, redaction, schema
│   ├── sandbox/         # chromedp runner (Business)
│   ├── score/           # weights, thresholds, hard rules, explain
│   ├── review/          # очередь, кампании, действия
│   ├── notify/          # wazuh, thehive, iris, jira, webhook, email reply
│   ├── store/ httpapi/ web/ report/ license/ crypto/
├── addins/
│   ├── outlook/         # manifest.xml, taskpane.html/js
│   └── gmail/           # Apps Script
├── data/
│   ├── brands.yaml
│   ├── weights.yaml
│   ├── shorteners.txt
│   ├── risky_tlds.yaml
│   ├── keywords/ (ru.yaml, en.yaml, kz.yaml)
│   └── homoglyphs.yaml
├── prompts/ (explain_v1.ru.txt, .en, .kz, vision_extract_v1.txt)
├── migrations/
├── configs/config.example.yaml
├── testdata/
│   ├── eml/            # ≥ 50 размеченных писем: phish/bec/invoice/clean/newsletter
│   ├── msg/ images/ attachments/
│   └── expected/       # golden-вердикты
├── deploy/ (docker-compose.yml, helm/, systemd/, ocr/Dockerfile, sandbox/Dockerfile)
├── docs/ (architecture, signals/, brands, api, addins, privacy, deployment)
├── .github/workflows/
├── Taskfile.yml, .goreleaser.yaml, go.mod, README.md
```

---

## 8. Конфигурация (полный пример)

```yaml
server: { listen: ":8082", base_url: "https://phishlens.company.kz", max_upload_mb: 25 }
storage:
  driver: sqlite
  dsn: "file:data/phishlens.db?_pragma=journal_mode(WAL)"
  store_bodies: false            # Community default
  encryption_key_env: PL_ENC_KEY
  retention: { submissions: 90d }

analysis:
  language: ru
  timeout: 10s
  thresholds: { phishing: 70, suspicious: 40 }
  weights_file: data/weights.yaml
  brands_file: data/brands.yaml
  custom_brands_enabled: true

auth_checks:
  own_spf_dkim_dmarc: true       # если нет Authentication-Results
  dns_resolver: "1.1.1.1:53"

reputation:
  rdap: { enabled: true, cache_ttl: 168h }
  dnsbl: ["zen.spamhaus.org"]
  urlhaus: { enabled: true }
  openphish: { enabled: true }
  safebrowsing: { enabled: false, api_key_env: GSB_KEY }
  abuseipdb: { enabled: false, key_env: ABUSEIPDB_KEY }
  virustotal: { enabled: false, key_env: VT_KEY, attachments_only: true }
  link_expansion: { enabled: true, max_redirects: 5, timeout: 4s }

ocr:
  mode: vision_llm               # tesseract | vision_llm | off
  tesseract_url: "http://ocr:8090"

llm:
  enabled: true
  redact_pii: true
  providers:
    - { name: cloud, type: openai_compatible, base_url: "https://openrouter.ai/api/v1", model: "anthropic/claude-haiku", api_key_env: OPENROUTER_KEY }
    - { name: local, type: ollama, base_url: "http://ollama:11434", model: "qwen2.5:14b", vision_model: "qwen2-vl:7b" }
  budget: { usd_per_day: 3.0, calls_per_hour: 300 }

sandbox: { enabled: false, url: "http://sandbox:9222", screenshot: true }

ingest:
  imap: { enabled: false, host: "", user: "", password_env: IMAP_PASS, folder: "INBOX", reply_with_verdict: true }
  graph: { enabled: false, tenant_id: "", client_id: "", client_secret_env: GRAPH_SECRET, mailbox: "phish@company.kz" }
  telegram: { enabled: false, token_env: TG_TOKEN }

integrations:
  wazuh: { enabled: false, api_url: "", user: "", password_env: WAZUH_PASS, min_verdict: suspicious }
  webhook: { enabled: false, url: "", secret_env: WEBHOOK_SECRET }
  thehive: { enabled: false }

auth:
  anonymous_analyze: true        # для демо; в проде false
  api_keys_enabled: true
  oidc: { enabled: false }
```

---

## 9. CLI

```
phishlens serve
phishlens analyze --file suspicious.eml [--json] [--no-llm]
phishlens analyze --text "..." 
phishlens analyze --image screenshot.png
phishlens batch --dir testdata/eml --out results.jsonl        # прогон корпуса
phishlens eval --dir testdata/eml --expected testdata/expected # precision/recall/F1 по вердиктам
phishlens weights tune --labels labels.jsonl --out weights.tuned.yaml
phishlens brands add --name "Kaspi" --domains kaspi.kz,kaspi.bank --keywords "kaspi,каспи"
phishlens lists allow add sender@partner.kz
phishlens ioc export --since 30d --format stix
phishlens report --period month --format docx --out phishing_sept.docx
phishlens apikey create --name outlook-addin --role user
phishlens migrate up
```

---

## 10. Тестирование

- Unit на каждый сигнал: ≥ 3 позитивных, ≥ 3 негативных кейса; сравнение версий домена/homoglyph — таблицы ≥ 100 кейсов.
- Парсеры: фаззинг (`go test -fuzz`) для eml/msg/html/zip-листинга — устойчивость к мусору и бомбам.
- Корпус: ≥ 200 размеченных писем (свои синтетические + публичные датасеты: Nazario, SpamAssassin, APWG-подобные), золотые вердикты; в CI — порог F1 ≥ 0.9 на корпусе, регрессии ломают билд.
- Интеграционные: mock-DNS (`miekg/dns` тест-сервер), записанные ответы TI (`go-vcr`), Postgres в testcontainers.
- Add-in: e2e в Playwright против Outlook Web (ручной этап перед релизом).
- Безопасность: тесты промпт-инъекции (письма с «ignore previous instructions») — вердикт не должен меняться; тесты на утечку PII в LLM-запрос.

---

## 11. Безопасность продукта

- Вложения: только листинг и статический разбор, никакого выполнения; парсинг в отдельной горутине с лимитами памяти/времени; при sandbox — отдельный контейнер без сети кроме прокси.
- Ссылки разворачиваются через HEAD с User-Agent без утечки данных, без cookies, с ограничением на внутренние адреса (SSRF-защита: блок RFC1918, link-local, metadata IP).
- Изображения: декодирование с лимитами, EXIF удаляется.
- PII-редакция (email, телефоны, ИИН/БИН, номера карт) перед любым внешним вызовом; словарь замен не покидает процесс.
- Хранение: шифрование тел писем, ключ вне БД; удаление по запросу; экспорт для GDPR/закона РК о персональных данных.
- Промпт-инъекция и «LLM сказал clean» — не могут переопределить жёсткие правила.
- CI: `govulncheck`, `gosec`, SBOM, distroless, non-root, read-only FS.

---

## 12. Поставка

- Бинари + Docker (`ghcr.io/<you>/phishlens`), опциональные образы `phishlens-ocr`, `phishlens-sandbox`; Helm.
- `docker compose up` → демо с тремя примерами и локальным Ollama (либо ключ OpenRouter).
- Outlook add-in manifest с инструкцией для M365 admin; Gmail add-on с инструкцией для Workspace.
- Публичное демо на своём домене (anonymous mode, rate-limit, без хранения) — главный маркетинг.
- Документация: Quick start, Signals reference, Brands, Add-ins, Privacy & data handling, API.
- Лендинг: демо в первом экране, «Проверить письмо» без регистрации, тарифы.

---

## 13. Roadmap

- v1.1: детект в Telegram/WhatsApp-скриншотах — специальные паттерны для мессенджер-мошенничества (Kaspi/OLX-сценарии).
- v1.2: голосовые/SMS (smishing) — текстовый вход с телефонным контекстом, проверка номеров.
- v1.3: awareness-модуль — фишинг-симуляции на базе реальных перехваченных кампаний.
- v2.0: обучение собственного классификатора на корпусе организации (дообученный small-LM), полностью офлайн.

---

## 14. Definition of Done v1.0

- [ ] Разделы 4.1 (web, API, eml/msg/text/image, Telegram), 4.2 (≥ 60 сигналов), 4.3, 4.4, 4.5, 4.7, 4.8.1, 4.9.1–4.9.2 — реализованы; IMAP/Graph/add-ins/sandbox/очередь — Business, минимум Outlook add-in и IMAP в v1.0.
- [ ] Корпус ≥ 200 писем, F1 ≥ 0.9 в CI.
- [ ] Публичное демо развёрнуто, три примера работают ≤ 5 с.
- [ ] Документация сигналов полная (каждый сигнал — своя страница).
- [ ] Пилот в одной организации (можно AIDIA/знакомая компания) 2 недели, ≥ 20 реальных обращений, зафиксированные FP/FN и правки весов.
- [ ] Лендинг + README с GIF, схемой, сравнением с альтернативами (PhishTool, CheckPhish, Sublime).
