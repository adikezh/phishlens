# Бренды

data/brands.yaml — стартовый набор 100+ брендов. Поля: name, domains (официальные),
esp_domains (рассыльщики бренда), keywords, locale, colors, logo_phash.

Inline images and image submissions produce a perceptual hash. When a brand
has a valid `logo_phash`, hashes within Hamming distance 8 produce a `logo`
brand match. Image palettes are also compared with configured `colors` and can
produce a `color` brand match; this is advisory evidence and should be combined
with domains or message content.

Правила:
- бесплатные почтовые домены (gmail.com, outlook.com, icloud.com) **не** являются доменами бренда —
  иначе любое письмо с Gmail станет «официальным письмом Google» и получит −40;
- keywords — короткие маркеры, по которым определяется имитация в теме/теле; общие слова (bank, pay) в
  stopLabel матчера игнорируются при сравнении доменов.

Определение (internal/brands.Matcher.Match): домен отправителя (официальный / lookalike) → домены ссылок (lookalike)
→ ключевые слова. Lookalike: токен бренда в чужом домене (kaspi-secure-login.com), гомоглифы (kаspi.kz),
Дамерау–Левенштейн (1 правка для коротких меток, 2 — для ≥ 8 символов).

Кастомные бренды организации: `phishlens brands add --name "Acme" --domains acme.kz --keywords acme`
или `POST /v1/brands` (admin).
