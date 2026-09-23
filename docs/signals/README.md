# Справочник сигналов

Каждый сигнал — отдельная страница `docs/signals/<id>.md` по шаблону:

```
# <id>  (H-xx / D-xx / …)
**Категория:** header | auth | domain | link | attachment | content | brand | reputation | semantic
**Вес по умолчанию:** +N (data/weights.yaml)   **Источник:** heuristic | dns | ti | llm
## Что проверяет
## Почему это признак фишинга
## Доказательство (Evidence)
## Ложные срабатывания и как их снизить
## Тесты
```

Живой список зарегистрированных сигналов с весами: `GET /v1/signals` или `phishlens weights show`.

## Реализовано в каркасе

| ID | ТЗ | Вес | Статус |
|---|---|---|---|
| header.displayname_email | H-01 | 20 | ✅ + тесты |
| header.replyto_mismatch | H-02 | 15 | ✅ + тесты |
| header.returnpath_mismatch | H-03 | 10 | ✅ + тесты |
| auth.spf_fail / spf_softfail / dkim_fail / dkim_none / dmarc_fail / unverified | H-04 | 20/10/15/5/25/3 | ✅ Authentication-Results или собственная SPF/DKIM/DMARC DNS-проверка |
| auth.aligned_official | F-4.5.3 | −40 | ✅ |
| header.messageid_mismatch / messageid_missing | H-06 | 8/5 | ✅ + тесты |
| header.date_skew | H-08 | 8 | ✅ + тесты |
| header.received_ip_listed / bulk_mailer_personal | H-05/H-07 | 30/8 | ✅ TI hook + bulk-mailer header heuristic |
| header.received_private_ip | H-05 hygiene | 3 | ✅ low-confidence route anomaly |
| domain.punycode / mixed_script | D-03 | 20/25 | ✅ |
| domain.brand_lookalike | D-04 | 30 | ✅ (таблица в brands_test) |
| domain.free_mail_org | D-05 | 15 | ✅ |
| domain.risky_tld | D-06 | 10×risk | ✅ |
| link.text_href_mismatch | L-01 | 20 | ✅ |
| link.ip_host / nonstandard_port | L-02 | 20/8 | ✅ |
| link.shortener | L-03 | 10 | ✅ HEAD-разворачивание с лимитом редиректов и SSRF guard |
| link.tracking_pixel / missing_unsubscribe | L-07 | 8/8 | ✅ статический HTML/inline-image анализ |
| QR URL from image | L-08 | — | ✅ gozxing decode; URL проходит обычный link-анализ |
| link.obfuscated | L-04 | 15 | ✅ |
| link.data_uri / cloud_form | L-04/L-06 | 18/18 | ✅ explicit data URI and credential-linked cloud forms |
| link.punycode / brand_lookalike / many_domains | D-03/D-04/L-06 | 20/30/8 | ✅ |
| attachment.dangerous_ext / double_ext / rtl_override | A-01 | 30/25/30 | ✅ |
| attachment.archive_encrypted / archive_executable | A-02 | 25/30 | ✅ zip/RAR4/7z listing without extraction; RAR5 stays opaque |
| attachment.macro | A-03 | 30 | ✅ OOXML and legacy OLE VBA directory markers |
| attachment.html_active | A-06 | 25 | ✅ |
| content.urgency / threat | C-01 | 10/10 | ✅ ru/en/kz |
| content.credential_request | C-02 | 20 | ✅ |
| content.sms_code_request / card_data_request | C-02 | 12/12 | ✅ specialized credential requests |
| content.generic_greeting | C-03 | 8 | ✅ |
| content.language_mismatch | C-04 | 12 | ✅ detected message language vs configured brand locale |
| content.bec_pattern | C-05 | 40 | ✅ |
| content.finance_request | C-06 | 10 | ✅ keywords + KZ IIN/BIN mod-11 check |
| content.bank_detail_change / kz_identifier | C-06 | 15/6 | ✅ split invoice-fraud evidence |
| content.hidden_text | C-07 | 15 | ✅ |
| content.image_only | C-08 | 10 | ✅ |
| brand.sender_mismatch | F-4.3.3 | 35 | ✅ |
| reputation.org_blocklist / org_allowlist | R-03 | 100/−30 | ✅ |
| reputation.ip_listed | R-01 | 30 | ✅ DNSBL |
| reputation.domain_listed | D-02/R-02 | 40 | ✅ local list + OpenPhish + optional authenticated URLhaus |
| reputation.domain_age | D-01 | 25 | ✅ RDAP registration event; provider failure degrades to unknown |
| attachment.pdf_active | A-04 | 25 | ✅ bounded static scan; no rendering or action execution |
| semantic.llm_phishing / suspicious / clean | F-4.4.3 | 25/10/−15 | ✅ |

Не начаты: L-05, A-05.
