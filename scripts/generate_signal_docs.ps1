param(
    [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
)

$signalIDs = @(
    'auth.aligned_official','auth.dkim_fail','auth.dmarc_fail','auth.spf_fail','auth.unverified',
    'attachment.archive_encrypted','attachment.archive_executable','attachment.dangerous_ext','attachment.double_ext','attachment.html_active','attachment.macro','attachment.pdf_active','attachment.rtl_override','attachment.virustotal',
    'brand.sender_mismatch',
    'content.bank_detail_change','content.bec_pattern','content.card_data_request','content.credential_request','content.finance_request','content.generic_greeting','content.hidden_text','content.image_only','content.kz_identifier','content.language_mismatch','content.sms_code_request','content.threat','content.urgency',
    'domain.brand_lookalike','domain.free_mail_org','domain.mixed_script','domain.punycode','domain.risky_tld',
    'header.bulk_mailer_personal','header.date_skew','header.displayname_email','header.messageid_mismatch','header.messageid_missing','header.received_ip_listed','header.received_private_ip','header.replyto_mismatch','header.returnpath_mismatch',
    'link.brand_lookalike','link.cloud_form','link.data_uri','link.ip_host','link.login_form','link.many_domains','link.missing_unsubscribe','link.nonstandard_port','link.obfuscated','link.punycode','link.shortener','link.text_href_mismatch','link.tracking_pixel',
    'reputation.domain_age','reputation.domain_listed','reputation.ip_listed','reputation.org_allowlist','reputation.org_blocklist',
    'semantic.llm_clean','semantic.llm_phishing','semantic.llm_suspicious'
)

$requirements = @{
    auth='H-04'; attachment='A-01..A-06'; brand='F-4.3.3'; content='C-01..C-08'; domain='D-03..D-06'; header='H-01..H-08'; link='L-01..L-08'; reputation='R-01..R-03 / D-01..D-02'; semantic='F-4.4.3'
}
$signalsDir = Join-Path $Root 'docs/signals'
New-Item -ItemType Directory -Force -Path $signalsDir | Out-Null
foreach ($id in $signalIDs) {
    $path = Join-Path $signalsDir ($id + '.md')
    if (Test-Path -LiteralPath $path) { continue }
    $category = $id.Split('.')[0]
    $name = ($id.Split('.')[1] -replace '_', ' ')
    $text = @"
# $id

**Категория:** $category  **Требование ТЗ:** $($requirements[$category])  **Источник:** heuristic/ti/llm

## Что проверяет

Зарегистрированная проверка $id анализирует метаданные, содержимое или внешний результат,
указанные в контракте PhishLens. Проверка не исполняет вложения и возвращает только
объяснимый сигнал с доказательством и confidence.

## Почему это важно

Признак «$name» может указывать на фишинг, социальную инженерию или подозрительную
инфраструктуру. Он является частью суммы сигналов и сам по себе не заменяет итоговый
вердикт, кроме явно описанных жёстких правил.

## Доказательство и ограничения

В Signal.Evidence сохраняется ограниченный фрагмент или безопасное техническое значение.
Ошибки внешних источников деградируют в 'unknown' и не ломают анализ. Тела сообщений и
секреты во внешние интеграции не передаются этим документом.

## Ложные срабатывания

Легитимные рассылки, корпоративные прокси, платёжные подрядчики и нестандартные почтовые
клиенты могут выглядеть так же. Снижение риска выполняется через allowlist, ESP-домены,
порог confidence и ручную метку аналитика.

## Тесты

Проверка зарегистрирована в internal/signals/$category/register.go; позитивные и
негативные сценарии находятся рядом с реализацией. Полный registry/docs parity проверяется
тестом internal/signals/docs_test.go.
"@
    Set-Content -LiteralPath $path -Value $text -Encoding utf8NoBOM
}
Write-Output "Signal documentation ensured: $($signalIDs.Count) pages"
