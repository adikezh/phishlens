# header.replyto_mismatch  (H-02)

**Категория:** header  **Вес по умолчанию:** +15  **Уверенность:** 0.9  **Источник:** heuristic
**Код:** `internal/signals/header/h02_replyto_mismatch.go`

## Что проверяет
Регистрируемый домен (eTLD+1) заголовка `Reply-To` отличается от домена `From`.
`mail.kaspi.kz` и `kaspi.kz` считаются одним доменом.

## Почему это признак фишинга
Злоумышленник подделывает `From` (или использует похожий домен), но ответ жертвы должен попасть
к нему — поэтому `Reply-To` указывает на контролируемый им ящик. Типично для BEC и «поддержки банка».

## Доказательство
`Reply-To: support@kaspi-secure-login.com | From: security@kaspi.kz`

## Ложные срабатывания
- Рассылочные платформы (`reply@mailer.example`) — снижается через `esp_domains` бренда (пока учитывается только в H-03; TODO применить и здесь).
- Тикет-системы (`support@helpdesk.vendor.com`) — добавить домен в allowlist организации.

## Тесты
`internal/signals/header/header_test.go: TestReplyToMismatch` — 3 позитивных, 3 негативных.
