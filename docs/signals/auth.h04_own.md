# auth.h04_own (H-04)

**Категория:** auth  
**Вес по умолчанию:** использует существующие H-04 сигналы  
**Источник:** dns

## Что проверяет

Если в письме нет `Authentication-Results`, PhishLens выполняет bounded
проверку по исходному `.eml`: SPF — для первого внешнего IP из `Received`,
DKIM — с проверкой подписи и ключа `selector._domainkey` через DNS, DMARC — по
`_dmarc.<from-domain>` с relaxed/strict alignment для SPF и DKIM.

Результаты записываются только в нормализованный `AuthResults` с источником
`own`; исходное письмо остаётся in-process и не сохраняется в JSON/Community
SQLite.

## Почему это важно

Одного отсутствия `Authentication-Results` недостаточно, чтобы считать письмо
фишинговым. Внешняя сеть может быть недоступна, поэтому DNS-ошибки дают
неизвестный результат/предупреждение, а не положительную угрозу.

## Ложные срабатывания и ограничения

- SPF использует доступный внешний `Received` IP и envelope sender; если их
  нет, SPF остаётся неизвестным.
- DMARC policy проверяется без исполнения каких-либо действий; отсутствие
  записи `_dmarc` даёт `none`.
- DKIM с malformed signature даёт `permerror`, а transient DNS failure не
  превращается в `pass`.

## Тесты

`internal/authcheck/authcheck_test.go` проверяет SPF/DMARC pass, fail при
неавторизованном IP и отсутствие DMARC-записи на fake DNS resolver.
