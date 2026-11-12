# TASKS: 156 — UTLS_KEY_SHARE_OPTION

**Фича:** [017-REALITY](../../FEATURES/017-REALITY/FEATURE.md) · план — [PLAN.md](PLAN.md)

- [x] 1. SPEC/PLAN/TASKS; строка 156 в Roadmap и FEATURE 017
- [ ] 2. Issue с обоснованием и решение владельца по включению опции
- [x] 3. Стражи `utls_key_share_lx_test.go`; мутация «`classical` = no-op» роняет 19 подтестов
- [x] 4. `lxUTLSKeyShare`/`lxApplyKeyShare`/`lxStripHybridKeyShare`; поле опции; проводка в `utls_client.go` и `lxUTLSConn`; REALITY на общем фильтре; тесты пакета зелёные
- [x] 5. Стенд `lx-test/utls_key_share` против Xray v26.11.9 (Linux): TCP и XHTTP, `""` и `classical` — 4/4
- [x] 6. lx-config EN/RU §7, пометки в SPEC 089 и 122
- [x] 7. IMPLEMENTATION_REPORT.md; статус I
- [ ] 8. Прогон на устройстве в мобильной сети (`""` против `classical` на одном TLS-узле)
