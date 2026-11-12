# SPEC: 156 — UTLS_KEY_SHARE_OPTION

**Фича:** [REALITY](../../FEATURES/017-REALITY/FEATURE.md) (линия uTLS-приветствия: [083](../083-REALITY_MLKEM_KEYSHARE/SPEC.md) → [089](../089-REALITY_KEY_SHARE_OPTION/SPEC.md) → эта; та же ручка, но для обычного TLS)

| Поле | Значение |
|------|----------|
| Тип | F (feature) — опция `tls.utls.key_share` (`hybrid` / `classical`): по-узловой выбор, нести ли в uTLS ClientHello обычного TLS (не REALITY) гибридный key share `X25519MLKEM768`. Двойник `tls.reality.key_share` (089) |
| Статус | I (implemented) — стражи зелёные, полная сборка, стенд [`lx-test/utls_key_share`](../../../lx-test/utls_key_share/run.sh) против Xray v26.11.9 (TLS + TCP и TLS + XHTTP, 4/4); на устройстве и в поле не прогонялось. Отчёт — [IMPLEMENTATION_REPORT.md](IMPLEMENTATION_REPORT.md) |
| Ветка | `lx-utls-key-share` от `lx` |
| Связанные | [089](../089-REALITY_KEY_SHARE_OPTION/SPEC.md) (тот же фильтр, теперь общий), [118](../118-UTLS_CHROME_155/SPEC.md) (`chrome_155` несёт гибрид), [122](../122-UTLS_RELEASE_HANDSHAKE_STATE/SPEC.md) (обёртка `lxUTLSConn`, в которую встроено применение), [088](../088-REALITY_FRAGMENT_BYPASS/SPEC.md) (фрагментация — другой ответ на тот же симптом); Xray [#6256](https://github.com/XTLS/Xray-core/issues/6256), Xray PR [#7135](https://github.com/XTLS/Xray-core/pull/7135) (Chrome 155 по умолчанию) |

**Touches:** `option/tls.go` (`OutboundUTLSOptions.KeyShare`), `constant/tls.go` (комментарий к `RealityKeyShare*`), `common/tls/utls_client.go` (поле `keyShare`, валидация в `newUTLSClient`, передача в `Client()`, `Clone()`), `common/tls/reality_client.go` (`classical` зовёт общий `lxStripHybridKeyShare`, снят импорт `sing/common`), `common/tls/utls_release_lx.go` (122: `withKeyShare`, `alpnApplied` → `helloPrepared`, `lxPrepareHello`), `common/tls/utls_release_lx_test.go` (переименование флага), новые `common/tls/utls_key_share_lx.go` и `common/tls/utls_key_share_lx_test.go`, стенд `lx-test/utls_key_share/{run.sh,relay.py}`, пример `lx-test/config/utls_key_share.json`, `SPECS/README.md`, `SPECS/FEATURES/017-REALITY/FEATURE.md`, `docs-lx/lx-config.{ru.,}md` (подраздел §7; §0 не тронут — его пример на REALITY, где `utls.key_share` — ошибка).

## Why

Ноябрь 2026, мобильные операторы: TLS-узлы (VLESS поверх TLS на TCP и XHTTP, без REALITY) с `fp=chrome` перестают подниматься — TCP установлен, ClientHello уходит, ответа нет. Гибридный шар `X25519MLKEM768` (+1216 байт) делает приветствие `chrome`/`chrome_155` длиной 1,9–2 КБ, оно уходит двумя TCP-сегментами. Тот же симптом, что в [089](../089-REALITY_KEY_SHARE_OPTION/SPEC.md) и Xray [#6256](https://github.com/XTLS/Xray-core/issues/6256): двухсегментное приветствие теряется, односегментное проходит. **Что именно на пути срабатывает — не доказано**, гипотезы (размер, отпечаток Chrome 133, состояние адреса) в этой задаче не разбираются.

Для REALITY ручка уже есть (089), но там `classical` упирается в сервер: Xray ≥ v26.9.8 приветствие без гибрида отвергает. У обычного TLS такого ограничения нет: Xray TLS-inbound (Go `crypto/tls`), Caddy, nginx, CDN выбирают X25519, если клиент ML-KEM не предлагает. Значит для TLS-узлов короткое приветствие — рабочий ответ без размена на совместимость с сервером, и его стоит дать по узлу.

Почему не `curve_preferences`: опция действует только на std-клиенте, uTLS-пресет её игнорирует (`copyConfig` не переносит). Почему не отпечаток `edge`/`ios`/`android`: это обещание «выгляжу как Edge 85», а не «не шлю ML-KEM» (089 §Why), и старые пресеты, по полевым наблюдениям, режутся тоже.

## Опция

`tls.utls.key_share` — строка, значения и смысл как у `tls.reality.key_share`:

| Значение | Поведение |
|---|---|
| `""` (не задано) | Как несёт отпечаток. Приветствие байт-в-байт то же, что без опции (обёртка 122 вызывает `lxApplyKeyShare` только при непустом значении). |
| `"classical"` | `X25519MLKEM768` вырезается из `supported_groups` и `key_share`. `chrome_155` на стенде: 690–800 байт вместо 1,9–2 КБ, один TCP-сегмент. Сервер выбирает X25519 без HelloRetryRequest. |
| `"hybrid"` | Гибрид обязателен: на отпечатке без него первое рукопожатие падает с `utls key_share "hybrid": fingerprint Edge 85 carries no X25519MLKEM768 key share`. На `chrome`/`chrome_155`/`firefox`/`safari` ничего не меняет. |

Ошибки при построении outbound'а:

- неизвестное значение — `unknown utls key_share: classic (expected "hybrid" or "classical")`;
- вместе с `reality.enabled` — `utls key_share is unsupported in reality, use reality.key_share` (REALITY собирает свой `UConn`; одна ручка на рукопожатие);
- `classical` вместе с `ech.enabled` — `utls key_share "classical" is unsupported with ECH` (внутреннее и внешнее приветствия ECH собираются внутри utls из тех же расширений, вырезание там не покрыто).

```json
"tls": {
  "enabled": true,
  "server_name": "example.com",
  "alpn": ["h2"],
  "utls": { "enabled": true, "fingerprint": "chrome_155", "key_share": "classical" }
}
```

## Транспорты

Опция живёт в uTLS-клиенте, поэтому действует везде, где TLS поверх TCP идёт через `tls.NewDialer` / `ClientHandshake` → `UTLSClientConfig.Client`:

| Транспорт | Действует |
|---|---|
| raw TCP (VLESS/Trojan/VMess + TLS) | ✅ стенд: 759–793 байта, сервер Xray v26.11.9 принимает |
| XHTTP h1/h2, все режимы | ✅ стенд: 688–750 байт, сервер Xray v26.11.9 принимает |
| WebSocket, HTTPUpgrade, gRPC (full и lite), HTTP (h2) | ✅ тот же путь, юниты обёртки 122 |
| XHTTP h3, Hysteria2, TUIC, naive и прочий QUIC | ❌ uTLS не участвует; приветствие QUIC — отдельная история |
| REALITY | ❌ своя ручка `reality.key_share` (089), здесь — ошибка конфига |

## Как реализовано

- **Валидация** — `lxUTLSKeyShare(options)` в `newUTLSClient` после выбора отпечатка; значение кладётся в `UTLSClientConfig.keyShare`, `Clone()` переносит (outbound'ы клонируют TLS-конфиг на каждый dial).
- **Применение** — в обёртке 122: `Client()` отдаёт `newLXUTLSConn(...).withKeyShare(c.keyShare)`. Первый `HandshakeContext` вызывает `lxPrepareHello`: `lxApplyALPN` (если ALPN задан) или `BuildHandshakeState()`, затем `lxApplyKeyShare`. Флаг `alpnApplied` стал `helloPrepared`: приветствие готовится один раз, неудачная сборка оставляет флаг снятым, повтор пересобирает — как раньше.
- **`classical`** — `lxStripHybridKeyShare` (`common.Filter` по `SupportedCurvesExtension.Curves` и `KeyShareExtension.KeyShares`) и второй `BuildHandshakeState()`: пресет применён один раз, второй вызов перемаршаливает hello из отфильтрованных расширений, ключ X25519 остаётся в `KeyShareKeys.Ecdhe`. Это тот же фильтр, что в 089, теперь одна функция на оба клиента: REALITY зовёт её в `prepareClientHello`.
- **Оба списка — намеренно.** Гибрид, оставленный в `supported_groups` без шара, позволил бы серверу на Go ≥ 1.24 ответить HelloRetryRequest на `X25519MLKEM768` и всё равно получить длинное приветствие вторым полётом.
- **`hybrid`** — `realityHelloCarriesHybridShare(uConn)` из 089.

## Требования

- **R1.** `""` не меняет ClientHello ни для одного отпечатка (`TestLxUTLSKeyShareDefaultKeepsHybrid`).
- **R2.** `classical` убирает `X25519MLKEM768` из обоих расширений на `chrome`/`chrome_155`/`firefox`/`safari`/`random`/`randomized`, оставляет запись X25519, совпадающую с `Ecdhe`; сырой hello короче 1184 байт. С ALPN `h2` и с ALPN пресета (`TestLxUTLSKeyShareClassicalStripsHybrid`).
- **R3.** Рукопожатие со стоковым `crypto/tls`-сервером: `classical` → сервер видит группы без ML-KEM и договаривается на `X25519`; `""` → `X25519MLKEM768`; данные проходят (`TestLxUTLSKeyShareHandshake`).
- **R4.** `hybrid` на отпечатке без шара — ошибка с именем отпечатка; на `chrome` — без изменений (`TestLxUTLSKeyShareHybridRequiresShare`).
- **R5.** Опечатка, сочетание с REALITY и `classical` + ECH отвергаются при построении (`TestLxUTLSKeyShareRejected`); `Clone()` сохраняет политику (`TestLxUTLSKeyShareSurvivesClone`).
- **R6.** Поведение REALITY `key_share` (089) не меняется: его стражи зелёные после выноса фильтра.

## Критерии приёмки

1. Стражи R1–R5 в `common/tls/utls_key_share_lx_test.go` и весь `common/tls`, `option`, `constant` зелёные (`-tags with_utls -ldflags "-checklinkname=0"`). Мутация «`classical` — no-op» роняет 19 подтестов в трёх тестах. ✅ 2026-11-13
2. Сборка полным `LX_TAGS` для `linux/amd64` и `android/arm64`. ✅ 2026-11-13
3. `sing-box check`: конфиг VLESS + XHTTP с `key_share: classical` принят, `classic` отвергнут с текстом. ✅ 2026-11-13
4. Стенд `lx-test/utls_key_share/run.sh` против Xray v26.11.9 (официальный релиз), два VLESS TLS-inbound (raw TCP и XHTTP `alpn: h2`), самоподписанный сертификат, ретранслятор меряет первую TLS-запись. Linux: TCP 1917 → 759 байт, XHTTP 1940 → 750, все четыре прогона дошли до сервера. Windows: 1942–1983 → 688–793, 204. Разброс — GREASE-ECH пресета. ✅ 2026-11-13
5. Проводка в приложениях и прогон на мобильной сети. ⏳ «Остаток»

## Границы

- **Не автофолбэк** — по тем же причинам, что в 089 §Границы.
- **Не для REALITY.** Там `reality.key_share`, и `classical` на Xray ≥ v26.9.8 = отказ сервера.
- **Не QUIC.** XHTTP h3, Hysteria2, TUIC — приветствие строит не uTLS.
- **Не ECH + `classical`.** Отвергается конфигом; если понадобится — отдельная задача с фильтрацией внутри сборки ECH в utls.
- Ядро отпечаток не подменяет и `chrome` не перенаправляет на другой пресет.
- `classical` снимает постквантовую защиту рукопожатия на этом узле — это выбор узла, а не дефолт.

## Остаток

- **Приложения / панель:** поле `key_share` в модели узла и подписке, проводка в `tls.utls.key_share`, предупреждение «отключает постквантовую защиту рукопожатия».
- Полевой прогон на мобильной сети: один TLS-узел, `""` против `classical`.

## Условие снятия

Не хотфикс, а опция — снимать нечего. Что сторожить на мерже: `lxStripHybridKeyShare` вызывается только под `classical` (в REALITY и в `lxApplyKeyShare`); если апстрим вернёт безусловный фильтр гибрида в uTLS-клиент, упадёт `TestLxUTLSKeyShareDefaultKeepsHybrid`. Если апстрим заведёт свою опцию того же смысла — переехать на его имя, оставив `key_share` алиасом на один релиз.
