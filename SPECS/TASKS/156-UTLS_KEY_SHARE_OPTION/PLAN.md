# PLAN: 156 — UTLS_KEY_SHARE_OPTION

**Фича:** [017-REALITY](../../FEATURES/017-REALITY/FEATURE.md) · контракт — [SPEC.md](SPEC.md)

## Файлы

| Файл | Что меняется |
|------|--------------|
| `common/tls/utls_key_share_lx.go` (новый, `with_utls`) | `lxUTLSKeyShare(options)` — валидация при построении outbound'а; `lxApplyKeyShare(uConn, keyShare)` — политика на собранном hello; `lxStripHybridKeyShare(uConn)` — фильтр `X25519MLKEM768`, вынесенный из `reality_client.go` |
| `option/tls.go` | `OutboundUTLSOptions.KeyShare` (`json:"key_share"`), блок `// lx:begin/end SPEC 156` |
| `constant/tls.go` | строка комментария: значения `RealityKeyShare*` служат и `utls.key_share` |
| `common/tls/utls_client.go` | поле `keyShare` в `UTLSClientConfig`; `lxUTLSKeyShare` в `newUTLSClient`; `Client()` передаёт политику в `lxUTLSConn`; `Clone()` её переносит — всё `// lx:` |
| `common/tls/utls_release_lx.go` (lx-файл 122) | `withKeyShare`; `alpnApplied` → `helloPrepared`; `lxPrepareHello` = ALPN 122, затем `lxApplyKeyShare` |
| `common/tls/reality_client.go` | `case classical` зовёт `lxStripHybridKeyShare` вместо встроенного фильтра; импорт `sing/common` снят |
| `common/tls/utls_key_share_lx_test.go` (новый) | стражи R1–R5 |
| `common/tls/utls_release_lx_test.go` | переименование флага |
| `lx-test/utls_key_share/{run.sh,relay.py}`, `lx-test/config/utls_key_share.json` | стенд против Xray и пример для `sing-box check` |
| `SPECS/…`, `docs-lx/lx-config.{ru.,}md` | SPEC/PLAN/TASKS/отчёт, Roadmap, FEATURE 017, пометки в 089 и 122, подраздел §7 |

## Почему внутри обёртки 122, а не в `Client()`

`Client()` отдаёт соединение до рукопожатия, а hello собирается в первом `HandshakeContext`:
пресет uTLS применяется в `BuildHandshakeState`, после него ALPN-подмена 122 пересобирает
hello второй раз. Политика должна идти после обоих — иначе пересборка ALPN вернёт гибрид
пресета. `lxUTLSConn` уже держит «собрать один раз под мьютексом, при ошибке повторить», поэтому
политика встроена туда же, а флаг переименован в `helloPrepared`. Без политики и без ALPN
обёртка не вызывает ничего лишнего — провод апстрима.

## Почему общий фильтр с 089

Фильтр — одно и то же правило над одним и тем же `UConn` в двух клиентах. Две копии
разошлись бы на первом же изменении utls (новая гибридная группа, другой тип расширения).
Вынос меняет в `reality_client.go` только тело `case classical` на один вызов; стражи 089
сторожат REALITY-путь как раньше.

## Почему ошибка с REALITY и с ECH

- REALITY строит свой `UConn` в `prepareClientHello` и не проходит через `lxUTLSConn`:
  `utls.key_share` там молча не действовал бы. Одна ручка на рукопожатие — `reality.key_share`.
- ECH: внутреннее и внешнее приветствия utls собирает из тех же расширений внутри себя;
  фильтр поверх собранного состояния это не покрывает. Лучше отказ конфига, чем hello с
  гибридом во внутреннем приветствии при `classical`. `hybrid` с ECH допустим — это проверка.

## Проверка

- `gofmt`, `go vet` (без тегов и `with_utls`), `go test -tags with_utls -ldflags "-checklinkname=0" ./common/tls/ ./option/`.
- Мутация: `classical` = no-op → стражи R2/R3 падают.
- `go build ./...`; сборка `LX_TAGS`; `sing-box check` на `lx-test/config/*.json`.
- `lx-test/utls_key_share/run.sh` против официального Xray: TCP и XHTTP, `""` и `classical`.
