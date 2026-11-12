# IMPLEMENTATION REPORT: 156 — UTLS_KEY_SHARE_OPTION

**Фича:** [017-REALITY](../../FEATURES/017-REALITY/FEATURE.md) · контракт — [SPEC.md](SPEC.md)

## Что сделано

| Файл | Содержимое |
|------|-----------|
| `common/tls/utls_key_share_lx.go` | `lxUTLSKeyShare` (опечатка, REALITY, `classical` + ECH — ошибки при построении), `lxApplyKeyShare` (`classical` — фильтр и пересборка, `hybrid` — проверка шара), `lxStripHybridKeyShare` (общий с REALITY) |
| `option/tls.go`, `constant/tls.go` | `OutboundUTLSOptions.KeyShare`; комментарий к `RealityKeyShare*` |
| `common/tls/utls_client.go` | `keyShare` в конфиге, валидация в `newUTLSClient`, `withKeyShare` в `Client()`, `Clone()` |
| `common/tls/utls_release_lx.go` | `withKeyShare`, `helloPrepared`, `lxPrepareHello` |
| `common/tls/reality_client.go` | `classical` → `lxStripHybridKeyShare`; импорт `sing/common` снят |
| `common/tls/utls_key_share_lx_test.go` | `TestLxUTLSKeyShareDefaultKeepsHybrid`, `…ClassicalStripsHybrid`, `…Handshake`, `…HybridRequiresShare`, `…Rejected`, `…SurvivesClone` (26 подтестов; отпечатки `chrome`, `chrome_155`, `firefox`, `safari`, `random`, `randomized`) |
| `lx-test/utls_key_share/` | `run.sh` + `relay.py` — стенд против Xray |
| `lx-test/config/utls_key_share.json` | пример TCP и XHTTP с `classical` |

Апстримные файлы: `option/tls.go`, `constant/tls.go`, `common/tls/utls_client.go`,
`common/tls/reality_client.go` — правки помечены `// lx:`. `go.mod`, сабмодули, build-теги не
менялись: опция живёт под существующим `with_utls`, без поля провод прежний.

## Проверка

Go: go1.26.1 windows/386 на хосте (в `go.version` — go1.26.10); стенд — Linux (WSL2, x86_64).

- `gofmt` по восьми Go-файлам — чисто; `go vet ./common/tls/ ./option/ ./constant/` без тегов и
  с `with_utls` — чисто.
- `go test -tags with_utls -ldflags "-checklinkname=0" ./common/tls/ ./option/` — ok; без тегов — ok.
- Мутация «`classical` = no-op» в `lxApplyKeyShare`: падают 19 подтестов в
  `…ClassicalStripsHybrid`, `…Handshake`, `…SurvivesClone`; остальные зелёные.
- Стражи REALITY 083/086/087/089 зелёные после выноса фильтра.
- `go build ./...` без тегов — ok; `CGO_ENABLED=0 go build -trimpath -tags "<LX_TAGS>" -ldflags "-s -w -checklinkname=0" ./cmd/sing-box`
  для `linux/amd64` и `android/arm64` — ok.
- `sing-box check` на всех `lx-test/config/*.json` (10 файлов) — ok; тот же пример с
  `"classic"` — `unknown utls key_share: classic (expected "hybrid" or "classical")`.

### Стенд

`XRAY=… SING_BOX=… lx-test/utls_key_share/run.sh`, Xray v26.11.9 (официальный релиз,
`Xray-linux-64.zip`), sing-box-lx с `LX_TAGS`, `linux/amd64`, 2026-11-13:

```
tcp-default: OK (ClientHello 1917 B, xray accepted 1)
tcp-classical: OK (ClientHello 759 B, xray accepted 1)
xhttp-default: OK (ClientHello 1940 B, xray accepted 1)
xhttp-classical: OK (ClientHello 750 B, xray accepted 1)
```

Тот же контур на Windows (Xray v26.11.9 `windows-32`, внешний адрес через `freedom`) — 204 на
всех четырёх; `classical` 688–793 байта, `""` 1942–1983. Размер плавает от запуска к запуску:
у пресета Chrome GREASE-ECH случайной длины.

## Не проверено

- Устройство и мобильная сеть, ради которых опция заведена.
- XHTTP h3 / QUIC — вне скоупа по построению (SPEC §Транспорты).
- `-race`: на хосте нет cgo.
