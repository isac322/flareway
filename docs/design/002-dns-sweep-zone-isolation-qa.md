# Flareway 설계 002 — DNS 스윕 zone 격리(issue #93) 분석·설계·QA

- 작성일: 2026-09-22
- 상태: **구현 및 로컬 QA 완료.** 18개 QA ID와 명시된 모든 하위 사례(QA-10(d) 포함)를 실행해 PASS를 확인했다. 최종 PR/CI 및 생성물 게이트는 별도 추적한다.
- 입력: issue #93 본문과 실행 증거 코멘트, `internal/sweep` 현재 소스, 조사·안전 분석 합의.
- 표기: `[E]` 실행 증거, `[D]` 설계 결정, `[C]` 토론 중 기각·정정된 사항, `[live-blocked]` 실계정/실배포 검증이 남은 주장.

---

## 1. 요약 — 핵심 결정

1. **결함**: `sweepDNSRecords`가 계정 전체 zone을 순회하며 zone-scoped DNS 레코드를 수집할 때, 어느 한 zone의 목록 오류(403 등)가 `listFailure`를 거쳐 즉시 fatal 반환된다. 이미 수집한 건강 zone의 레코드는 폐기되고, 이후 zone은 질의되지 않으며, 판정 단계에 도달하지 못해 drift item·invalidation·wakeup event가 전부 소실된다. 거부 zone이 먼저 오든 나중에 오든 결과는 동일하다 `[E]`.
2. **수정 방향**: zone 단위 실패를 격리한다. 403/404/5xx/전송/페이지네이션 오류는 해당 zone의 수집물 전체를 폐기하고 다음 zone으로 계속 진행하며, 건강 zone의 안전한 drift item은 그대로 판정·디스패치한다 `[D]`.
3. **계약**: `SweepFunc` 시그니처는 유지한다. 부분 안전 items는 비공개 `scopedListingError`(발견 순서 보존 `[]error`, 각 요소 `*zoneFailure{zoneID, err}`)를 통해서만 반환된다. `RunTargetOnce`는 generic `errIncompleteListing`보다 typed scoped 오류를 먼저 인식해 `(items, partial, 집계 오류)`를 반환하고, `runTarget`은 partial 분기를 generic error보다 먼저 처리해 진단을 로깅하고 안전 items를 디스패치한다 `[D]`.
4. **fail-closed 보존**: 실패 zone의 checkpoint는 `listedZones` 격리로 missing 판정에서 제외된다. generic `errIncompleteListing`과 `(nil, nil)` 반환은 기존처럼 nil-items partial이며, 단일-scope target의 미검증 부분 목록은 절대 유출되지 않는다 `[D]`.
5. **fatal 경계**: context 취소/데드라인, HTTP 429(계정 수준 스로틀링), HTTP 401(보수적 중단 정책 — 전역 인증 무효의 증명이 아님), 열거되지 않은 4xx(400/405/422 등), 그리고 클라이언트 페이싱 실패(`flarecloudflare.ErrRateLimitWait`)는 pass를 즉시 중단하며 이후 zone 호출과 findings를 만들지 않는다 `[D]`.
6. **범위 외**: Access 스위퍼 리팩터링, 자격증명 확대, checkpoint-only 열거로의 범위 축소, CRD/provisioning 변경, map·공개 API 확장은 전부 하지 않는다 `[D]`.

---

## 2. 증거와 그 한계

### 2.1 실행 증거 `[E]`

issue #93의 재현 Go probe를 작성자가 두 리비전에서 직접 실행했다.

| 리비전 | 정체 | 결과 |
|---|---|---|
| `dd322e3ec216a64425489045bfde2e5def3080bc` | 태그 `v0.2.0`(최초 포함 릴리스) | denied-first **FAIL**, denied-last **FAIL**, worker event 단언 **FAIL**; healthy target control **PASS**, healthy worker control **PASS** |
| `3d75780715a75edc6f05d072f9be33f6765c6227` | 현재 `main` = 릴리스 `v0.2.1` | 동일하게 실패/통과. 결함 미수정 상태 확인 |

- 결함 도입: PR #90, merge commit `e54a0302f78bf0eb4d9cd0a40ebf89f3158d95eb`(2026-09-22T02:01:50Z). 계정 전체 스윕 워커의 최초 도입.
- 최신 릴리스 `v0.2.1`은 2026-09-22T13:47:28Z에 게시됐으며 동일 코드 경로를 포함한다.
- probe는 provider API 경계에서만 결함을 주입한다(HTTP stub / fake `flarecloudflare.API`). Kubernetes fake client와 실제 `AccountSweeper.RunTargetOnce`·`runTarget`·`sweepDNSRecords`를 사용하며, 프로젝트 스윕 로직과 결과 findings는 mock하지 않는다.
- 미수정 워크트리(`dd322e3e`)에서 `go test -mod=readonly -count=1 ./internal/sweep` 실행 결과 **PASS (0.844s)** — 결함이 존재하는 상태에서 기존 스윕 테스트 스위트가 녹색이라는 것이 유출(escape) 경로의 커버리지 공백을 입증한다. 신규 issue probe는 위 표대로 FAIL이다. 단, 이것은 "모든 기존 테스트를 감사했다"는 주장이 아니라 해당 패키지 스위트의 실행 결과다.

### 2.1.1 실행된 것과 계획된 것의 구분

| 구분 | 항목 |
|---|---|
| **실행 완료** `[E]` | issue probe의 pre-fix control, 구현 후 전체 QA 18개 ID와 모든 하위 사례, 로컬 게이트(`make lint-fix`, `make test`, race 반복), 소스 리비전 동일성 확인 |
| **별도 추적** | `make verify-generated`, CI 전체 녹색, 실배포/실계정 검증 `[live-blocked]` |

구현 후 QA는 §9 표에 기록한 probe·stub·cfstub 하네스로 실행했다. 원래 함수 본문 overlay는 denied-first/denied-last에서 변경 전 FAIL, 변경 후 PASS였고 healthy single/multi controls는 양쪽에서 PASS였다. 미들웨어 guard-removal overlay도 scoped absorption에서 변경 전 FAIL, 변경 후 PASS였다.

pre-fix control이 실제로 행사한 것은 좁다: healthy target control은 `result=ok`와 missing item 1건을, healthy worker control은 invalidation 1과 wakeup event 1을 확인했다. 구현 후 QA-01의 단일·다중 zone과 메트릭·이벤트 단언은 §9의 PASS 결과로 별도 검증했다.

### 2.2 릴리스와 배포의 구분

- **주장 가능**: 결함 코드 경로가 `v0.2.0`·`v0.2.1`·현재 `main`에 소스 동일성으로 존재한다.
- **주장하지 않음**: 실제 배포 환경에서의 직접 관측. issue의 라이브 관측(계정의 다수 zone에 대한 403 반복, 컨트롤러 로그의 `target sweep failed`)은 보고자의 익명화된 데이터이며 이 문서의 검증이 아니다 `[live-blocked]`.
- **주장하지 않음**: 라이브 토큰의 정확한 권한 정책. Cloudflare 토큰 검증은 감사 환경에서 할당된 정책/스코프를 노출하지 않으며, HTTP 403만으로는 고유한 인가 원인을 특정할 수 없다. per-zone 403이 도달 가능하다는 것은 Cloudflare 문서(zone-scoped token permission)와 보고자 관측으로 뒷받침된다 `[live-blocked]`.
- **주장 가능**: 구현 후 로컬 QA와 로컬 명령의 결과는 §9·§10에 기록한다. CI·생성물 게이트의 성공과 라이브 회귀 없음은 주장하지 않는다.

### 2.3 증거의 한계

- probe는 라이브 페이지네이션, 레이트 리밋, provider 가용성을 실제로 행사하지 않는다. per-zone 권한 경계와 결과 전파를 격리한다.
- 프로덕션 메트릭은 별도 측정되지 않았다. worker notification 경계는 실행된 worker control로만 확인됐다.
- 403 응답의 Cloudflare 오류 코드(예: 10000 "Authentication error")는 분류에 영향이 없다 — sweeper는 HTTP status만 본다. 라이브 거부 응답의 정확한 코드는 미검증이다 `[live-blocked]`.

---

## 3. 인과 분석 — 발생 / 유출 / 억제

### 3.1 발생(occurrence) — 왜 결함이 생겼는가

1. `sweepDNSRecords`(`internal/sweep/targets_dns.go:78-90`)는 계정 전체 zone을 순서대로 순회하며 zone마다 `ListDNSRecordsByComment`를 호출한다.
2. 첫 실패에서 `return nil, listFailure(err)`가 즉시 반환한다. `listFailure`(`account_sweeper.go:48-59`)는 HTTP 4xx를 "확정적 클라이언트 거부"로 분류해 원본 오류를 그대로 전파한다.
3. `RunTargetOnce`(`account_sweeper.go:214-236`)는 이를 `result=error`로 매핑하고 nil items를 반환한다. `runTarget`(`account_sweeper.go:196-208`)은 오류를 로깅하고 `handleDriftResults`를 호출하지 않는다.
4. 결과: 이미 수집된 건강 zone의 레코드는 판정 전에 폐기되고, 미질의 zone은 영원히 평가되지 않으며, 그 pass의 모든 per-object invalidation과 wakeup event가 소실된다.

### 3.2 유출(escape) — 왜 기존 방어가 못 막았는가

1. `listFailure`의 "4xx = 계정 전역 거부" 모델은 계정-scope 목록에서는 올바른 fail-closed지만, **per-zone 인가 이질성**(토큰이 일부 zone에만 DNS:Read를 가진 경우)을 모델링하지 못한다. zone-scope 호출에 같은 분류기를 적용한 것이 설계 공백이다. 미수정 워크트리에서 `go test -mod=readonly -count=1 ./internal/sweep`가 PASS(0.844s)한 것이 이 공백을 입증한다 — 결함이 존재하는데도 기존 스위트는 녹색이다 `[E]`.
2. 기존 단위 커버리지는 `listFailure(403)`를 격리해서만 단언하고, 성공/실패가 섞인 다중 zone 루프를 검사하지 않았다.
3. `listedZones` 격리(`targets_dns.go:128`)는 존재하지만 fatal 조기 반환이 판정 단계 자체를 우회하므로 도달 불가능한 방어였다.

### 3.3 억제(containment) — 무엇이 피해를 제한했는가, 못했는가

- **제한된 것**: false missing은 발생하지 않는다. 부분 목록을 완전 목록으로 오인해 건강 객체를 missing으로 판정하는 최악의 시나리오는 기존 fail-closed가 막는다. pass-level 오류는 메트릭(`result=error`)과 로그에 남는다.
- **제한 못한 것**: 탐지 사각지대. 거부 zone이 인벤토리에 남아 있는 한 매 pass가 동일하게 실패하므로, 관리 zone의 삭제·변조 DNS 레코드가 스윕 경로로 보고되지 않고(`DriftItem` 없음, invalidation 없음, wakeup event 없음) 소유 `CloudflareTunnel`이 재조정되지 않는다. orphan cleanup도 사각이다 — 읽기 가능 zone의 stray marker 레코드가 보고되지 않는다. 권한 경계가 안정적이면 이 상태는 무기한 지속되며 `last-success`는 진행하지 않는다.

---

## 4. 반사실(counterfactual) 분석

| 반사실 | 기대 결과 | 근거 |
|---|---|---|
| 거부 zone이 마지막에 열거됐다면? | 여전히 실패. 수집된 건강 레코드가 판정 전 폐기된다 | denied-last 케이스 FAIL `[E]` |
| 모든 zone이 읽기 가능했다면? | 정상 동작. missing 감지, invalidation, event 발송 | healthy control PASS `[E]` |
| 루프 계속만 하고 partial이 nil-items를 유지한다면? | 건강 findings는 여전히 소실 | 결과 처리 경계(`runTarget`이 partial에서 dispatch 안 함)가 별도 결함 지점 |
| items만 dispatch하고 첫 오류 중단을 유지한다면? | denied-first에서 미질의 zone이 여전히 손실 | 두 수정은 각각 필요충분이 아니라 함께 필요 |
| 열거를 checkpoint zone으로만 제한한다면? | 증상은 완화되나 계정 전체 orphan 발견과 grant 취소 zone의 cleanup 의무 추적이 소실 — 동등한 수정이 아님 | §6 대안 A 기각 |
| 403을 "레코드 없음"으로 해석한다면? | 미평가 zone을 빈 성공 목록으로 취급해 false missing 발생 — 절대 금지 | fail-closed 불변식 |

---

## 5. 설계 계약 `[D]`

### 5.1 타입드 scoped partial 계약

```text
zoneFailure        { zoneID string; err error }              // 비공개, 래핑된 원인 보존
  .Error()  — "zone <id>: <cause>"
  .Unwrap() — 원인 error
scopedListingError { failures []error }                      // 비공개, 각 요소 *zoneFailure, 발견 순서 보존
  .Error()  — "scoped listing incomplete: N zone failure(s); zone <id>: <cause>…"
  .Is(t)    — t == errIncompleteListing 이면 true
  .Unwrap() — []error (저장 슬라이스를 그대로 반환 — 호출당 할당 없음; Go 1.20+ 다중 unwrap, errors.Is/As 트리 검사용)
```

- `SweepFunc` 시그니처 `func(ctx, *AccountSweeper) ([]DriftItem, error)`는 **변경하지 않는다**. 부분 안전 items는 반환값이 아니라 typed 오류와 함께하는 계약으로 표현한다.
- 명시적 partial-safe 계약: `*scopedListingError`와 함께 반환된 items만 "안전"으로 간주한다. 다른 어떤 오류·센티넬과 함께 반환된 items는 유출로 간주해 폐기한다.
- `kind` 필드는 두지 않는다 — 로깅 경로가 이미 `target.Kind`를 제공하므로 중복이다(구현 단계 합의로 §5.1 초기안에서 제거).

### 5.2 `sweepDNSRecords`의 zone 격리

- zone별 `ListDNSRecordsByComment` 실패 분류는 **허용 목록(allowlist)** 방식이다. 격리되는 것은 정확히 403, 404, ≥500, 그리고 `flarecloudflare.StatusCode`가 HTTP status를 반환하지 못하는 전송 오류뿐이다. 그 외 모든 오류는 기존 terminal 경로를 유지한다.
  - **격리·계속**: HTTP 403, 404, zone-local 5xx, 전송 오류(페이지네이션 도중 실패 포함 — 어댑터가 `(nil, err)`를 반환하므로 부분 페이지는 sweeper에 도달하지 않는다) → `failures`에 `{zoneID, 원인}` 추가, `listedZones[zone.ID]` 미설정, 해당 zone의 수집 레코드 전체 폐기, 다음 zone 계속.
  - **즉시 중단(terminal)**: `context.Canceled`/`DeadlineExceeded`, `IsRateLimited`(429), HTTP 401(보수적 중단), 그리고 열거되지 않은 4xx(400/405/409/422 등) → `(nil, err)` 반환, 이후 zone 호출 없음. 요청 형태 결함(400/422)이나 충돌(409)은 모든 zone에서 동일하게 재발하므로 zone-local 격리가 아니라 `result=error`로 표면화한다. context 계열 오류는 절대 `scopedListingError`에 흡수되지 않는다 — 집계에 ctx 오류가 섞이면 `RunTargetOnce`의 최우선 `errors.Is(err, context.Canceled)` 분기가 안전 items까지 shutdown으로 폐기한다.
  - **페이싱 실패**: `wait(ctx)`(rate limiter 대기)의 실패는 zone-scoped가 아니라 전역이다. 베어 오류로 terminal 반환하며 scoped 경로에 합류하지 않는다. 어댑터 미들웨어가 반환하는 페이싱 실패도 zone 경계에서 동일하게 terminal이다: `flarecloudflare.ErrRateLimitWait` 센티넬(`internal/cloudflare/client.go`)이 `limiter.Wait` 실패를 `fmt.Errorf("%w: %w", ErrRateLimitWait, err)`로 표시하고(렌더링 문자열과 원인 매칭은 기존과 바이트 동일), zone 분류기는 context 가드와 같은 조기 가드에서 이를 먼저 거부한다 — 원인이 context 센티넬도 HTTP status도 갖지 않으므로 no-status 전송 분기에 도달하면 scoped로 흡수된다. 단, 계정 수준 `ListZones` 내부의 페이싱 실패는 기존 `listFailure` 의미론(전송 오류 → generic partial)을 그대로 따른다 — 어느 쪽이든 pass는 중단되므로 관측 결과는 동일하다.
- **전 zone 실패**: `([]DriftItem{}, scopedListingError)` → `result=partial` + 비nil 집계 오류 + `last-success` stale + findings 0. 이는 단일 zone 계정의 기존 `result=error` 라벨을 partial로 바꾸는 **의도된 라벨 변경**이다 — 조용한 성공이 아니라 "목록 미완성"의 정직한 분류이며, 집계 오류가 어느 zone이 왜 실패했는지 보존한다(§7 C1 기각 사유).
- 계정 전체 인벤토리(`ListZones`)와 checkpoint 기반 cleanup 자격은 유지한다. checkpoint-only 열거로 축소하지 않는다.
- `listedZones` fail-closed 격리는 기존 의미 그대로: 목록이 완료되지 않은 zone의 checkpoint는 missing 판정에서 제외. `claimed` 맵도 계정 전체로 유지 — 성공 zone으로 좁히면 실패 zoneID를 가진 checkpoint가 claim한 레코드가 false orphan이 된다.
- `listFailure`는 바이트 동일하게 유지한다(다른 6개 target 파일과 `ListZones`의 회귀 방어). zone 분류기는 새 함수이며 자체 테이블 테스트를 `TestListFailureClassification` 옆에 둔다.
### 5.3 `RunTargetOnce` 분기 순서

1. `errors.Is(err, context.Canceled)` → `(nil, "", err)` (기존).
2. `errors.As(err, &scoped)` → `ObserveSweep(partial)`, **`(items, partial, scoped)`** — 안전 items와 집계 진단 보존.
3. `errors.Is(err, errIncompleteListing)` → `ObserveSweep(partial)`, `(nil, partial, nil)` — generic 계약 불변 `[C-2]`.
4. `err != nil` → `ObserveSweep(error)`, `(nil, error, err)` (기존).
5. `items == nil` → `ObserveSweep(partial)`, `(nil, partial, nil)` (기존).
6. 성공 → `ObserveSweep(ok)` + `SetSweepLastSuccess` (기존). **partial에서는 절대 갱신하지 않는다.**

분기 2가 분기 3보다 먼저 오는 순서는 본질적이다: `scopedListingError.Is`가 `errIncompleteListing`에 매치하므로(§5.1), 순서가 뒤집히면 scoped 오류가 generic 분기에 흡수돼 `(nil, partial, nil)`을 조용히 반환하고 안전 items가 소실된다. QA-02/QA-03의 item 수 단언이 이 회귀를 잡는다.

### 5.4 `runTarget` 분기 순서

1. `context.Canceled` → 조용한 종료 (기존).
2. `result == partial` → `err != nil`이면 집계 진단을 **Info** 레벨로 로깅(`"target sweep partial: scoped listing incomplete (fail-closed for unlisted scopes)"`, `error: err.Error()`), `err == nil`이면 기존 안내 로그. 이후 `handleDriftResults(ctx, items)` — scoped partial의 안전 items는 invalidator latch와 wakeup event로 정상 디스패치, generic partial의 nil items는 즉시 no-op. **Info 고정은 설계 결정이다**: 지속적으로 403을 반환하는 zone은 DNSRecord TTL마다 비nil 집계를 영구히 생성하므로, 올바르게 억제된 상태를 Error로 라우팅하면 영구적 오류 노이즈와 그 위의 알림을 오염시킨다.
3. `err != nil` → 기존 오류 로깅.
4. 기본 → `handleDriftResults` (기존).

### 5.5 계정 수준 실패의 기존 계약 보존

- `as.zones(ctx)`(`ListZones`) 실패는 기존 `listFailure` 의미론 그대로: 5xx/전송 → generic `errIncompleteListing`(partial), 4xx → error 전파(`account_sweeper.go:321`). 로컬 읽기(`client.List`, `clusterID`)는 `listFailure`를 거치지 않는다 — `targets_dns.go:91-93`은 `fmt.Errorf("list CloudflareTunnels: %w")`로 베어 래핑하고 `clusterID`(`account_sweeper.go:338-340`)는 kube 오류를 그대로 반환하므로, kube API 5xx를 포함해 **항상 `result=error`**이며 partial 경로가 없다. 이 비대칭을 "수정"하지 않는다.
- 401은 "토큰이 전역적으로 무효"라는 증명이 아니라 **인증 불확실성에 대한 보수적 pass 중단 정책**으로 표기한다 `[C]`.

---

## 6. 대안 검토와 기각 사유

| 대안 | 판정 | 사유 |
|---|---|---|
| A. 열거를 checkpoint가 있는 zone으로만 제한 | 기각 | 계정 전체 orphan 발견과 grant 취소 zone의 checkpoint-owned cleanup 의무 추적이 소실된다. issue가 요구한 "account-wide orphan-discovery와 cleanup obligations 보존"에 위배. 범위 축소는 동등한 수정이 아니다 |
| B. generic debounce/재시도 또는 넓은 generation predicate | 기각 | issue가 명시적으로 금지. 실패를 분류하지 않고 흐리며, per-zone 판정 격리를 제공하지 않는다 |
| C. 자격증명을 전 zone으로 확대 | 기각 | 보안 회귀. 최소 권한 토큰이 정당한 배포 형태이며, 읽기 전용 DNS 열거가 provisioning 인가를 침범한다는 주장도 하지 않는다 |
| D. Access 스위퍼 동일 리팩터링 | 범위 외 | 같은 per-scope abort 형태가 Access 스위퍼에도 존재하나, 공유 헬퍼 적용 여부는 별도 결정 사항. 이번 변경은 DNS target에 한정 |
| E. 공개 API/map 확장으로 부분 결과 표현 | 기각 | `SweepFunc` 시그니처 유지 + 비공개 typed 오류로 충분. 공개 표면 확장 불필요 |
| **채택: typed scoped partial(§5)** | 채택 | zone 격리 + 안전 items 보존 + 진단 보존 + fail-closed 유지를 최소 표면 변경으로 달성 |

---

## 7. 토론 정정 기록 `[C]`

합의 과정에서 초기안이 다음 지점들에서 정정됐다(T-1..T-5는 조사 단계 토론, C1..C17은 독립 QA 리뷰의 코드 근거 이의와 그 처분). 최종 계약은 §5다.

| # | 초기안 | 정정 | 사유 |
|---|---|---|---|
| T-1 | zone 실패를 베어 `errIncompleteListing` 센티널로 반환 | `scopedListingError`가 zoneID+래핑 원인을 발견 순서대로 집계 | 베어 센티널은 어느 zone이 왜 실패했는지 진단 정보를 버린다. 운영자가 stale `last-success`의 원인을 로그에서 특정할 수 없다 |
| T-2 | partial이면 items를 그대로 반환하는 계약을 모든 target에 허용 | 안전 items 반환은 `*scopedListingError` 경유만 허용. generic `errIncompleteListing`/`(nil,nil)`은 nil-items 유지 | 단일-scope target이 미검증 부분 목록을 유출하면 false missing 위험. generic 경로의 unsafe partial leakage 차단 |
| T-3 | HTTP 429도 zone-local 실패로 격리 후 계속 | 429는 즉시 pass 중단, 이후 zone 호출 0 | 429는 계정/클라이언트 수준 스로틀링 신호. 계속 호출하면 스로틀링을 악화시킨다 |
| T-4 | 모든 zone 실패 시 빈 items+nil error로 ok 처리 가능 | 전부 실패해도 `scopedListingError` 집계로 partial 반환 | 전면 실패를 조용한 성공으로 기록하면 `last-success`가 진행해 degraded sweep이 숨겨진다 |
| T-5 | HTTP 401을 "전역 인증 무효"로 표기 | "인증 불확실성에 대한 보수적 중단 정책"으로 표기 | 401은 토큰 전역 무효의 증명이 아니다 |

QA 비평가 이의 처분(전부 코드 근거로 심사, 최종 확정):

| # | 이의 | 처분 |
|---|---|---|
| C1 | 전 zone 실패를 `result=error` terminal로 유지해야 단일 zone 계정의 error 신호를 보존 | **기각** — `docs/operations/freshness-and-drift.md`가 degraded sweep의 운영 신호를 "stale `last-success` + rising `partial`"로 문서화하며 `result=error`에 걸린 경보는 없다. error→partial은 의도된 라벨 변경으로 §5.2에 명시 |
| C2 | 격리는 allowlist여야 함(403/404/≥500/전송만). 나머지 4xx terminal | **채택** — §5.2, QA-11(c) |
| C3 | `listFailure` 바이트 동일 유지, zone 분류기는 신규 함수+신규 테이블 테스트 | **채택** — §5.2, §8 |
| C4 | 집계 오류가 context 오류를 흡수하면 안 됨(최우선 분기가 안전 items를 shutdown 폐기) | **채택** — §5.2, QA-10(a) |
| C5 | `DeadlineExceeded`는 기존 비대칭으로 `result=error`에 도달 — partial로 "수정" 금지 | **채택** — QA-10(b), 기존 동작으로 명시 |
| C6 | `wait(ctx)` 페이싱 실패는 전역 terminal, scoped 경로 비합류 | **채택** — §5.2, QA-10(c) |
| C7 | cfstub 재시도 가능 결함(429/5xx)은 `Times:-1` 필요 — `Times:1`은 SDK 재시도에 소비돼 단언이 공허해짐 | **채택** — §9 하네스 규칙 |
| C8 | mid-pagination 케이스 불가 주장 → **번복**: 전용 httptest 프록시로 page=2만 500 처리 가능, 레코드 1개면 SDK가 terminator page=2 요청을 보냄 | **채택(번복 후)** — QA-07 |
| C9 | 로그 문자열 단언 금지 — `*scopedListingError` 구조 단언으로 대체 | **채택** — §9 단언 규칙 |
| C10 | 프로메테우스 델타 단언 금지(`t.Parallel` 오염) — 반환 result 문자열로 대체 | **조건부 채택** — 메트릭 읽기는 지명된 직렬 케이스 QA-09(b)·QA-18(a)만 허용, 나머지는 result 문자열 |
| C11 | `listedZones` false-positive 방어 케이스 — 거부 zone checkpoint가 missing으로 새지 않음을 명시 | **채택** — QA-04 강화 |
| C12 | `claimed` 계정 전체 유지 — 좁히면 false orphan | **채택** — §5.2, QA-08(c) |
| C13 | 계약 문서 3개소 동시 수정 필요 | **채택+확장** — 4개소(§8): `account_sweeper.go`, `types.go`, `doc.go`, `freshness-and-drift.md` |
| C14 | `runTarget` 디스패치는 분기 순서가 아니라 실제 dispatch로 단언 | **채택** — QA-02/03/08 W 단언 |
| C15 | cfstub 케이스는 두 리미터(sweeper 자체 + 팩토리 per-account) 모두 해제 필요 | **채택** — §9 하네스 규칙 |
| C16 | partial 분기 로그는 Info — 지속 403이 영구 Error 노이즈가 되는 것 방지 | **채택** — §5.4 |
| C17 | 건강 zone orphan이 partial pass에서도 정상 탐지됨을 증명하는 양성 케이스 | **채택** — QA-08(a) |
---

## 8. 구현 대상 파일 (구현 완료)

| 파일 | 변경 내용 |
|---|---|
| `internal/sweep/targets_dns.go` | per-zone 루프의 allowlist 오류 격리(403/404/≥500/전송), terminal 중단(ctx/429/401/기타 4xx/페이싱 — `ErrRateLimitWait` 포함), `scopedListingError` 집계, `listedZones`·`claimed` fail-closed 유지. 신규 zone 분류기 함수 — `listFailure`는 바이트 동일 유지 |
| `internal/cloudflare/client.go` | `ErrRateLimitWait` 센티넬 export + `rateLimitMiddleware`가 `fmt.Errorf("%w: %w", ErrRateLimitWait, err)`로 래핑(렌더링 문자열·원인 매칭 바이트 동일). 사용자 승인 범위 확장 — 리미터 값·재시도·자격증명·provisioning 동작 변경 없음 |
| `internal/sweep/account_sweeper.go` | 비공개 `zoneFailure`/`scopedListingError` 타입, `RunTargetOnce`의 typed-partial 우선 평가, `runTarget`의 partial-우선 디스패치와 Info 집계 로깅. `RunTargetOnce` doc 주석(210-213)의 "partial은 nil items/nil error" 문구를 scoped 예외 포함으로 수정 |
| `internal/sweep/types.go` | `TargetDescriptor.SweepFunc` 결과 계약 주석(84-91)에 scoped partial(안전 items) 조항 추가 |
| `internal/sweep/doc.go` | 패키지 계약 산문(47-55)의 "partial pass는 어떤 객체도 invalidate하지 않는다"를 **DNS-only 예외**로 수정 — 다른 6개 target은 변경되지 않았음을 명시 |
| `docs/operations/freshness-and-drift.md` | "부분 목록이면 그 pass를 전부 폐기한다"를 DNS scoped partial 예외로 수정(적용 완료 — 메트릭 표 설명은 변경 없이 정확) |
| `internal/sweep/dns_sweep_test.go` | 신규. issue 코멘트의 probe 하네스(zonePermAPI/zonePermFactory/recordingInvalidator/newProbeSweeper)를 표준 하네스로 채택하고 §9 QA-01..18 zone 격리 케이스를 수록 |
| `internal/sweep/sweep_test.go` | `TestRunTargetOnceResultMapping` 테이블에 scoped 행 추가, zone 분류기 테이블 테스트를 `TestListFailureClassification` 옆에 신규 작성(기존 테스트 불변) |

비대상: `internal/sweep/targets_access.go` 및 다른 5개 target 파일(범위 외 — 계정 전체 중단 동작 유지), `test/cfstub` 공유 코드(QA-07은 테스트 전용 httptest 프록시로 해결), CRD/`config/`, provisioning 경로, 공개 API.
---

## 9. QA 매트릭스 — 18건

계층(tier) 표기: **U** = `RunTargetOnce` 단위 계약(반환값·API 호출 저널), **W** = `runTarget` 워커 디스패치(invalidator 호출·events 채널), **M** = 관측성(result 라벨·`last-success` 진행 여부).

하네스 표기: **probe** = issue 코멘트의 실행 검증된 하네스(`zonePermAPI`가 `flarecloudflare.API`를 임베드하고 per-zone `dnsReadable` 맵 + 순서 보존 호출 슬라이스를 제공, `zonePermFactory`가 `ClientFactory` 구현, `recordingInvalidator`, `newProbeSweeper`가 fake kube client + 버퍼드 events 채널 배선, `dnsTarget()`이 `freshness.GradeForKind("DNSRecord")`로 구성). 실제 어댑터와 동일한 래핑 403 형태(`fmt.Errorf("list Cloudflare DNS records by comment: %w", &cloudflaresdk.Error{StatusCode: 403})`)를 만들어 `flarecloudflare.StatusCode`가 동일하게 분류하며, `RateLimit/RateBurst = 1e6`로 페이싱을 사실상 해제한다. **cfstub** = HTTP stub + `ClientFactory`. **stub** = `SweepFunc` 스텁으로 `runTarget`/`RunTargetOnce`를 in-package 구동.

결과 표기: **PASS** = 구현 후 실행 완료. 로컬 구현·QA는 완료했으며, 최종 PR/CI 및 생성물 게이트는 별도로 추적한다.

### 하네스 규칙

1. **표준 하네스는 probe**다(C18). cfstub은 실제 페이지네이터가 핵심인 QA-07에만 사용한다.
2. **재시도 가능 결함(429/5xx)은 `Times:-1`**(C7): `Times:1`은 SDK의 `WithMaxRetries(3)` 재시도에 소비돼 호출이 성공하고 단언이 공허해진다. cfstub 케이스의 정본 결함은 재시도·백오프가 없는 403이다.
3. **두 리미터를 모두 해제**(C15): `AccountSweeperOptions.RateLimit/RateBurst`와 `NewFactory`의 `cloudflare.WithLimiter(rate.NewLimiter(rate.Inf, 1))`. `DefaultFactory`는 `SweepClient`를 구현하지 않으므로 `remote()`가 limiter 경로를 타고 모든 원격 호출이 0.5 req/s로 페이싱된다. zone listing은 terminator page 요청을 포함해 zone당 2 HTTP 요청이다. `WithLimiter`가 `Client()`의 per-account limiter를 실제로 이기는지 하네스 작성 시 확인하고, 이기지 못하면 다른 훅이 필요하다.
4. **QA-07 전용 프록시**(C8 번복): cfstub은 `r.URL.Path`만 매칭해 page=2만 겨냥한 결함 주입이 불가하다. 테스트 소유 `httptest.NewServer`를 cfstub 앞에 세워 `r.URL.Query().Get("page")=="2"` 요청에만 영구 500을 반환하고 나머지는 프록시한다 — 공유 cfstub 변경 없음. 레코드 1개면 충분하다: SDK의 `V4PagePaginationArray.GetNextPage`는 비어있지 않은 page 1 뒤에 항상 terminator page=2를 요청한다(`test/cfstub/sdk_test.go:193-215`가 저널 2회 호출을 고정).

### 단언 규칙

1. **로그 문자열 단언 금지**(C9). 집계 진단은 구조적으로 단언한다: `errors.As(err, &scoped)`로 `*scopedListingError` 획득 → `failures`의 각 요소를 `errors.As`로 `*zoneFailure`로 풀어 `zoneID` 비교, `errors.Is(scoped, 주입 원인)`(다중 unwrap으로 각 `zoneFailure`의 원인까지 도달), zone 실패 순서 비교.
2. **프로메테우스 델타 단언 금지**(C10) — `ObserveSweep`/`SetSweepLastSuccess`는 프로세스 전역 `observability.Default`에 쓰고 스윕 테스트는 `t.Parallel()`을 사용해 교차 오염된다. 반환된 result 문자열이 메트릭 라벨과 1:1이므로 그것으로 대체한다. `last-success` stale은 카운터를 읽지 않고 코드 경로로 추론한다: `SetSweepLastSuccess`는 ok 경로에서만 호출되므로(`account_sweeper.go:231-234`) partial 반환은 곧 stale이다. **예외**: 지명된 직렬 케이스 QA-09(b)와 QA-18(a)만 메트릭 카운터/타임스탬프를 실측하며 `t.Parallel()`을 쓰지 않는다.
3. **디스패치는 실제 호출로 단언**(C14): recording `Invalidator`와 버퍼드 events 채널로 `Invalidate` 호출 수와 `GenericEvent` 배출 수를 센다. 분기 순서 존재만으로는 부족하다.

| ID | 하위 사례 | 준비(setup) | 관측 단언 | 계층 | 하네스 | 결과 |
|---|---|---|---|---|---|---|
| QA-01 | a) 단일 zone 건강 | zone 1개 200, checkpoint 레코드가 원격에 없음 | `DriftCaseMissing` 1건, invalidation 1, wakeup event 1, `result=ok`, 비nil items — ok 경로만이 `SetSweepLastSuccess`에 도달(AC6 회귀 감시) | U+W+M | probe | **PASS** — 실행 완료 |
| QA-01 | b) 다중 zone 전부 건강 | zone 2개 200, 동일 checkpoint | 동일 단언 + 저널에 두 zone 모두 질의 | U+W+M | probe | **PASS** — 실행 완료 |
| QA-02 | denied-first | zone A(첫 번째) 403, zone B 200 + missing checkpoint | **삼중 단언**: 저널에 A·B 모두 질의(순서 보존 호출 수 = zone 수), B의 `DriftCaseMissing` 정확히 1건 + invalidation 1 + event 1, `result=partial` + 비nil 집계가 A의 zoneID와 원인을 구조적으로 포함 | U+W+M | probe | **PASS** — 변경 전 FAIL, 변경 후 PASS |
| QA-03 | denied-last | zone A 200 + missing checkpoint, zone B(마지막) 403 | QA-02와 동일 삼중 단언(순서 불변). 결함 버전에서는 A가 질의되고도 findings가 폐기되므로 "질의됨"만으로는 불충분 — items·dispatch까지 단언 | U+W+M | probe | **PASS** — 변경 전 FAIL, 변경 후 PASS |
| QA-04 | 거부 zone 내 checkpoint | zone B 403, checkpoint의 ZoneID=B이고 레코드는 모든 읽기 가능 zone에 부재 | 해당 checkpoint에 대한 items 0, invalidation 0, event 0, `result=partial`, checkpoint status 보존. `listedZones` 방어가 없으면 false missing이 freshness gate를 닫고 reconciler를 깨운다(영향: 허위 drift·reconcile churn — reconciler의 T0 재읽기가 레코드 재생성을 막음) | U+W+M | probe | **PASS** — 실행 완료 |
| QA-05 | 무관 zone 404 | zone A 404, zone B 200이나 레코드 내용 변경됨 | B의 `DriftCaseMismatch` 1건, invalidation 1, event 1, `result=partial` | U+W+M | probe | **PASS** — 실행 완료 |
| QA-06 | a) 한 zone 5xx | zone A 500, zone B 200 + missing | B의 missing 1건 정상 디스패치, `result=partial`, `last-success` stale(경로 추론) | U+W+M | probe | **PASS** — 실행 완료 |
| QA-06 | b) 한 zone 전송 오류 | zone A 연결/전송 실패(`StatusCode` 미반환), zone B 200 + missing | a)와 동일 단언 | U+W+M | probe | **PASS** — 실행 완료 |
| QA-07 | 페이지네이션 중간 실패 | zone A 레코드 1건 + page=2 영구 500(전용 httptest 프록시), zone B 200 + missing | HTTP 저널이 A의 page 1 성공과 page 2 실패를 보이고, zone A에 대한 **모든 case의 findings가 0**(missing·mismatch·orphan 전부 — 어댑터가 `pager.Err()`로 `(nil, err)`를 반환해 부분 페이지가 sweeper에 도달하지 않음, `internal/cloudflare/dns.go:116-122`), B의 missing 1건, `result=partial` | U+W+M | cfstub+프록시 | **PASS** — 실행 완료 |
| QA-08 | a) 건강 zone orphan(양성) | zone B 403, zone A에 checkpoint 없는 레코드가 live tunnel CNAME + 유효 소유권 마커 | `DriftCaseOrphan` 정확히 1건이 안전 items에 포함, `runTarget`은 orphan에 대해 **아무것도 디스패치하지 않음**: invalidation 0, event 0, 원격 쓰기 0 — 격리가 "findings 감소"가 아님을 증명하는 양성 케이스 | U+W+M | probe | **PASS** — 실행 완료 |
| QA-08 | b) orphan 비후보 | 동일하나 마커 없음 또는 CNAME target 불일치 | orphan item 0 — strict ownership 미충족은 후보가 아님 | U | probe | **PASS** — 실행 완료 |
| QA-08 | c) `claimed` 계정 전체 | 건강 zone A의 레코드가 ZoneID=B(실패)인 checkpoint에 claim됨 | missing도 orphan도 아님 — items 0. `claimed`를 성공 zone으로 좁히면 false orphan 발생 | U | probe | **PASS** — 실행 완료 |
| QA-09 | a) 복수 zone 거부 + 일부 건강 | zone A·C 403, zone B 200 + missing | B의 findings 정상, 집계에서 A·C 두 zoneID를 **결정적 순서**로 복구 가능하고 각각 자기 원인을 래핑(구조 단언), `result=partial` | U+W+M | probe | **PASS** — 실행 완료 |
| QA-09 | b) 전 zone 거부 | 모든 zone 403 | items 0, invalidation 0, event 0, `result=partial`(ok 아님 — 의도된 error→partial 라벨 변경), `last-success` stale, 집계에 전 zone 나열. **직렬 테스트에서만** `flareway_sweep_total{result="partial"}` 카운터와 `last-success` 타임스탬프를 실측 | U+W+M | probe(직렬) | **PASS** — 실행 완료 |
| QA-10 | a) context 취소 | zone 2/3 진행 중 ctx cancel(페이싱 해제로 결정적) | `errors.As(err,&scoped)==false`, `errors.Is(err,context.Canceled)==true`, items nil, result `""`(빈 문자열 — partial 아님), 저널에 정확히 2회 `ListDNSRecordsByComment`, invalidation 0, event 0, 메트릭 없음 | U+W | probe | **PASS** — 실행 완료 |
| QA-10 | b) deadline 초과 | 동일하나 `DeadlineExceeded` | `result=error` — `DeadlineExceeded`는 `Canceled`와 비대칭으로 generic error 분기에 도달하는 **기존 동작**. partial로 "수정"하지 않는다 | U | probe | **PASS** — 실행 완료 |
| QA-10 | c) 페이싱 `wait(ctx)` 실패 | 실제 리미터 유지(하네스 규칙 3의 페이싱 해제에서 **제외**), 리미터가 토큰을 승인하기 전에 만료되는 짧은 deadline의 context | x/time v0.16.0의 베어 wait 오류는 래핑되지 않으므로 `errors.Is`/`errors.As`가 모두 false, `result=error`, findings 0. burst 초과 오류는 이 설정에서 도달 불가 | U | probe(페이싱 유지) | **PASS** — 실행 완료 |
| QA-10 | d) 실제 미들웨어 페이싱 오류 | 실제 cloudflare-go 클라이언트(`WithLimiter` rate=1e-9/burst=1 소진, `WithRequestOptions(MaxRetries(0))`) + 50ms context로 네트워크 없이 어댑터의 실제 페이싱 오류를 획득해 후속 zone의 API 경계에 주입 | `errors.Is(err, ErrRateLimitWait)==true`, `errors.Is(err, context.Canceled/DeadlineExceeded)==false`, HTTP status 없음, `errors.As(err,&scoped)==false`, `result=error`, items nil, 후속 zone 호출 0, invalidation 0, event 0; 취소된 context의 페이싱 오류는 `context.Canceled`가 여전히 검출 가능. **명시적으로 지원되는 커스텀 설정(WithLimiter+MaxRetries(0)) 엣지 — 기본 스윕 루프(deadline 없음)에서 관측된 인시던트가 아니다** | U+W | probe+실제 어댑터 | **PASS** — 변경 전 FAIL, 변경 후 PASS |
| QA-11 | a) HTTP 401 | zone A 401 | pass 즉시 중단, 이후 zone 호출 0, `result=error`, findings 0. 보수적 중단 정책(전역 인증 무효 주장 아님) | U+W+M | probe | **PASS** — 실행 완료 |
| QA-11 | b) HTTP 429 | zone A 429 | 동일 단언 — 계정 수준 스로틀링이므로 계속 호출 금지 | U+W+M | probe | **PASS** — 실행 완료 |
| QA-11 | c) 체계적 기타 4xx | zone A 400(또는 422) | terminal `result=error`, 이후 zone 호출 0 — allowlist 외 4xx는 격리되지 않고 영구 partial이 되지 않음 | U+M | probe | **PASS** — 실행 완료 |
| QA-12 | a) `ListZones` 5xx/전송 | 계정 zone 목록 실패 | generic `errIncompleteListing` → `(nil, partial, nil)`, DNS 레코드 호출 0, 기존 계약 보존 | U+M | probe | **PASS** — 실행 완료 |
| QA-12 | b) `ListZones` 4xx | 계정 zone 목록 401/403 | `result=error`, DNS 레코드 호출 0 | U+M | probe | **PASS** — 실행 완료 |
| QA-12 | c) 로컬 읽기 실패 | `client.List(CloudflareTunnelList)` 또는 `clusterID` 읽기 실패 | 오류 전파, `result=error`, 기존 동작 불변 | U | probe | **PASS** — 실행 완료 |
| QA-13 | generic target unsafe items | 단일-scope target(예: `sweepCloudflareTunnels`)이 generic `errIncompleteListing`과 items를 함께 반환 | `(nil, partial, nil)` — items 폐기, dispatch 0, invalidation 0. typed scoped 오류만 items를 운반 가능 | U+W | stub | **PASS** — 실행 완료 |
| QA-14 | grant 취소 metamorphic — 읽기 가능 | 동일 checkpoint fixture를 고정하고 계정 grant 상태만 허용→취소로 변경, provider는 zone 읽기 허용, 레코드 변조 | **출력 불변성 단언**: grant 전이 전후로 `DriftCaseMismatch` 1건, invalidation 1, event 1이 동일 — 스윕은 grant 상태를 참조하지 않으므로 checkpoint cleanup 자격이 구조적으로 보존됨을 증명. 스윕의 grant 인지나 컨트롤러 cleanup 실행은 주장하지 않는다 | U+W+M | probe | **PASS** — 실행 완료 |
| QA-15 | grant 취소 metamorphic — provider 거부 | 동일 checkpoint fixture, grant 허용→취소 + 해당 zone 403 | **출력 불변성 단언**: 전이 전후로 items 0, invalidation 0, event 0, `result=partial` 동일. `status.dnsRecords` 엔트리가 바이트 동일하게 보존 — fake client가 Update/Patch/Delete 시 테스트 실패로 스윕 무쓰기를 입증(AC5) | U+W+M | probe | **PASS** — 실행 완료 |
| QA-16 | a) `ObserveOnly` tunnel | ObserveOnly tunnel의 checkpoint가 있는 zone 건강 | 판정 제외 — items 0(정책상 비교 자체를 생략) | U | probe | **PASS** — 실행 완료 |
| QA-16 | b) 삭제 중 tunnel | deletionTimestamp 설정 tunnel | 동일 — items 0 | U | probe | **PASS** — 실행 완료 |
| QA-16 | c) 타 계정 tunnel | `accountRef`가 다른 tunnel의 checkpoint | 동일 — 어떤 zone 상태에서도 items 0 | U | probe | **PASS** — 실행 완료 |
| QA-17 | a) checkpoint zone 부재 | checkpoint의 zoneID가 `ListZones` 인벤토리에 없음 | false missing 0, 해당 checkpoint 판정 skip, 나머지 zone 정상 | U+W | probe | **PASS** — 실행 완료 |
| QA-17 | b) zones = 0 | `ListZones`가 빈 목록 반환 | 완전한 빈 listing — 비nil 빈 items, `result=ok`, `last-success` 갱신(기존 계약) | U+M | probe | **PASS** — 실행 완료 |
| QA-18 | a) partial→complete 회복 | partial pass 다음 pass 전 zone 건강 | `result=ok` 복귀, findings 정상 디스패치, **직렬 테스트에서 `last-success` 타임스탬프 진행을 실측**(단언 규칙 2의 지명 예외) | U+W+M | probe(직렬) | **PASS** — 실행 완료 |
| QA-18 | b) event 버퍼 포화 | events 채널 가득한 상태에서 drift 감지 | event는 drop되나 invalidator latch는 닫힘 유지(무효화 소실 아님), drift 지속 시 다음 pass 재발송 | W | stub | **PASS** — 실행 완료 |
누락 없는 하위 사례 집계: QA-01(2), QA-06(2), QA-08(3), QA-09(2), QA-10(4), QA-11(3), QA-12(3), QA-16(3), QA-17(2), QA-18(2) — 명시된 모든 부사례는 표에 개별 행으로 열거했다.

### 영구 회귀 테스트 매핑

- **QA-02·QA-03**: issue 재현기의 AC 정렬 영구 테스트 — 변경 전 FAIL, 변경 후 PASS(C23).
- **QA-01**: 건강 대조군 — 수정이 순수 추가적임을 감시.
- **QA-10(b)**: `TestRunTargetOnceResultMapping`의 저비용 테이블 행으로 충분. **QA-10(c)**는 그 테이블에 둘 수 없다 — 스텁 `SweepFunc`는 `wait()`에 도달하지 않으므로 실제 리미터를 쓰는 독립 케이스여야 한다.
- **QA-10(d)**: 실제 SDK 미들웨어가 만든 오류를 probe 경계에 주입하는 독립 케이스 — 스텁 `SweepFunc`는 어댑터 미들웨어에 도달하지 않고, QA-10(c)의 sweeper 리미터 경로와는 다른 페이싱 기원을 고정한다. **QA-18(b)**는 `freshness.Latch` 실구현으로 `IsInvalidated`를 단언한다.
- 18건 전부와 명시된 하위 사례를 실행해 PASS를 확인했다. 원래 함수 본문 overlay는 denied-first/denied-last에서 변경 전 FAIL, 변경 후 PASS였고 healthy single/multi controls는 양쪽에서 PASS였다. 미들웨어 guard-removal overlay도 scoped absorption에서 변경 전 FAIL, 변경 후 PASS였다.

### 이 QA 세트가 커버하지 않는 것

- **다른 6개 target**(`targets_access.go` 포함): 첫 실패 scope에서 계정 전체를 중단하는 기존 동작을 그대로 유지한다. issue가 Access 스위퍼를 명시적으로 범위 외로 지정.
- **라이브 Cloudflare 동작**: 실제 페이지네이션·레이트 리밋·provider 가용성은 stub/fake로 격리된 범위만 검증한다 `[live-blocked]`.
- **403의 정확한 provider 원인**: HTTP status만 분류에 사용되며, 라이브 거부 응답의 Cloudflare 오류 코드는 미검증이다 `[live-blocked]`.

---

## 10. 게이트와 검증 절차

구현과 로컬 QA는 완료했다. 다음 명령으로 로컬 검증을 실행했다:

1. `make lint-fix` — 0 issues.
2. `make test` — 23 packages, controller envtest 포함.
3. `go test -mod=readonly -race -count=3 -json ./internal/sweep ./internal/cloudflare` — 29개 QA root를 3회 실행, 실패 0.

CI와 `make verify-generated`는 최종 PR/체크 결과가 authoritative인 별도 게이트다. 이 문서는 해당 게이트의 성공을 주장하지 않는다.

---

## 11. 비주장(non-claims)

- 라이브 배포 환경에서의 직접 검증을 주장하지 않는다 `[live-blocked]`.
- 라이브 토큰의 정확한 권한 정책·403의 고유 원인을 특정하지 않는다 `[live-blocked]`.
- 구현 및 로컬 QA 완료는 주장하지만, CI·생성물 검증·최종 PR 체크의 성공은 주장하지 않는다.
- 읽기 전용 DNS 열거가 provisioning 인가를 침범한다고 주장하지 않는다.
- QA-10(d)의 페이싱 실패는 명시적으로 지원되는 커스텀 설정(`WithLimiter` + `MaxRetries(0)`)에서 재현되는 엣지다 — 기본 스윕 루프(deadline 없음)에서 관측된 인시던트라고 주장하지 않는다.
- 다른 6개 target(Access 스위퍼 포함)의 동일 계정 전체 중단 동작 수정은 이 변경의 범위가 아니다.
