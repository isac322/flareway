# ServiceToken create-before-capture 복구 — QA/설계 문서 (Issue #94)

- 작성일: 2026-09-22 (구현 반영 갱신: 2026-09-23)
- 상태: 구현 완료. §5의 ST-QA-01~46 모두 `internal/controller`의 실제 테스트 함수에 매핑되어 있으며, targeted `TestServiceToken*` suite는 fake API 기준으로 통과했다(`go test -json` exit 0, 77개 passing 이벤트, subtest 포함). 전체 게이트 `make lint-fix`, `make test`, `make test-exploratory-compile`, `make verify-artifacts` 모두 supervised 실행으로 exit 0을 기록했다. verify-generated와 원격 CI는 아직 실행되지 않았다.
- 대상 이슈: `isac322/flareway` #94 — `CreateServiceToken` 성공 후 credential Secret 쓰기 실패 시 발급된 원격 토큰 ID가 유실되는 결함.
- 승인된 애플리케이션 범위: `internal/controller/servicetoken_controller.go`, private 헬퍼/상수, 관련 테스트와 문서만. `api/` 및 공유 Cloudflare API 변경 없음. `cmd/` 변경 없음(APIReader는 `SetupWithManager`에서 self-init).

---

## 1. 근본 원인
`ServiceTokenReconciler.Reconcile`은 원격 `CreateServiceToken`을 먼저 호출하고(수정 전 `internal/controller/servicetoken_controller.go:192`), 그 다음에야 일회성 credential을 destination Secret에 쓴다(`:196`, `writeInitialSecret`). 이 두 단계 사이에는 발급된 토큰 ID를 기록하는 내구성 체크포인트가 없었다. 아래 라인 참조는 수정 전 코드 기준이다.

- Secret 쓰기가 transient 오류(예: apiserver 503)로 실패하면 reconcile은 에러를 반환하고, `status.tokenId`는 비어 있으며, credential Secret도 존재하지 않는다.
- 기존 복구 경로 `recoverTokenID`(`:513-526`)는 Secret의 `flareway.bhyoo.com/service-token-id` annotation만 읽으므로, Secret 자체가 없는 pre-Secret 실패 창을 커버하지 못한다(커버하는 것은 post-Secret/pre-status 창뿐).
- 재시도는 동일한 ownership-marker 이름으로 `CreateServiceToken`을 다시 호출한다. 첫 번째로 발급된 토큰은 어떤 상태/Secret/journal에도 기록되지 않았으므로 참조 없이 좌초(stranded)된다.
- 삭제 경로 `reconcileDelete`(`:528-551`)는 기록된 `status.tokenId`만 삭제하고, sweeper는 orphan을 metric+log로만 보고하므로, 좌초된 토큰을 회수하는 경로가 존재하지 않는다.

**이 결함은 G6 위반이 아니다.** `Ready=True`가 credential capture 전에 보고된 적은 없다. 문제는 Ready 판정이 아니라, 발급된 원격 ID의 provenance가 capture 전에 내구성 있게 기록되지 않는다는 점이다.

### 1.1 실행된 재현 (Grade B, 저장소 fake)

- `dd322e3`에서 이슈의 fixture를 적용해 실행: 첫 reconcile이 Secret 쓰기 503로 실패한 뒤, 재시도가 `token-2`를 발급하고 `token-1`은 marker 이름을 유지한 채 좌초됨을 관측했다. healthy control(두 번의 정상 reconcile)은 원격 토큰 1개로 통과했다.
- duplicate-name provider 정책 시뮬레이션: accept 분기는 중복 토큰 2개가 남고, reject(409) 분기는 재시도가 실패해 수렴하지 못하며 `token-1`이 남는다. 두 분기 모두 `api.creates == 2`와 동일 create 이름을 관측했다.
- 주의: 409 reject 분기는 테스트 헬퍼가 주입한 시뮬레이션이며 실제 Cloudflare의 duplicate-name 동작 관측이 아니다. Cloudflare 공개 문서는 일회성 secret 반환만 확정하고 duplicate-name 정책은 확정하지 않으므로, 설계는 어느 쪽 정책에도 의존하지 않는다.
- 기준선: 현재 main(`3d75780`, #98 gatewayapi/access 변경만 포함)에서 기존 ServiceToken 테스트는 통과했다. `make test` 로그는 `ok github.com/isac322/flareway/internal/controller 109.713s`로 끝났으나 RPC 타임아웃으로 exit status가 전달되지 않았으므로, 로그상 suite 출력만 확인된 것으로 기록한다. 같은 기준선에 신규 복구 테스트를 scratch로 올려 실행한 결과 `TestServiceTokenCredentialWriteFailureRecoversSameToken`은 결함대로 두 번째 create(`api.creates == 2`)로 FAIL해 재현을 확인했고, `TestServiceTokenHealthyIssueReapsJournalAndStaysIdle`은 PASS했다. 미생성 삭제 케이스(invalid zone/missing account/revoked grant)와 ST-QA-15 subtype(deletionTimestamp 후 finalizer 추가 불가)도 구(old) 런타임 overlay에서는 FAIL, 현재 구현에서는 PASS다. 구현 브랜치에서는 targeted `TestServiceToken*` suite가 `go test -json` exit 0(77개 passing 이벤트, subtest 포함)으로 통과했고, 전체 게이트 4종(`lint-fix`, `test`, `test-exploratory-compile`, `verify-artifacts`)도 모두 exit 0이다.
---

## 2. 검토된 대안과 기각 사유

| 대안 | 판정 | 사유 |
|---|---|---|
| **A. post-create 체크포인트** (원격 생성 직후 `status.tokenId` 등에 ID를 먼저 기록) | 기각 — 불충분 | 체크포인트 쓰기 자체가 실패할 수 있어 창이 닫히지 않는다(생성 성공 → 체크포인트 쓰기 실패 → 동일 좌초). 실패 지점을 한 단계 뒤로 옮길 뿐 제거하지 못한다. |
| **B. 즉시 롤백** (Secret 쓰기 실패 시 같은 reconcile 안에서 `DeleteServiceToken`) | 기각 — crash에 취약 | 롤백은 in-memory 복구다. Secret 쓰기 실패와 롤백 사이에 프로세스가 죽으면 롤백은 실행되지 않고 토큰은 좌초된다. crash를 견디는 복구는 내구성 상태가 선행되어야 한다. |
| **C. 이름 기반 blind adoption** (재시도가 marker 이름으로 `List`/`findByName` 후 첫 매치를 채택) | 기각 — 안전하지 않음 | 이름만으로는 provenance를 증명할 수 없다. 동일 marker를 공유하는 임의의 중복, foreign cluster, cross-scope 토큰을 채택하거나 삭제할 수 있고, 일회성 secret은 어차피 재독출이 불가하다. G2/G3 위반. |
| **D. pre-create journal (채택)** | 채택 | 원격 CREATE **이전에** 의도(intent)를 내구성 journal에 기록한다. crash 후에도 journal이 시도의 provenance를 증명하므로, 재시도는 blind create가 아니라 journal-bound 복구를 수행한다. |

독립 리뷰에서 추가로 기각된 항목: `Accepted`/`Ready` condition API 재설계(기존 condition 관례 유지, `api/` 변경은 승인 범위 밖), HMAC 등 추측적 forgery 방어 기계(근거 없는 과잉), prefix-only 매칭으로의 provenance 약화(안전하지 않음 — prefix는 감지 전용, mutation은 정확한 전체 이름 일치만 허용).

---

## 3. 구현된 설계

이 절의 합의 설계는 코드에 구현됐다(`internal/controller/servicetoken_recovery.go`, `servicetoken_controller.go`). 구현에서 추가된 세부: 원격 이름은 200자 상한으로 specName을 절단한다; `dispatched`+후보 0건과 zone retiring 대기는 `Ready=False, Reason=RecoveryPending`으로 보고하고 30초 후 requeue한다; create 성공 시 발급 ID를 journal의 `issuedID`에 checkpoint하고, 응답 이름 divergence 시 credential을 먼저 Secret에 커밋한 뒤 `Conflict`로 block한다; zone 복구는 retiring 토큰의 ID와 이름을 journal에 기록한다; pending 삭제 정리는 journal의 `issuedID`/`retiringID`와 exact attempt/retiring 이름 일치, 또는 커밋된 credential의 clientID 일치로 provenance를 검증한다; 첫 dispatch 전에 private attempt finalizer를 기록해 미생성 CR의 삭제 차단을 해소한다(§3.5).

### 3.1 Journal과 예약

- **전용 journal Secret**: CR UID에서 결정적으로 파생된 이름(예: `flareway-st-intent-<cr-uid>`)의 controller-owned Secret. 모든 키/상수는 `internal/controller`의 private 상수이며 `api/` 변경은 없다.
- **예약 범위**: destination 예약과 journal 기록은 **managed 신규 생성 분기에만** 적용한다. `AdoptById`, `ObserveOnly`, established(`status.tokenId` 존재) 경로는 journal/reservation을 만들지 않는다.
- **이중 예약**: 원격 CREATE 전에 (a) journal을 기록하고 (b) credential destination Secret을 `Create`로 예약한다. `AlreadyExists`면 캐시가 아닌 authoritative read로 재확인하고 이 CR의 controller 소유임을 검증한 뒤에만 진행한다(충돌 Secret을 adopt하지 않음). 예약 실패 시 원격 mutation은 0건이다(원격 read는 허용).
- **authoritative read**: journal 로드와 credential readback은 informer 캐시가 아니라 `APIReader`로 수행한다. stale cache miss가 rotate/recreate를 정당화하는 일은 없어야 한다. `APIReader`는 `SetupWithManager`에서 self-init하며 `cmd/` 변경은 없다.
- **journal 처리 순서**: journal은 freshness gate보다 먼저, 그리고 scope/zone 재해석보다 먼저 처리한다. 재개 시 zone/account은 journal에 기록된 zone ID와 account 바인딩을 사용한다 — dispatch와 capture 사이의 `spec.zone` 편집이나 zone 검증 flap이 resume을 `Invalid`로 좌초시키지 않는다.

### 3.2 바인딩과 원격 이름

- journal은 불변 identity tuple을 바인딩한다: live CR UID, account CR UID + account ID, resolved zone ID, cluster UID, destination Secret, `spec.name`, 그리고 attempt 고유 **random** nonce.
- 원격 생성 이름은 compact한 결정적 CR UID prefix + nonce를 포함한다(예: `flareway/<clusterUID>/<namespace>/<crUID>/<specName>-<nonce>`). 이 prefix 덕분에 journal이 삭제돼도 scoped list가 이 CR이 시작한 원격 토큰을 감지할 수 있다.
- **이름 일치 규칙**: mutation(rotate/delete/recreate 대상 선정)은 journal nonce를 포함한 **전체 attempt 이름의 정확한 일치**에만 허용한다. prefix 매칭은 미추적 충돌의 감지·block에만 쓰이며 adoption 근거가 되지 않는다. create 응답이 반환한 `Name`이 요청한 attempt 이름과 다르면 loop하지 않고 block한다.
- mutable 필드(`duration`, `enabled`)는 journal 바인딩 대상이 아니며, credential capture 이후 `UpdateServiceToken`으로 정렬하고 canonical name으로 정규화한 뒤에야 `Ready`를 보고한다.

### 3.3 재개(resume) 규칙 — fail-closed

journal은 `prepared`(create 요청 미발송)와 `dispatched`(원격 create 직전에 영속화)를 구분한다. `dispatched`는 원격 create 요청 **이전에** 커밋되어야 한다.

- `prepared` + 원격 후보 0건 → create 발송 허용(이전 create가 없음이 상태로 증명됨). **zero match가 create를 정당화하는 유일한 상태다.**
- `dispatched` + scoped list에서 **정확히 1개**의 검증된 후보(전체 바인딩 + 정확한 attempt 이름 일치) → 복구 진행.
- `dispatched` + 후보 0건 → **미증명**: 원격이 아직 list에 안 잡혔을 수 있다. create/rotate 모두 금지, mutation 없이 block/relist. 부재는 mutation을 정당화하지 않고, 존재만이 바인딩한다. 이 bounded non-convergence는 의도된 fail-closed이며 가짜 자동 복구가 아니다.
- `dispatched` + 후보 2개 이상, 또는 foreign/불일치 바인딩 → mutation 없이 `Conflict`로 block.
- journal 부재 + scoped discovery가 동일 CR의 attempt prefix 또는 canonical legacy 이름 충돌을 감지 → adoption 없이 block.

### 3.4 Credential 복귀와 capture 판정

- **credential-committed predicate**: "credential 있음"은 Secret 존재가 아니라 `CF-Access-Client-Id` + `CF-Access-Client-Secret` 데이터 키와 `flareway.bhyoo.com/service-token-id` annotation이 **모두 비어있지 않게** 존재할 때만 성립한다. 예약만 된 빈 Secret(데이터 0건 + reserved-for marker)이나 부분 credential은 절대 `Ready`가 아니다. 이 predicate는 managed pending capture 경로에만 적용된다 — `AdoptById` 경로는 기존 의미론(비어 있는 Secret은 `SecretMissing`, adoption은 credential을 회전하지 않음)을 유지하며 새로운 비어있음 guard를 추가하지 않는다.
- account scope: 초기 credential 유실 시 지원되는 `RotateServiceToken`으로 복구. rotate 오류 시 account delete fallback은 없다.
- zone scope: zone rotate는 미지원이므로 검증된 `DeleteServiceToken` 후 clean `Create`로만 복구한다. 순서는: (1) retiring 토큰 ID/nonce를 journal에 내구성 있게 기록 → (2) delete 완료를 확인 → (3) 확인 후에만 replacement attempt를 prepare하고 create. 이전 delete가 불확실한 동안 create하지 않는다.
- capture된 credential은 정규화 실패·status patch 실패를 견딘다: 재시도는 readback으로 capture를 인식하고 rotate 없이 후속 단계만 재수행한다.
- journal은 status checkpoint(`status.tokenId` + `Ready` patch) 성공 전까지 유지하고, 그 후에만 삭제(reap)한다. checkpoint 이후에 남은 journal은 reap 대상일 뿐 resume/rotate 근거가 아니다 — established 상태에서 destination이 나중에 삭제돼도 `SecretMissing`을 보고할 뿐 자동 rotate하지 않는다.

### 3.5 삭제와 정책

- pending 상태의 CR 삭제는 `status.tokenId`가 비어 있고 ownership이 미검증이어도 journal을 조회해 미완료 원격 토큰을 정리한다(기존 empty-status skip을 우회). 미해결 dispatch나 원격 삭제 실패 시 finalizer를 유지하고 `CleanupBlocked`를 보고한다 — finalizer를 조용히 버려 원격을 누수시키지 않는다.
- `deletionPolicy: Orphan`이면 원격 토큰을 유지한다.
- `managementPolicy: ObserveOnly`는 원격 mutation뿐 아니라 credential/journal 쓰기도 금지한다(관측만). pending 미해결 journal이 있는 ObserveOnly는 `Ready`가 되지 않고 Secret도 쓰지 않는다.
- established(`status.tokenId` 기록됨) 상태에서 Secret이 사라지면 `SecretMissing`을 보고하고 자동 rotate/recreate하지 않는다(§6.7/§10.3 계약 유지).
- legacy orphan의 자동 adoption은 없다.
- **attempt marker(구현됨)**: private attempt finalizer를 journal 생성·첫 원격 dispatch보다 먼저 내구성 있게 기록한다. marker 부재 + `status.tokenId` 공백 + journal 부재는 "원격 dispatch 없음"을 증명하므로 원격 호출·scope 해석 없이 finalizer를 제거한다(legacy markerless CR도 동일). marker 존재 + journal 부재는 기존 fail-closed(ST-QA-34)를 유지한다. marker는 journal이 존재하는 동안 또는 status checkpoint 전에는 reap하지 않으며, established 토큰 삭제 시 두 finalizer를 모두 제거한다.

---

## 4. 합의 과정 기록

scout hub가 불가해 Main이 제안과 이의를 중계했다. 최종 통합 제약에 대해 TokenFlow, RecoveryOptions, QASurface가 각각 명시적으로 수용했고, 독립 리뷰어(DesignChallenge)가 추가 안전 수정을 제기해 Main이 수용/적응했다. 이것은 설계 합의이지 구현/테스트 증거가 아니다.

| 참여자 | 제기된 이의/쟁점 | 해결 |
|---|---|---|
| TokenFlow | journal이 out-of-band로 삭제되면 heuristic adoption 위험; 동일 이름 중복의 모호성; spec drift; zone scope 복구 | CR UID prefix + nonce를 원격 이름에 포함해 journal 부재 시에도 scoped list로 감지·block; 불변 tuple 바인딩으로 drift 차단; zone은 Delete+Create로 한정 |
| RecoveryOptions | journal tampering 방어; journal 생명주기(조기 삭제 금지); credential write timeout의 in-doubt 상태; scope별 복구 비대칭; teardown | journal을 status checkpoint 성공까지 유지; timeout 시 durable Secret readback 선행; account=Rotate / zone=Delete+Create; teardown이 journal을 조회해 pending 원격 정리, 실패 시 finalizer 유지 |
| QASurface | 22개 케이스 매트릭스와 게이트 정렬; private constants로 `api/` 무변경 확인 | 매트릭스를 본 문서 §5로 확정하고 신규 갭 케이스를 추가 |
| DesignChallenge (독립 리뷰) | ① 캐시 read의 stale miss가 rotate를 정당화할 수 있음 → journal/credential read는 `APIReader` authoritative read, `SetupWithManager` self-init. ② `prepared`/`dispatched` 구분 필요 — `dispatched`+0건은 "없음"이 아니라 "모름". ③ journal을 freshness gate·scope 재해석보다 먼저 처리하고 journal 기록 zone/account로 resume. ④ empty status의 pending delete가 journal을 우회하면 안 됨. ⑤ checkpoint 후 잔여 journal은 reap만. ⑥ credential 판정은 Secret 존재가 아니라 완전한 credential predicate. ⑦ `AlreadyExists` 시 authoritative 재확인 + 소유 검증. ⑧ zone 복구는 retiring ID를 먼저 checkpoint하고 delete 확인 후에만 재생성. ⑨ compact 이름 + 정확한 nonce 일치, 반환 이름 divergence는 block. ⑩ provenance 한계 명시 | §3 전반에 반영; QA 케이스 ST-QA-37~41 추가 및 기존 케이스 assertion 보강. condition API 재설계·HMAC·prefix 매칭 제안은 범위/안전 사유로 기각 |

---

## 5. QA 매트릭스

ST-QA-01~46은 모두 구현됐으며 §5.1의 테스트 함수에 매핑된다. tier는 실행 수준을 나타낸다. controller 패키지 테스트는 envtest 자산이 필요하므로 `KUBEBUILDER_ASSETS` 설정 하의 `go test ./internal/controller/ -run '<Name>' -count=1` 형태이며, fake API만 쓰는 케이스는 동일 패키지의 unit 성격 테스트다. assertion은 소비자 관점(원격 토큰 수, Secret 내용, status condition, finalizer)에서 관측 가능한 것만 기술한다. targeted `TestServiceToken*` suite와 전체 게이트 4종은 모두 통과했다(문서 상단 상태 참조).
| ID | 분류 | 제목 | 자극(stimulus) | assertion | tier |
|---|---|---|---|---|---|
| ST-QA-01 | Core | 예약 실패 시 원격 mutation 0건 | journal/destination 예약 단계의 Secret `Create`에 503 주입 | reconcile 즉시 중단; **원격 mutation 0건**(Create/Rotate/Delete/Update 모두; 원격 read는 허용); 원격 토큰 0개 | unit |
| ST-QA-02 | Core | credential 쓰기 실패 복구(account) | 예약 성공 → 원격 create 성공 → destination Secret `Update` 503 | reconcile 1 실패, `Ready != True`(status가 비어 있다고 단정하지 않음); reconcile 2가 journal을 읽고 `RotateServiceToken`으로 credential capture; 원격 토큰 정확히 1개; `Ready=True` | unit/envtest |
| ST-QA-03 | Core | credential 쓰기 실패 복구(zone) | `spec.zone` 지정 + Secret `Update` 503 | zone rotate 미지원이므로 reconcile 2가 journal 기반으로 retiring ID checkpoint → 검증된 `DeleteServiceToken` → 재생성·capture; 원격 토큰 정확히 1개; `Ready=True` | unit/envtest |
| ST-QA-04 | Resilience | 원격 응답 손실 / 전송 타임아웃 | 원격 create는 커밋됐으나 응답이 유실/타임아웃 | reconcile 2가 journal의 attempt 이름으로 scoped list → **정확한 전체 이름 일치** 1건을 provenance 검증 후 복구(account=rotate, zone=delete+create); credential capture; `Ready=True` | unit |
| ST-QA-05 | Resilience | in-doubt Secret 쓰기 readback | Secret `Update`가 client timeout을 반환했으나 etcd에는 커밋됨 | reconcile 2가 **APIReader authoritative readback**으로 기존 credential+annotation 발견; rotate/create 없이 `Ready=True` 수렴 | unit/envtest |
| ST-QA-06 | Provider | duplicate name 거부(409) | fake가 동일 이름 create에 409 반환 + Secret 쓰기 실패 | reconcile 2가 journal이 가리키는 기존 토큰을 reclaim/rotate; blind create 없이 409 없이 수렴 | unit |
| ST-QA-07 | Provider | duplicate name 허용(account scope) | account-scoped ServiceToken + fake가 중복 이름 허용 + Secret 쓰기 실패 | reconcile 2가 두 번째 토큰을 만들지 않고 journal이 가리키는 기존 토큰을 rotate로 회수; 원격 토큰 합계 정확히 1개; `Ready=True`(zone scope는 reclaim이 합법적으로 replacement를 생성하므로 본 케이스는 account로 한정) | unit |
| ST-QA-08 | Security | 기존 비소유 Secret 충돌 | `spec.secretRef` 위치에 controller ownerReference 없는 Secret 존재(예약 `Create`의 `AlreadyExists` 경로) | authoritative 재확인 + 소유 검증 후 원격 create·journal 쓰기 이전에 중단; 충돌 Secret adopt 없음; 원격 토큰 0개; `Ready=False, Reason=Conflict` | unit/envtest |
| ST-QA-09 | Security | immutable destination Secret | destination Secret이 `immutable: true`이거나 쓰기 거부 | 예약 단계가 쓰기 불가를 감지해 원격 생성 전 실패; 원격 mutation 0건; `Ready=False` | unit/envtest |
| ST-QA-10 | Provenance | 재개 시 모호한 원격 후보 | 재개 시 scoped list가 동일 CR attempt prefix에 매치되는 원격 토큰 2개 이상 반환 | blind adoption/rotation 거부; `Ready=False, Reason=Conflict` fail-closed; credential 쓰기 0건 | unit |
| ST-QA-11 | Provenance | foreign cluster UID marker | 동일 이름이지만 다른 cluster UID를 가진 원격 토큰 존재 | 후보로 간주하지 않고 무시; adopt/rotate/delete하지 않음; 현재 cluster UID로 자체 토큰 경로 진행 | unit |
| ST-QA-12 | Isolation | scope 불일치(account↔zone) | pending journal이 account scope에 바인딩된 상태에서 `spec.zone` 추가(또는 그 반대) | journal 바인딩 drift로 감지; cross-scope adopt/rotate/delete 없이 `Conflict` fail-closed | unit |
| ST-QA-13 | Edge | pending 중 journal 삭제 | 원격 토큰 생성됨 + journal Secret이 out-of-band 삭제 | scoped discovery가 CR UID prefix의 원격을 감지하나 journal 부재 → adoption 없이 `Ready=False, Reason=Conflict` block; 중복 create 0건 | unit |
| ST-QA-14 | Edge | pending 중 `spec.secretRef` 변경 | create intent pending 중 operator가 `spec.secretRef` 수정 | journal 바인딩과 현재 spec 불일치 감지 → `Conflict` fail-closed; 중복 토큰 생성 없음 | unit |
| ST-QA-15 | Edge | pending 중 CR 삭제 | 원격 create와 credential capture 사이에 CR 삭제(`status.tokenId` 비어 있음); subtype: journal은 존재하나 attempt finalizer가 삭제 전에 수동 제거됨 | `reconcileDelete`가 empty-status skip을 우회해 journal로 pending 원격을 식별, `DeleteServiceToken` 실행 후 finalizer 제거; orphan 0개. subtype에서는 deletionTimestamp 이후 finalizer를 다시 추가하지 않는다(Kubernetes가 금지) — 기존 journal provenance만으로 정리 | unit/envtest |
| ST-QA-16 | Regression | 발행된 Secret 소실 계약 유지 | `Ready=True` 수렴 후 Secret이 out-of-band 삭제 | 자동 rotate/recreate 금지; `Ready=False, Reason=SecretMissing`; `status.tokenId` 보존; rotation은 `spec.rotation.requestedAt` 필요 | unit/envtest |
| ST-QA-17 | Regression | out-of-band 원격 삭제(#49) | 수렴된 원격 토큰이 Cloudflare에서 직접 삭제(404) | `Ready=False, Accepted=False`; Access 컴파일이 해당 토큰 해석을 중단 | unit |
| ST-QA-18 | Regression | teardown 원격 삭제 실패(#63) | finalizer 있는 CR 삭제 중 `DeleteServiceToken` 500 | `CleanupBlocked=True` 보고, finalizer 유지, 원격 teardown 성공 전까지 K8s 리소스 제거 안 함 | unit |
| ST-QA-19 | Security | ObserveOnly 불변식 | `spec.managementPolicy: ObserveOnly` (+ subcase: pending 미해결 journal 잔존) | 원격 mutation 0건(Create/Rotate/Delete/Update) **및 credential/journal 쓰기 0건**; 관측 상태만 반영; pending 미해결 journal이 있어도 `Ready` 미보고·Secret 미기록 | unit |
| ST-QA-20 | Security | CloudflareAccount grant 철회 | ServiceToken namespace에 대한 grant 철회 | 어떤 Cloudflare API 호출 전에 중단; fail-closed deny; 원격 상태 무 변경 | unit/envtest |
| ST-QA-21 | Recovery | post-Secret/pre-status crash(창 C) | Secret에 credential+annotation 커밋 후 status patch 실패 | 다음 reconcile이 authoritative readback으로 capture 인식; `status.tokenId`+`Ready=True` 복원; 신규 create/rotate 0건; journal은 status patch 성공 후에만 reap | unit |
| ST-QA-22 | Baseline | 정상 멱등 reconcile 대조 | 결함 주입 없이 생성 후 연속 reconcile | reconcile 1: 예약→원격 1개 생성→capture→`Ready=True`; reconcile 2: 원격 mutation 0건, status 불변 | unit/envtest |
| ST-QA-23 | Recovery | account 복구 rotate 실패 | pending journal 존재 + `RotateServiceToken` 500 | delete fallback 없이 에러 반환·재시도; 원격 토큰 보존; 다음 reconcile의 rotate 재시도로 수렴; 원격 토큰 정확히 1개 | unit |
| ST-QA-24 | Recovery | zone 복구 delete 실패/재시작 | (a) `DeleteServiceToken` 실패 (b) delete 성공 후 create 전 controller 재시작 | (a) 원격 토큰 유지·재시도, delete 불확실 동안 create 없음; (b) 재시작 후 journal의 retiring ID checkpoint로 delete 확인 후에만 재생성; 최종 원격 토큰 정확히 1개 | unit |
| ST-QA-25 | Resilience | create 응답 손실 시 ID 미관측 | 원격 create 커밋됐으나 ID를 포함한 응답 전체 유실; `status.tokenId`는 미기록 | 재시도가 journal의 attempt name+nonce로 scoped list → 정확한 이름 일치 1건 복구; `api.creates`가 1을 유지(두 번째 create 없음) | unit |
| ST-QA-26 | Recovery | capture 후 정규화 실패 | credential capture 완료 후 canonical name 정규화/`UpdateServiceToken` 실패 | 재시도가 durable credential readback으로 rotate 없이 정규화만 재시도; credential 재발급 없음; 최종 `Ready=True` | unit |
| ST-QA-27 | Recovery | journal 정리/status patch 실패 | credential capture 후 status patch 실패(또는 journal 삭제 실패) | journal이 유지되고 재시도가 readback으로 수렴; journal은 status checkpoint 성공 후에만 삭제됨을 관측 | unit |
| ST-QA-28 | Edge | 재생성된 CR의 UID 불일치 | CR 삭제 후 동일 namespace/name으로 재생성(새 UID), 구 journal 잔존 | 새 CR UID가 journal 바인딩과 불일치 → adoption 없이 block 또는 자체 intent 진행; 구 journal은 ownerReference GC 대상 | unit/envtest |
| ST-QA-29 | Security | 손상/foreign journal | journal 내용이 파싱 불가이거나 다른 CR/owner를 가리킴 | fail-closed block; 원격 mutation 0건; credential 쓰기 0건 | unit |
| ST-QA-30 | Lifecycle | Orphan 정책 + pending 원격 | `deletionPolicy: Orphan` + pending 원격 토큰 상태에서 CR 삭제 | 원격 토큰 유지(삭제 시도 0건); finalizer 제거; journal 정리 | unit |
| ST-QA-31 | Edge | pending 중 mutable 필드 변경 | pending 중 `spec.duration`/`spec.enabled` 변경 | 불변 tuple은 일치하므로 복구 진행; credential capture 후 `UpdateServiceToken`으로 duration/enabled 정렬; 정렬 전 `Ready` 미보고 | unit |
| ST-QA-32 | Provenance | pending 중 account UID/ID 변경 | pending 중 `spec.accountRef` 전환 또는 account CR UID/account ID 변경 | journal 바인딩 불일치 → `Conflict` fail-closed; 어느 account에도 mutation 0건 | unit |
| ST-QA-33 | Security | 부분/빈 credential은 Ready 불가 | destination Secret이 예약 marker만 있고 데이터 0건이거나, token-id annotation만 있고 `CF-Access-Client-Secret` 등 키 결손 | credential-committed predicate(clientId+clientSecret+token-id annotation 모두 존재) 미충족 → `Ready=True` 미보고; 불완전 credential을 완전으로 취급하지 않음 | unit |
| ST-QA-34 | Edge | journal 부재 삭제의 fail-closed | CR 삭제 시점에 journal 없음 + pending 원격 존재 가능(미해결 dispatch) | finalizer는 검증되지 않은 pending 원격이 남아있는 동안 제거되지 않음; scoped list로 CR UID prefix 원격을 발견하면 검증 후 삭제, 삭제 실패·모호 시 `CleanupBlocked`+finalizer 유지 | unit |
| ST-QA-35 | Edge | dispatch 전 crash(prepared) | journal이 `prepared`로 커밋된 뒤 원격 create 발송 전 프로세스 crash | 재개 시 `prepared`+후보 0건 → create 발송 허용(이전 create 없음이 상태로 증명됨); 원격 토큰 정확히 1개 | unit |
| ST-QA-36 | Resilience | dispatched + 원격 일시 불가시 | create 발송 후 응답 유실/crash + 재개 시 scoped list가 0건 반환(일시적 미반영) | create/rotate 재발송 금지; mutation 없이 block/relist; bounded non-convergence는 의도된 fail-closed; 이후 list에 나타나면 정상 복구 | unit |
| ST-QA-37 | Resilience | stale cache miss가 rotate를 유발하지 않음 | credential 커밋 + status checkpoint 실패 + 즉시 requeue에서 informer 캐시가 Secret을 miss | `APIReader` authoritative read가 커밋된 credential을 확인; rotate/create 0건; capture를 committed로 인식해 수렴 | unit/envtest |
| ST-QA-38 | Recovery | dispatch~capture 사이 verified-zone metadata flap | journal `dispatched` 상태에서 account의 verified zone 목록이 일시적으로 flap(예: zone 미반영). spec과 account identity는 불변 | journal을 freshness gate·scope 재해석보다 먼저 처리하고 journal 기록 zone ID/account 바인딩으로 resume; `Invalid` 좌초 없이 복구 진행. spec/account identity 변경은 본 케이스 범위 밖 — ST-QA-12/32 참조 | unit |
| ST-QA-39 | Edge | checkpoint 후 잔여 journal + destination 삭제 | status checkpoint 성공 후 journal이 reap 전에 남아있고 operator가 destination Secret 삭제 | 잔여 journal은 reap 대상일 뿐 resume/rotate 근거 아님 → `SecretMissing` 보고; 자동 rotate 0건 | unit |
| ST-QA-40 | Provider | create 응답 이름 divergence | 원격 create 응답의 `Name`이 요청한 attempt 이름과 다름 | loop/재시도 create 없이 block; divergence를 조용히 수용하지 않음 | unit |
| ST-QA-41 | Isolation | 비관리 경로는 journal/reservation 없음 | `AdoptById`·`ObserveOnly`·established(`status.tokenId` 존재) 경로 실행 | journal Secret과 destination reservation을 생성하지 않음; 기존 경로 의미론 유지 | unit |
| ST-QA-42 | Edge | 미생성 invalid-zone CR 삭제 | `spec.zone`이 verified zone에 없어 생성 경로가 `Invalid`로 진입하지 못한 채 CR 삭제 | attempt marker 부재 + `status.tokenId` 공백 + journal 부재 → 원격 호출·scope 해석 없이 finalizer 제거; 원격 mutation 0건 | unit |
| ST-QA-43 | Edge | 미생성 grant 부재/계정 미해결 CR 삭제 | grant 철회 또는 account 미존재로 어떤 원격 호출 전에 차단된 상태에서 CR 삭제 | 동일하게 marker 부재가 미dispatch를 증명 → 원격 호출 없이 finalizer 제거; 원격 mutation 0건 | unit |
| ST-QA-44 | Edge | marker 기록 후 journal 생성 실패 | attempt marker 커밋 성공 + journal Secret `Create` 실패 | marker 존재 + journal 부재는 dispatch 가능성을 배제하지 못하므로 fail-closed 유지; 원격 mutation 0건; 삭제도 scoped 검증 없이 finalizer를 제거하지 않음 | unit |
| ST-QA-45 | Lifecycle | established 토큰 + 잔여 marker 삭제 | `status.tokenId` 기록된 established CR에 attempt marker가 남은 상태에서 CR 삭제 | 검증된 원격 삭제 후 finalizer와 attempt marker를 모두 제거; orphan 0개 | unit |
| ST-QA-46 | Edge | legacy markerless empty-status CR 삭제 | marker 도입 전에 생성된 CR(`status.tokenId` 공백, journal·marker 모두 부재) 삭제 | marker 부재가 미dispatch를 증명 → 원격 호출·scope 해석 없이 finalizer 제거; 원격 mutation 0건 | unit |

### 5.1 테스트 매핑과 실행

케이스는 `internal/controller/servicetoken_recovery_test.go`, `servicetoken_recovery_boundary_test.go`, `servicetoken_controller_test.go`의 테스트 함수로 구현됐다. 개별 실행은 다음 형태다(envtest 자산 필요 시 `make test-envtest` 경로와 동일하게 `KUBEBUILDER_ASSETS` 설정):

```text
go test ./internal/controller/ -run '<TestName>' -count=1
```

전체 게이트는 `make test`(= `test-unit` + `test-envtest`)로 수행한다.

| ID | 테스트 함수 |
|---|---|
| ST-QA-01 | `TestServiceTokenEarlySecretWriteFailureLeavesNoRemoteMutation` |
| ST-QA-02, ST-QA-07 | `TestServiceTokenCredentialWriteFailureRecoversSameToken` |
| ST-QA-03 | `TestServiceTokenZoneCredentialWriteFailureDeletesAndRecreates` |
| ST-QA-04, ST-QA-25 | `TestServiceTokenCreateResponseLossResumesAttempt` |
| ST-QA-05 | `TestServiceTokenCommittedCredentialWriteTimeoutKeepsCredential` |
| ST-QA-06 | `TestServiceTokenDuplicateNameConflictForcesJournalRecovery` |
| ST-QA-08 | `TestServiceTokenForeignDestinationSecretBlocksCreate` |
| ST-QA-09 | `TestServiceTokenImmutableDestinationBlocksCreate` |
| ST-QA-10 | `TestServiceTokenAmbiguousRemoteCandidatesBlockResume` |
| ST-QA-11 | `TestServiceTokenForeignClusterTokenIsIgnored` |
| ST-QA-12 | `TestServiceTokenPendingScopeDriftConflicts` |
| ST-QA-13 | `TestServiceTokenDeletedJournalBlocksAdoption` |
| ST-QA-14 | `TestServiceTokenPendingSecretRefChangeConflicts` |
| ST-QA-15 | `TestServiceTokenPendingDeleteCleansRemote` |
| ST-QA-16 | `TestServiceTokenEstablishedMissingSecretNeverRotates` |
| ST-QA-17 | `TestServiceTokenRemoteLossRevokesAccepted`, `TestServiceTokenUpdateRemoteLossRevokesAccepted` |
| ST-QA-18 | `TestServiceTokenDeletionFailureReportsCleanupBlocked` |
| ST-QA-19 | `TestServiceTokenObserveOnlyNeverMutates` |
| ST-QA-20 | `TestServiceTokenGrantRevocationDeniesBeforeRemote` |
| ST-QA-21, ST-QA-27 | `TestServiceTokenStatusPatchFailureReapsJournalOnRetry` |
| ST-QA-22 | `TestServiceTokenHealthyIssueReapsJournalAndStaysIdle` |
| ST-QA-23 | `TestServiceTokenRecoveryRotateFailureRetriesWithoutDelete` |
| ST-QA-24 | `TestServiceTokenZoneRecoveryDeleteFailureBlocksReplacement`, `TestServiceTokenZoneRecoveryResumesCreateAfterDelete` |
| ST-QA-26 | `TestServiceTokenRecoveryUpdateFailureRetriesWithoutRotation` |
| ST-QA-28 | `TestServiceTokenRecreatedCRUIDMismatch` |
| ST-QA-29 | `TestServiceTokenCorruptOrForeignJournalBlocks` |
| ST-QA-30 | `TestServiceTokenOrphanPendingDeleteKeepsRemote` |
| ST-QA-31 | `TestServiceTokenPendingMutableFieldChangeAligns` |
| ST-QA-32 | `TestServiceTokenPendingAccountDriftConflicts` |
| ST-QA-33 | `TestServiceTokenPartialCredentialNeverReady` |
| ST-QA-34 | `TestServiceTokenJournallessPendingDeleteFailsClosed` |
| ST-QA-35 | `TestServiceTokenPreparedJournalRetriesCreate` |
| ST-QA-36 | `TestServiceTokenDispatchedJournalWithZeroRemoteBlocks` |
| ST-QA-37 | `TestServiceTokenStaleCacheMissKeepsCommittedCredential` |
| ST-QA-38 | `TestServiceTokenZoneVerificationFlapResumes` |
| ST-QA-39 | `TestServiceTokenStaleJournalAfterCheckpointIsReapOnly` |
| ST-QA-40 | `TestServiceTokenCreateNameDivergenceBlocks` |
| ST-QA-41 | `TestServiceTokenNonManagedPathsSkipJournal` |
| ST-QA-42, ST-QA-43, ST-QA-46 | `TestServiceTokenNeverCreatedDeletionSkipsRemoteMutation` |
| ST-QA-44 | `TestServiceTokenAttemptMarkerProtectsJournalCreateFailure` |
| ST-QA-45 | `TestServiceTokenAttemptMarkerCleanupAndSteadyState` |

---

## 6. 한계

- **provider list 일관성**: scoped list가 방금 생성된 원격 토큰을 즉시 반영한다는 보장은 없다. `dispatched` + 0건은 "없음"이 아니라 "모름"이므로 block/relist로 응답한다. 이로 인한 bounded non-convergence는 결함이 아니라 의도된 fail-closed다.
- **provenance 수단의 한계**: service token은 tags/comment 같은 metadata 필드가 없어 **원격 이름이 유일한 내구성 provenance**다. nonce는 random이며 추측 불가해야 한다. ownership-verified journal + unguessable nonce 이상의 forged-name 저항을 주장하지 않는다.
- **clone/restore 미탐지**: 동일 Cloudflare account를 공유하는 복원된 클러스터 clone(동일 cluster UID·journal 포함)은 바인딩으로 구분할 수 없다.
- **모든 provenance 소실**: journal + CR + 원격 이름의 provenance가 모두 삭제되면 발견 가능한 범위를 넘어선다. 이 경우 남은 바인딩에서 fail-closed로 동작할 뿐이며, 모든 내구성 provenance 삭제에 대한 절대적 보장을 주장하지 않는다.
- **증거 범위**: §1.1의 재현과 §5의 모든 테스트는 저장소 fake API 기반이며 실제 Cloudflare 실행이 아니다. targeted suite와 전체 게이트 4종은 통과했으나 verify-generated와 원격 CI는 미실행이므로, 이 문서는 실계정 검증이나 CI 통과를 주장하지 않는다.
