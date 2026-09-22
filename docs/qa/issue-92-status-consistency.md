# Issue #92 상태 일관성 QA 체크리스트

대상: [isac322/flareway#92](https://github.com/isac322/flareway/issues/92) — 수렴된 Gateway가 reconcile마다 `ConfigApplied=False`를 중간 게시하고 상태를 교란하는 결함.
상태: **구현 진행 중 — 부분 실행 증거 기록됨**. 일부 항목은 envtest에서 실행되어 PASS/FAIL이 기록되었고 나머지는 `pending`이다. 이 문서는 제안된 QA와 실행된 증거를 구분해 기록하며, 전체 검증 완료를 의미하지 않는다.

## 1. 실행된 증거 (결함 측)

아래는 이미 실행되어 결함을 확인한 증거이다. 수정이 통과했다는 증거가 아니며, PASS는 결함 존재를 의미한다.

- **envtest 진단 스펙 PASS** (Go 1.27.1, Kubernetes 1.35.0 envtest, 소스 `dd322e3`): 무변경 수렴 패스가 mid-gate에 `ConfigApplied=False/Pending`(신규 타임스탬프 21:02, 21:03)을 게시하고, 종료 시 `True/Applied`가 이전 타임스탬프 21:01을 복원해 전이 시각이 역행함을 확인. 미ACK 대조군은 `False/Pending`이 정상임을 확인.
- **라이브 감사** (v0.2.0, `dd322e3`): 8개 스냅샷에서 `ConfigApplied`/`Ready` 찢어진 쌍과 매 샘플 갱신되는 tunnel `resourceVersion`, 정지된 Gateway `resourceVersion`을 기록. 메트릭 창(40.7521초)에 reconcile 103회, `workqueue_work_duration_seconds_sum` 40.5819 worker-초. 이 수치는 라이브 관측값이며 격리 테스트 기준선이 아니다.
- **교차 작성자 진단 PASS** (parent 실행, envtest 1.35, 소스 `dd322e3`, 격리 fixture, 17.379s): production Gateway 작성자가 (`ConfigApplied=True`, `Ready=True`) 시드 상태에 실제 `ConfigApplied=False` 쓰기를 수행하면 (False, True) 찢어진 쌍이 영속화됨을 실 API 서버 호출로 확인 — fresh read만으로는 수용 기준을 만족할 수 없다는 실행 증거. tunnel fresh-read 대조군은 (False, False), stale tunnel 스냅샷 작성자는 (False, True)와 `Ready` 타임스탬프 원복을 재현. 최초 교차 작성자 실패는 fixture 오류(중복 Accepted/TunnelReady/DNSReady 시딩)로 수정되었으며 제품 결함이 아니다. 매니저 churn 계측과 수정 후 검증은 아직 측정되지 않음(NOT MEASURED).

- **SSA CAS 프로토콜 PASS** (parent 실행, envtest 1.35): 동일 소유자의 동일 SSA 재적용은 no-op(resourceVersion 329→329). stale resourceVersion + `ForceOwnership` apply는 Conflict로 거부되어 최신 상태를 보존. resourceVersion 없는 대조 apply는 성공. CAS 프로토콜 자체는 확인됨.

### 수정 측 실행 증거 (부분)

아래는 수정 구현에 대해 실제로 실행된 결과이다. 전체 항목이 검증된 것이 아니다.

- **envtest-component PASS**: QA-92-01, 03, 05~13(13은 대상 재실행), 14, 15, 17~22, 46~49 — 실 API 서버(envtest 1.35)에서 실행.
- **envtest-manager PASS**: QA-92-02, 04, 24(실 차단 캐시), 25, 28, 35, 36, 40, 43.
- **QA-92-43 쌍측정 완료** (동일 하네스·동일 정상 상태, 실제 매니저+실 타이머): pre-fix 40.7533초 창에 Gateway reconcile 1774회·Tunnel 7088회, `workqueue_work_duration_seconds_sum` 40.7270+30.5046 worker-초, tunnel status `MODIFIED` 7098건, `resourceVersion` 증가 7107. post-fix 40.7559초 창에 Gateway 0회·Tunnel 21회, work 0+0.2790 worker-초, `MODIFIED` 0건, `resourceVersion` 증가 0, 원격 config 쓰기 0건(양쪽).
- **음성 대조**: baseline에서 찢어진 쌍 시드는 기대대로 FAIL, post-fix에서 PASS.
- **FAIL (구현 수정 중)**: QA-92-37, 38, 39, 41, 42; QA-92-34는 fixture 실패.
- **단정 교정**: QA-92-30b — 동일값 SSA 적용은 소유 이전이 아니라 공유 소유(co-ownership)를 생성함이 실행으로 확인되어 2단계 단정으로 교정; 교정된 claim-before-release 단정은 양 phase 모두 PASS.
- **공유 conditions 트랜잭션 그룹 PASS** (envtest, 15/15, 95.722s): QA-92-16(지속+일시 CAS), 23, 24(helper + 실 차단 캐시, 매니저 경유), 26, 27, 29, 30a/b/c, 31, 32(Direct 실제 Reconcile + Gateway 거부), 33(ObserveOnly 실제 Reconcile + mutation 없음), 34(실제 drain/finalizer).
- **전체 controller 스위트 PASS** (Ginkgo 269/269, 539.372s): `ownershipVerified` revocation 수정 후 실행. 이전에 별도 블로커였던 기존 stale credential identity 회귀도 함께 통과. `make test-unit`도 통과.
- **미해결**: QA-92-44(기존 게이트 전체 CI + 커밋 후 verify-generated)만 `pending` — 전체 검증 완료가 아님.
- **최종 리뷰 회귀 수정 PASS** (envtest): QA-92-26/29 확장 케이스 — Gateway 신규 UID/spec generation 체크포인트 재현이 수정 전 FAIL, fresh UID/generation/mode/provenance 가드 + RV-CAS 데이터 헬퍼 적용 후 2/2 PASS. volatile timestamp — 실제 T1 데이터 apply 후 nil 관측이 구 T1을 영속화해 FAIL, identity UID 패치에서 Active/Inactive 타임스탬프 제외 후 PASS.
- **마이그레이션 확장 PASS** (envtest): QA-92-30b API 요청 수 양성 단정 통과. ownership=false 클리어는 revocation 수정으로 이미 PASS(269 전체 스위트에 포함).
- **독립 최종 리뷰 완료**: 최종 atomicity 리뷰와 최종 Gateway 리뷰 모두 현재 수정을 승인, 발견 사항 없음.
- **통합 스위트 PASS**: `go test ./internal/controller -count=1 -timeout 30m` — controller+manager 통합 708.665s 전부 통과. lint 수정 PASS. `make test-unit` + `verify-artifacts` PASS(parity build·Helm·Kustomize·runtime defaults 포함).

QA 항목이 검증할 대상 계약:

- 조건만 다루는 공통 SSA 매니저 `flareway-tunnel-status`가 `status.conditions`를 소유. 기존 데이터 매니저(`flareway-tunnel`, `flareway-gateway`)는 데이터 필드를 계속 소유.
- fresh `APIReader` 읽기 + `resourceVersion` CAS로 conditions 트랜잭션 수행. 작성자 소유 condition만 오버레이하고, 다른 작성자 및 외부 항목은 보존. `Ready`를 동일 트랜잭션에서 원자적으로 계산.
- 타임스탬프는 pre-reconcile 스냅샷이 아니라 fresh live condition에서 유도. 관측 provenance 변경(세대/소유자/모드/삭제)은 거부.
- 충돌 재시도는 유한하며 원격 동작을 재실행하지 않는다.
- `WithTunnelLock` 내부 pre-mutation 콜백(no-op/Hold 판정 이후, `UpdateTunnelConfiguration` 이전)은 **conditions만** 기록: `ConfigApplied=False`(reason Applying)와 `Ready=False`를 동일 문서로 강등하고, 의도한 hash는 메시지에만 담는다. `configVersion.Desired`/`DesiredHash`는 추측으로 기록하지 않고 마지막 성공 push를 계속 기술 — push 전 DesiredHash 영속화는 in-lock no-change 분기(`gateway_cloudflare.go:648-656`)를 오염시켜 실패 후 재push를 영구 차단하므로 금지. 새 hash·반환 버전·appliedAt을 담은 단일 데이터 체크포인트는 push 성공 후, 게이트 평가 전에 기록.
- promotion은 CAS-RV뿐 아니라 live desired version/hash/remote + ownerUID/generation/mode/deletedAt 불일치를 거부.
- 무변경 수렴 패스는 speculative Pending을 건너뛰고 유효 상태 쓰기 0회.
- `GatewayReconciler`에 `APIReader` 배선 필요(`cmd/main.go`, `suite_test.go`).
- promotion은 CAS-RV뿐 아니라 세 독립 도메인 검사를 요구: (a) 컴파일된 스냅샷 identity의 정확한 xDS ACK, (b) 모든 활성 cloudflared Pod가 int64 설정 버전 `cloudflareResult.version`을 보고하고 live `configVersion` Desired/DesiredHash/Remote가 해당 패스가 컴파일·관측한 값과 일치, (c) 컴파일된 public hostname의 DNS readiness(External DNS 시 생략). 여기에 ownerUID/generation/mode/deletedAt provenance 불일치 거부를 더한다. Envoy xDS 스냅샷 버전(문자열 identity, `translator.SnapshotVersion`)과 Cloudflare 설정 버전(int64)은 서로 다른 도메인이며 어떤 항목도 둘의 동등성을 단정하지 않는다.
설계 합의(AtomicityReview 확인): 내구성 무효화는 `api.UpdateTunnelConfiguration` 직전(`gateway_cloudflare.go:661`, `WithTunnelLock` 내부)에 conditions-only로 커밋하고, 반환된 버전·새 hash·appliedAt의 데이터 체크포인트는 push 성공 후 게이트 평가 전에 영속화한다. stale promotion은 도메인별 토큰 + owner UID·observed generation·mode·deletedAt provenance로 거부한다.
- 원격 생성 경로의 identity 캡처: `status.tunnelId`가 비어 있을 때 `commitTunnelConditions`(conditions/migration 커밋)가 단일 `ensureRemoteTunnel` 호출점보다 먼저 무조건 실행되어 `/status` 존재를 보장하고, `CreateTunnel` 반환 후 `/metadata/uid` test op를 가진 RFC 6902 JSON Patch(status subresource, `flareway-tunnel` 매니저)가 `tunnelRemoteIdentityFields`(`tunnelId`·`accountId`·`name`·`tunnelType`·`configSource`·`connectorState`·`createdAt`·`deletedAt`·`connectionsActiveAt`·`connectionsInactiveAt`·`ownershipVerified`)를 기록. `observedGeneration`은 의도적으로 제외 — 관측된 spec generation을 기록하는 필드이며 원격 truth가 아니므로 캡처가 쓰면 stale 관측을 새 generation에 재기록한다. generation·resourceVersion 전제조건 없음; 자격증명 Secret ref는 체크포인트 이후 `ensureTokenSecret`에서 생성되므로 패치에 포함하지 않음(G6는 controller 소유 Secret으로 충족, status 포인터는 결정적 이름으로 재유도 가능). vetoable conditions 트랜잭션이 캡처 앞에 오면 generation skew나 CAS 소진이 생성된 원격 identity를 유실시키고 다음 패스가 중복 create를 수행하므로 이 순서가 요구된다. test op 실패와 스키마 거부는 오류로만 반환되며 구분되지 않으므로 재생성 여부는 결과 객체 상태로 판정한다. 이 패치는 구조적으로 conditions를 건드리지 않으므로 conditions-first 규칙의 예외다.

## 3. 측정 계약

- 밀리초 SLA, 임의의 격리 기준선, 정확한 reconcile 횟수 단정을 금지한다. workqueue는 비동기 이벤트를 병합하므로 횟수가 아니라 관측 가능한 상태 시퀀스를 단정한다.
- churn은 API 서버 watch `MODIFIED` 이벤트와 `metadata.resourceVersion` 안정성으로 측정한다.
- 활성성(liveness)은 "다음 주기적 requeue 타이머가 발화하기 전에 이벤트에 인과적으로 이어진 reconcile이 관측된다"로 정의한다. 설정된 주기는 `programmedRequeue`(2s), `tunnelRequeue`(2s), Freshness TTL이다. 테스트 하네스 `Eventually` 타임아웃은 상한일 뿐 제품 SLA가 아니다.
- 매니저 활성성 증명: 주기적 requeue를 비활성화하거나 발화 시점을 관측 가능하게 한 상태에서, 상태 전용 이벤트 후 주기 타이머 만료 전에 reconcile 시작이 관측되어야 한다. 타이머 구조에 의한 우연한 진행은 활성성 증거로 인정하지 않는다.
- 베이스라인 비교는 동일 하네스·동일 정상 상태에서 pre/post를 실측한다. 라이브 수치(103회/40.5819 worker-초/40.7521초)는 참조 관측값이며 격리 테스트의 기대값으로 복사하지 않는다.
- 메시지 문구를 고정하지 않는다. reason 클래스와 지연 항목 범주를 단정한다.
- 버전 변경/체크포인트 경로에 "정확히 1회 쓰기"를 요구하지 않는다. 요구하는 것은 순서(무효화→intent hash→provider write→버전 체크포인트→게이트→promotion)와 실패 시 폐쇄성이다.
- CAS/충돌 항목(QA-92-16, QA-92-23~25, QA-92-27~30)은 실 API 서버(envtest)에서 실행한다. controller-runtime fake client는 SSA를 자체 patch 경로로 모사해 resourceVersion 전제조건을 구현하지 않으므로, fake client 구현은 이 항목들을 공허하게 통과시킨다.

## 4. QA 체크리스트

티어: `envtest-component` = 단일 reconciler + 실 API 서버(envtest), `envtest-manager` = 양 컨트롤러를 실 매니저/캐시/watch로 실행, `live-audit` = 실 설치 읽기 전용 관측.

### A. 정상 상태 무변경 시퀀스/타임스탬프

| ID | 전제 | 자극 | 관측 기대 | 티어 | 증거 |
|---|---|---|---|---|---|
| QA-92-01 | Gateway·tunnel 완전 수렴(desired=applied=remote, `ConfigApplied=True`, `Programmed=True`) | 무변경 reconcile 1회, 게이트 평가 중 mid-pass 영속 상태 판독 | 패스 중 어느 시점에도 `ConfigApplied=False`가 영속화되지 않음; 최종 `True`; remote update 횟수 불변 | envtest-component | PASS (수정측 envtest); 결함측 증거: 진단 스펙 |
| QA-92-02 | QA-92-01과 동일 | 연속 무변경 패스 + watch 관측 | tunnel status `MODIFIED` 이벤트 0건; `resourceVersion` 불변; 자기 유발 재큐 없음 | envtest-manager | PASS (수정측 envtest-manager) |
| QA-92-03 | `ConfigApplied=True`, 전이 시각 T0 | 시계 진행 후 무변경 패스 반복 | `lastTransitionTime`이 T0 유지; 전진도 역행도 없음 | envtest-component | PASS (수정측 envtest); 결함측 증거: 진단 스펙 |
| QA-92-04 | 수렴 상태 | 무변경 패스 | Gateway status·HTTPRoute·BackendTLSPolicy status도 재기록되지 않음; Gateway `resourceVersion` 불변. 관측된 무관한 기저 status churn은 별도 발견 사항으로 보고하며 본 항목 범위를 확장하지 않음 | envtest-manager | PASS (수정측 envtest-manager) |

### B. 실패·복구·메시지 전용 갱신

| ID | 전제 | 자극 | 관측 기대 | 티어 | 증거 |
|---|---|---|---|---|---|
| QA-92-05 | 원격·Pod 수렴, xDS 스냅샷이 최초 패스부터 한 번도 ACK되지 않음 | reconcile | `ConfigApplied=False`/Pending 유지, 지연 항목 범주(xDS ACK)가 메시지에 표시; `Programmed=False`. 초기 미수렴 음성 대조 | envtest-component | PASS (수정측 envtest); 결함측 대조군 확인됨 |
| QA-92-06 | `ConfigApplied=False`(실제 미수렴) | 게이트 충족 후 reconcile | `True`로 전이, `lastTransitionTime`이 실제 전이 시각으로 전진; 같은 리비전에서 `Ready` 일관 | envtest-component | PASS (수정측 envtest) |
| QA-92-07 | `ConfigApplied=False` 유지 중 | 지연 항목 구성만 변화(메시지/사유 변경, status 동일) | `lastTransitionTime` 보존; status 전이 없이 message/reason만 갱신 | envtest-component | PASS (수정측 envtest) |
| QA-92-08 | `ConfigApplied=False`가 수렴 타임아웃(30s) 경과 | 시계 진행 후 reconcile | status는 `False` 유지, 메시지가 타임아웃 범주로 격상; `lastTransitionTime`은 최초 `False` 전이 시각 유지 | envtest-component | PASS (수정측 envtest) |

### C. desired hash/version 진행·내구 체크포인트·중단

| ID | 전제 | 자극 | 관측 기대 | 티어 | 증거 |
|---|---|---|---|---|---|
| QA-92-09 | 버전 V 수렴 | spec 변경으로 desired V+1 도출 | provider 쓰기 **전에** conditions-only 강등: `ConfigApplied=False`(reason Applying)+`Ready=False` 동일 문서, 의도한 hash는 메시지에만 기록(no-op/Hold 판정 이후, `UpdateTunnelConfiguration` 이전). `configVersion.Desired`/`DesiredHash`는 추측 기록 없이 마지막 성공 push를 계속 기술 | envtest-component | PASS (수정측 envtest) |
| QA-92-10 | QA-92-09 진행 중 | provider write가 V+1 반환 | push 전에는 conditions만 변경되고 `configVersion`은 무변경; push 성공 후 게이트 평가 전에 단일 데이터 체크포인트가 `DesiredHash`=new·desired=remote=V+1·appliedAt을 영속화 | envtest-component | PASS (수정측 envtest) |
| QA-92-11 | QA-92-09 진행 중 | **매개변수화된 중단 매트릭스**: (a) conditions 강등 영속화 직후, (b) provider write 직후, (c) 버전 체크포인트 직후, (d) promotion 직전에 각각 abort 주입 | 각 지점에서 미게이트 버전을 Applied/Ready로 주장하는 영속 리비전 없음; 다음 패스가 fail-closed로 재개. 원격 쓰기는 exactly-once가 아니라 at-least-once + drift reconciliation — `UpdateTunnelConfiguration` 반환과 체크포인트 사이 중단은 원격을 기록 상태보다 앞서게 하며, 다음 패스가 tunnel lock 안에서 원격을 재읽어 baseline/drift 비교로 조정. status-CAS 재시도는 원격 동작을 재실행하지 않음 | envtest-component | PASS (수정측 envtest) |
| QA-92-12 | 버전 V 수렴 | desired hash만 변경(버전 동일/미지정) | applied 상태 무효화로 fail-closed; 구 `True`가 새 desired를 가리키지 않음 | envtest-component | PASS (수정측 envtest) |
| QA-92-13 | 버전 V 수렴 | V→V+1 전체 사이클 | 강등→체크포인트→게이트→promotion 순서 준수; 타임스탬프 단조; `Ready`가 `ConfigApplied`와 원자적으로 추종 | envtest-component | PASS (수정측 envtest, 대상 재실행) |

### D. 관측 API 오류·원격 mutation 실패

| ID | 전제 | 자극 | 관측 기대 | 티어 | 증거 |
|---|---|---|---|---|---|
| QA-92-14 | 수렴 상태 | (a) Pod list/원격 조회 등 API 오류 반환, (b) readiness probe 지연(비오류) | (a) reconcile 오류 반환; status 쓰기 가능 시 구분 가능한 reason의 `False`로 fail-closed; 조용한 `True` 유지로 실제 오류를 숨기지 않음. tunnel condition에 `Unknown` 삼태를 도입하지 않음(`Unknown`은 Gateway/GatewayClass Programmed 전용, 신규 API 동작은 범위 밖). (b) Go 오류가 아닌 pending으로 처리, `ConfigApplied=False`/Pending 유지 | envtest-component | PASS (수정측 envtest) |
| QA-92-15 | desired 진행 중 | `UpdateTunnelConfiguration` 실패 | 오류 반환; `ConfigApplied`/`Ready`는 `False` 유지; applied 미진행. **판별 단정**: 다음 패스가 `UpdateTunnelConfiguration`을 다시 호출(fake API 호출 수 증가)하고 `status.configVersion.DesiredHash`가 실패 전 값을 유지 — hash 단정 없이 재시도 통과만으로는 stuck no-change 분기를 가릴 수 있음 | envtest-component | PASS (수정측 envtest) |
| QA-92-16 | 상태 커밋 경로 | (a) 일시적 CAS resourceVersion 충돌, (b) 지속적 충돌로 재시도 한도 소진 | (a) 유한 재시도 후 단일 일관 커밋; status-CAS 재시도가 원격 동작을 재실행하지 않음. (b) 오류 반환 + backoff requeue; 비CAS 쓰기로 후퇴·충돌 강제 통과·delta 조용한 폐기 모두 금지 | envtest-component | PASS (수정측 envtest, 공유 conditions 그룹) |

### E. 드리프트 overwrite/hold

| ID | 전제 | 자극 | 관측 기대 | 티어 | 증거 |
|---|---|---|---|---|---|
| QA-92-17 | 수렴 상태, DriftPolicy=Overwrite | 원격 설정을 out-of-band 변경 | `DriftDetected=True`; 원격이 desired로 덮어써짐; 재수렴 후 `ConfigApplied` 회복 | envtest-component | PASS (수정측 envtest) |
| QA-92-18 | 수렴 상태, DriftPolicy=Hold | 원격 설정을 out-of-band 변경 | 게이트 평가 전 중단; `DriftDetected=True`; `ConfigApplied=False`/DriftHold; `Programmed=False`; 원격 미변경; requeue 반환. 성공 push와 체크포인트 사이 중단은 원격을 기록 baseline보다 앞서게 하므로 다음 패스가 drift 분기를 타고, Hold 하에서는 자기 중단 push를 out-of-band change로 보고 — 깨끗한 재시도가 아니라 해당 메시지를 기대(유계·기존 동작) | envtest-component | PASS (수정측 envtest) |

### F. xDS/Pod/DNS 게이트

| ID | 전제 | 자극 | 관측 기대 | 티어 | 증거 |
|---|---|---|---|---|---|
| QA-92-19 | 수렴 상태(스냅샷 ACK 완료, `ConfigApplied=True`) | ACK된 스냅샷이 NACK되거나 활성 ACK가 소실 | `ConfigApplied`가 `True`→`False`/Pending으로 실제 전이, `Programmed=False`; ACK 복구 시 재수렴 | envtest-component | PASS (수정측 envtest) |
| QA-92-20 | 원격 수렴 | cloudflared Pod 미준비 또는 `/config` 버전 불일치 | `ConfigApplied=False`/Pending, `Programmed=False` | envtest-component | PASS (수정측 envtest) |
| QA-92-21 | 원격·Pod 수렴, 관리형 DNS 모드 | DNS 레코드 미준비 | `ConfigApplied=False`/Pending, `Programmed=False` | envtest-component | PASS (수정측 envtest) |
| QA-92-22 | 나머지 게이트 충족 | 프라이빗 리스너 pending 상태 | 게이트 차단, 지연 항목에 프라이빗 리스너 범주 표시; `PrivateListenerDegraded`가 상태 반영 | envtest-component | PASS (수정측 envtest) |

### G. 교차 작성자·원자성·충돌

| ID | 전제 | 자극 | 관측 기대 | 티어 | 증거 |
|---|---|---|---|---|---|
| QA-92-23 | Gateway 모드 수렴 | `ConfigApplied` 전이를 유발하는 임의 경로 | 어떤 영속 리비전에도 `Ready=True ∧ ConfigApplied=False` 공존 없음; 두 condition이 단일 conditions 트랜잭션으로 커밋 | envtest-manager | PASS (수정측 envtest, 공유 conditions 그룹) |
| QA-92-24 | Gateway가 `ConfigApplied=False` 게시 직후 | informer 캐시가 지연된 상태에서 tunnel reconciler 실행 | stale 캐시가 live `ConfigApplied=False` 위에 `Ready=True`를 재게시하지 않음; fresh APIReader 읽기가 판정 근거 | envtest-manager | PASS (수정측 envtest-manager, 실 차단 캐시) |
| QA-92-25 | 마이그레이션 완료 상태, 의미 변경 없음 | Gateway 패스→tunnel 패스→Gateway 패스 교대 반복 + 동시 reconcile 스트레스 | 샘플링한 모든 영속 상태가 비찢어짐; 중복 condition 항목 없음; managedFields상 condition 항목당 단일 소유자; 교대 패스 전 구간 `resourceVersion` 불변(내용이 동일해도 매니저 교대는 managedFields를 재기록하므로 RV만이 ping-pong을 탐지) | envtest-manager | PASS (수정측 envtest-manager) |

### H. stale 세대/소유자/재생성/원격 ID

| ID | 전제 | 자극 | 관측 기대 | 티어 | 증거 |
| QA-92-26 | reconcile 진행 중 | spec 편집으로 generation 진행 | 해당 패스는 쓰기 없이 중단; 다음 패스가 새 generation과 fresh 관측값으로 기록. stale 관측을 새 generation으로 재기록하지 않음 | envtest-component | PASS (원본 + 확장: 동일 UID spec generation bump 시 stale hash 체크포인트 거부, 가드 적용 후 통과) |
| QA-92-27 | reconcile 진행 중, RV-basis 읽기와 apply 사이 | tunnel 객체 변형(generation bump 또는 타 작성자의 `configVersion.desired`/`desiredHash` 진행) | 커밋이 쓰기 없이 중단되거나 409 후 재유도; 다음 패스가 수렴. CAS는 tunnel 객체 범위만 커버 | envtest-component | PASS (수정측 envtest, 공유 conditions 그룹) |
| QA-92-28 | live Gateway 재검증과 tunnel status 커밋 사이 | Gateway spec 변경 또는 재생성(UID 변경) | 원자성이 아닌 유계 결과: 커밋이 대체된 Gateway generation을 기술할 수 있으나 같은 리비전에서 `Ready`는 `ConfigApplied`와 일관; Gateway watch가 교정 패스를 생성. 잔여 TOCTOU는 부정하지 않고 rationale로 명시 | envtest-manager | PASS (수정측 envtest-manager) |
| QA-92-29 | reconcile 진행 중 | 원격 tunnel 교체 / 모드 전환(Direct) / 삭제 시작 | live desired version·hash·remote·mode·deletedAt 불일치 시 promotion 거부(CAS-RV 통과만으로 부족) | envtest-component | PASS (원본 + 확장: 원격 update 콜백의 tunnel UID 재생성 시 대체 객체 구 config 수신 거부, 가드 적용 후 통과) |
| QA-92-30a | 수정 전 필드 소유 상태(`flareway-gateway`/`flareway-tunnel` 소유 condition) | 업그레이드 후 첫 패스 | 어떤 영속 리비전에도 Flareway condition 부재 없음 — conditions를 생략하는 data-only apply가 소유 주장보다 먼저 실행되면 구 매니저 소유 항목(`Ready` 포함)이 SSA로 삭제되므로 금지. SSA는 소유했지만 생략된 필드를 다른 소유자가 없을 때만 삭제하므로, 신규 매니저의 공유 소유 주장이 생략보다 먼저 성립하면 한 소유자의 생략만으로는 항목이 삭제되지 않음 | envtest-component | PASS (수정측 envtest, 공유 conditions 그룹) |
| QA-92-30b | 레거시 소유 객체의 condition 값이 이미 desired와 동일 | 신규 `flareway-tunnel-status` 매니저 첫 적용 → 이후 구 매니저의 conditions-생략 apply | 2단계 단정: (a) 첫 conditions 커밋 직후·conditions-생략 data apply 이전에 신규 매니저가 해당 항목의 소유자 중 하나(co-owner)로 등록됨 — 동일값 SSA 적용은 충돌이 아니라 공유 소유를 생성하므로 값 동등 fast-path가 소유 주장을 건너뛰지 않음; (b) 구 매니저의 다음 conditions-생략 apply 이후에야 신규 매니저가 단독 소유자가 됨. 순서가 본질: SSA는 소유했지만 생략된 필드를 다른 소유자가 없을 때만 삭제하므로 주장이 생략보다 먼저 성립해야 하며, 공유 소유 항목은 한 소유자의 생략으로 삭제되지 않음 | envtest-component | PASS (수정측 envtest, 교정된 2단계 단정 양 phase + API 요청 수 양성 단정 통과) |
| QA-92-30c | 마이그레이션 완료, 외부 매니저 소유 커스텀 condition 존재 | 반복 패스 | 패스당 쓰기 0건 유지 — skip 판정은 Flareway condition 타입 단위이며 외부 항목이 no-op skip을 영구 비활성화하지 않음; 외부 항목의 field-manager 소유 불변(문서가 외부 타입을 생략해 보존; 값 유지와 소유 탈취를 구분) | envtest-component | PASS (수정측 envtest, 공유 conditions 그룹) |
| QA-92-31 | 구 매니저로 `Ready=True ∧ ConfigApplied=False` 찢어진 쌍을 직접 시드(수정 전 바이너리가 남길 수 있는 상태) | 컨트롤러 기동 후 1패스 | 첫 conditions 커밋이 spec 변경·원격 호출 없이 `Ready=False`로 클램프; 업그레이드가 기존 찢어진 객체를 래치된 채로 두지 않음 | envtest-component | PASS (수정측 envtest, 공유 conditions 그룹) |
| QA-92-46 | 원격 `CreateTunnel` 호출 진행 중; fixture는 remote-projection이 persisted status와 divergence(unseeded 첫 create 또는 fake remote와 다른 시드 값 — 수렴 fixture는 캡처를 건너뛰어 공허 통과) | create 반환과 identity 캡처 사이에 CloudflareTunnel generation bump | remote-identity 프로젝션(`tunnelRemoteIdentityFields`)이 단위로 기록됨 — `ownershipVerified` 포함; `observedGeneration`은 캡처가 쓰지 않고 동일 패스의 data apply에 맡김(음성 단정 — 캡처가 쓰면 stale 관측을 새 generation에 재기록). 다음 패스가 두 번째 `CreateTunnel`을 호출하지 않음(fake 호출 수 불변 단정)하고 managed `GetTunnel` 경로로 진행, 채택 충돌 미보고. 부분 캡처는 `tunnelId` 설정+`ownershipVerified` false 조합이 영구 채택 충돌을 만들므로 단위 단정이 필수 | envtest-component | PASS (수정측 envtest) |
| QA-92-47 | 원격 `CreateTunnel` 호출 진행 중 | create 반환과 캡처 사이에 CR 삭제·재생성 | uid test op가 패치를 단위로 거부하고 오류가 반환·표면화됨; 대체 객체는 미변경(새 UID에 `tunnelId` 없음). 존재하지 않는 orphan 라우팅을 요구하지 않음. 오류 처리는 스키마 거부와 uid test 실패를 구분하지 않으므로 재생성 여부는 status code나 메시지가 아니라 결과 객체 상태로 단정 | envtest-component | PASS (수정측 envtest) |
| QA-92-48 | identity 캡처 패치 적용 | 패치 전후 conditions 및 managedFields 비교 | 모든 condition 항목과 field-manager 소유가 불변; 레거시 소유 상태에서도 condition 삭제 없음 — 패치가 구조적으로 conditions를 건드리지 않음을 증명(conditions-first 규칙의 명시적 예외가 아니라 구조적 면제) | envtest-component | PASS (수정측 envtest) |
### I. Direct/ObserveOnly/삭제 라이프사이클

| ID | 전제 | 자극 | 관측 기대 | 티어 | 증거 |
|---|---|---|---|---|---|
| QA-92-32 | `configuration.mode: Direct` tunnel | tunnel reconcile + Direct tunnel을 참조하는 Gateway | tunnel reconciler가 `ConfigApplied`+`Ready`를 단일 SSA로 기록; Gateway는 `Accepted=False`로 거부하고 tunnel status 쓰기 0건 (G4) | envtest-component | PASS (수정측 envtest, Direct 실제 Reconcile + Gateway 거부) |
| QA-92-33 | `managementPolicy: ObserveOnly` tunnel | Gateway/tunnel reconcile | 원격·자격증명 mutation 없음; `Ready=False`/ObserveOnly; status·finalizer 갱신은 허용 (G2). tunnel 작성자의 conditions 커밋이 이 상태에서 성공 — 소유권 전제조건(deletedAt·ownershipVerified·gatewayRef/Uid·live Gateway·drain)은 Gateway 작성자 전용이며 tunnel 커밋을 중단시키지 않음 | envtest-component | PASS (수정측 envtest, ObserveOnly 실제 Reconcile + mutation 없음) |
| QA-92-34 | 수렴 상태, 삭제·teardown 진행 | deny 스냅샷 ACK + Pod drain 중 reconcile | `ConfigApplied=True`/TeardownBlocked 유지(replicas 0까지); finalizer 순서 보존; teardown 중 `ConfigApplied` flap 없음. tunnel 작성자의 conditions 커밋이 삭제 진행 상태(deletedAt 설정 포함)에서 성공 — Gateway 전용 소유권 전제조건이 tunnel 커밋을 중단시키지 않음 | envtest-component | PASS (수정측 envtest, 실제 drain/finalizer — 초기 fixture 실패 후 통과) |
| QA-92-49 | 신규 CloudflareTunnel 프로비저닝 시작, `status.tunnelId` 비어 있음 | 라이프사이클 전 구간 관측 | 두 절 모두 단정: (a) `commitTunnelConditions`가 단일 `ensureRemoteTunnel` 호출점보다 먼저 무조건 실행되어 post-create 캡처 시점에 `/status`가 존재; (b) create 이전 중단은 원격 tunnel을 남기지 않음(아직 원격 리소스가 없으므로 비용 없음). 이 보장은 무조건 커밋 순서에서 오며 `Accepted` 선행 기록 가정에 의존하지 않음(`Accepted` set()은 in-memory 변경이며 첫 프로비저닝 경로는 status 부재로 `ensureRemoteTunnel`에 도달 가능). **판별 fixture**: Direct-mode 최초 reconcile + status 미시드 — 이전 status 쓰기는 전부 분기 한정(drain-wait는 기존 GatewayRef 필요, ownership-checkpoint는 Gateway 모드 블록, credentials-invalid는 오류 경로, open-gate는 비어있지 않은 tunnelId 필요)이며 Gateway 모드 fixture는 ownership 핸드셰이크가 create 전 write-and-requeue를 강제해 보장 부재를 가림. `/status` 존재는 커밋 후 어느 분기(merged-differs 쓰기 / deep-equal skip — skip은 conditions가 이미 존재함을 의미)를 탔든 단정 | envtest-component | PASS (수정측 envtest) |

### J. 상태 전용 watch wakeup (매니저 활성성)

공통 전제: 주기적 requeue 타이머 미발화 상태에서 상태 전용 이벤트 주입. 공통 기대: 이벤트에 인과적으로 이어진 Gateway reconcile이 다음 주기 타이머 만료 전에 관측됨(§3 활성성 정의). 하네스 `Eventually` 상한은 SLA가 아님.

| ID | 전제 | 자극 | 관측 기대 | 티어 | 증거 |
|---|---|---|---|---|---|
| QA-92-35 | `status.tunnelID` 미설정 | tunnel reconciler가 `TunnelID` 기록 | tunnel 작성자의 conditions 커밋이 `tunnelID` 미설정 상태에서 성공(초기 프로비저닝 상태 게시, 전제조건으로 중단되지 않음); Gateway가 깨어나 할당된 ID를 참조하는 설정 컴파일 진행 | envtest-manager | PASS (수정측 envtest-manager) |
| QA-92-36 | `status.connectorTokenSecretRef` nil | 자격증명 캡처 후 ref 기록 (G6) | tunnel 작성자의 conditions 커밋이 ref nil 상태에서 성공(전제조건으로 중단되지 않음); Gateway가 깨어나 자격증명 Secret을 읽고 dataplane 검사 진행 | envtest-manager | PASS (수정측 envtest-manager) |
| QA-92-37 | `status.ownershipVerified=false` | `OwnershipVerified=true` 기록 | tunnel 작성자의 conditions 커밋이 미검증 상태에서 성공(전제조건으로 중단되지 않음); Gateway가 깨어나 소유권 미검증 차단 해제, 수렴 진행 | envtest-manager | PASS (수정측 envtest-manager — fixture가 lazy client 사용 전 configuration을 시드해 accountID가 비었던 문제를 seed account identity로 교정 후 통과) |
| QA-92-38 | DNS 게이트 대기 중(`Programmed=False`), 관리형 DNS 모드 | `status.dnsRecords`에 컴파일된 public 리스너 hostname 항목이 비Conflict 상태로 기록(게이트가 실제 소비하는 필드, `publicDNSReady` gateway_cloudflare.go:791-807) | Gateway가 깨어나 `Programmed=True`로 승격. 판별 조건: `DNSReady=True` condition만 있고 대응 `dnsRecords` 항목이 없으면 `Programmed`가 되지 않음 | envtest-manager | PASS (수정측 envtest-manager) |
| QA-92-39 | 완전 수렴 | cloudflared Pod status가 not-ready로 전이 또는 `/config`가 desired 버전 미보고(게이트가 실제 소비하는 신호; Gateway 경로는 `TunnelReady` condition을 읽지 않음 — `validateGatewayTunnelWriter` + dataplane probe만 소비) | Gateway가 깨어나 `Programmed=False`로 fail-closed, 진동 없음 | envtest-manager | PASS (수정측 envtest-manager) |
| QA-92-40 | 채택 진행 중 | 작성자 가드가 소비하는 status 필드 기록: `status.tunnelId` 비어있지 않음, `status.accountID`, `status.ownershipVerified=true`, `status.connectorTokenSecretRef` 비nil, `status.gatewayRef`/`status.gatewayUid`가 live Gateway UID와 일치, `status.deletedAt` nil | Gateway가 깨어나 채택/검증 절차 진행 | envtest-manager | PASS (수정측 envtest-manager) |
| QA-92-42 | 계정 참조 중 | `CloudflareAccount` 갱신/자격증명 rotation | `mapAccountToGateways` 다중 홉 매핑으로 enqueue; 자격증명 검증 실패 시 오류 표면화 | envtest-manager | PASS (수정측 envtest-manager) |
| QA-92-41 | 수렴, DriftPolicy=Hold | `SweepEvents` 채널에 GenericEvent 전달 | 채널 이벤트로 깨어나 drift 평가, `DriftDetected` 반영, 무한 루프 없음 | envtest-manager | PASS (수정측 envtest-manager) |

### K. 계측·기존 게이트·최종 회귀

| ID | 전제 | 자극 | 관측 기대 | 티어 | 증거 |
|---|---|---|---|---|---|
| QA-92-43 | 동일 하네스·동일 정상 상태, 실제 매니저+실 타이머 | pre/post 수정 각각 기록된 창 형태(40.7521초)로 계측 | post-fix reconcile 수와 `workqueue_work_duration_seconds_sum`이 동일 조건 pre-fix 실측 대비 명확히 감소; 자기 유발 status `MODIFIED` 루프 0건. 라이브 수치는 참조값일 뿐 기대값으로 복사하지 않음 | envtest-manager + live-audit | PASS (쌍측정 완료: §1 수정 측 증거) |
| QA-92-44 | 수정 적용 | 기존 unit/envtest 스위트 전체 + 결함 단정 진단 스펙 | 기존 게이트 전부 통과; 결함을 단정하던 진단 스펙은 실패로 전환되어 제거/반전 대상임을 확인 | envtest-component | pending |
| QA-92-45 | QA 전 항목 확정 후 | 독립 리뷰어가 최종 diff를 재검토 | 관측 계약 단정 품질뿐 아니라 런타임 동작·라이프사이클·보안 불변조건·동시성·diff 범위 적절성을 포괄; 내부 구현 고정(소스 텍스트/배선/필드 복사 단정) 없음을 확인 | review | PASS (독립 최종 리뷰 2건 승인, 발견 사항 없음) |

## 5. 수용 기준 매핑

| 이슈 수용 기준 | QA 항목 |
|---|---|
| 수렴 reconcile이 평가 중이라는 이유만으로 중간 `ConfigApplied=False`를 외부에 게시하지 않는다 | QA-92-01, QA-92-02 |
| desired 불변·기적용 시 단일 멱등 관측 상태 커밋; desired 진행 시 수렴 평가 전 내구적 미적용 체크포인트로 abort fail-closed; 무변경 반복 패스가 전이 타임스탬프/상태 churn을 유발하지 않는다 | QA-92-01, QA-92-02, QA-92-03, QA-92-09, QA-92-10, QA-92-11, QA-92-16, QA-92-46, QA-92-47, QA-92-48 |
| `ConfigApplied`와 `Ready`가 불일치 뷰에서 게시되지 않음(`Ready=True ∧ ConfigApplied=False` 없음); `lastTransitionTime`이 항상 최근 실제 전이를 반영 | QA-92-03, QA-92-06, QA-92-07, QA-92-23, QA-92-24, QA-92-25, QA-92-31 |
| 정당한 pending/실패 상태 관측 가능 — 실제 probe/dataplane 실패 및 원격 할당·채택·자격증명 검증을 위한 상태 전용 wakeup 보존 | QA-92-05, QA-92-14, QA-92-19~22, QA-92-35~42, QA-92-49 |
| 안정 spec·정상 dataplane의 한정 재현에서 `ConfigApplied`/`Ready` 진동 없음, 기록된 기준선(103 reconcile, 40.5819 worker-초/40.7521초, 단일 워커) 대비 명확히 하회 | QA-92-02, QA-92-43 |
| `Ready=True`는 모든 필수 condition이 실제 수렴했을 때만 | QA-92-06, QA-92-23, QA-92-31, QA-92-32, QA-92-33 |
| 격리 컨트롤러/파이프라인 테스트가 중간 평가와 실제 pending/failure를 구별하고 외부 관측 상태 시퀀스를 단정 | QA-92-01, QA-92-05, QA-92-11, QA-92-45 |
## 6. 매니저 활성성 증명 (타이머 구조 없이)

다음을 모두 만족할 때 상태 전용 wakeup이 watch 경로로 발생했다고 인정한다:

1. 주기적 requeue(`programmedRequeue`, `tunnelRequeue`, Freshness TTL)가 관측 창 내 미발화이거나, 발화 시점이 reconcile 시작 시각과 구분 가능하게 기록된다.
2. 상태 전용 이벤트(예: `TunnelID` 기록)의 API 서버 커밋 시각 < Gateway reconcile 시작 시각 < 다음 주기 타이머 만료 시각의 인과 순서가 관측된다.
3. reconcile 내부에서 해당 변경이 실제로 소비된다(예: 할당된 `TunnelID`가 컴파일된 설정에 반영).
4. 이벤트가 없는 대조 창에서는 동일 기간 reconcile이 발생하지 않는다.

## 7. 피어 리뷰 확인
| 리뷰어 | 확인 내용 | 상태 |
|---|---|---|
| AtomicityReview (reviewer) | 전체 문서 최종 사인오프(무조건) — B1-B8, parent judge 교정 9건, Tier-1 작성자 분리(QA-92-33~37), conditions-only pre-mutation(QA-92-09~11/15/18), identity 캡처 세트(QA-92-46~49: uid test·remote-identity 단위 캡처·observedGeneration 제외·Direct 미시드 판별 fixture), SSA co-ownership 2단계 단정(QA-92-30a/b)까지 전부 파일 기준 검증. 30b 실행 PASS가 claim-before-release 안전 속성을 추론이 아닌 관측으로 확인함을 명시. 잔여 블로커 없음 | 최종 사인오프 (무조건, 실행 증거 반영본 포함) |
| GatewayFlow (scout) | 11개 QA 제안 수렴 — steady-state, fail-closed 체크포인트, 게이트, 드리프트, 관측 실패, 작성자 검증 항목이 §4 A–F, I에 반영됨 | 수렴 완료 |
| StatusConsistency (scout) | 12개 QA 제안 수렴 — SSA 매니저 분석, Ready callsite 감사, Direct/ObserveOnly/teardown 항목이 §4 G–I에 반영됨 | 수렴 완료 |
| ReproHarness (scout) | 10개 QA 제안 수렴 — watch MODIFIED/resourceVersion 측정 계약, 상태 전용 wakeup 7종이 §3, §4 J에 반영됨; §3/§4 J/§6 및 judge 교정 반영본 교차 확인 완료 | 합의 확인 (무조건, 블로커 없음) |

§2의 설계 계약은 AtomicityReview와 합의된 상태이며, 계약 변경 시 해당 항목의 기대를 보정한다.
