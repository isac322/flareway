# Flareway 설계 003 — 프로덕션 로깅 기본값과 Helm 로깅 설정(issue #96) 분석·설계·QA

- 작성일: 2026-09-23
- 상태: **구현, 로컬 QA, 최종 회귀 리뷰 완료.** 28개 QA ID 실행. PR CI는 별도 추적.
- 입력: issue #96 본문, `cmd/main.go`·차트·Kustomize 현재 소스, 베이스라인 스모크 실행 결과, 로거 내부 동작 실행 증거, 로그 콜사이트 분류 결과.
- 표기: `[E]` 실행 증거, `[D]` 설계 결정, `[C]` 토론 중 기각·정정된 사항, `[INFERENCE]` 소스 판독·추론(미실행).

---

## 1. 요약 — 핵심 결정

1. **결함**: `cmd/main.go`가 `zap.Options{Development: true}`로 초기화되고, Helm 차트와 Kustomize 매니페스트는 `--zap-*` 인자를 하나도 전달하지 않는다. 표준 설치는 개발 모드(콘솔 인코더 + DEBUG 레벨)로 동작한다 `[E]`.
2. **수정 방향**: 엔트리포인트 기본값을 `Development: false`로 바꾸고(프로덕션: JSON, info, error 스택트레이스), 기존 `--zap-*` 플래그를 차트 `logging` 값 세 개(`development`, `level`, `encoder`)와 Kustomize 명시 인자로 노출한다. 세 표면(standalone·Helm·Kustomize)이 동일한 정책을 렌더한다 `[D]`.
3. **단일 로깅 정책 — controller-runtime 로거 한정**: 엔트리포인트 기본값 전환으로 zap(logr 싱크) 출력은 JSON@info로 통일된다. client-go의 전역 klog 호출과 grpclog는 별도 텍스트 포맷으로 새어 나오는 문서화된 예외로 남는다 — klog를 같은 싱크에 묶는 라우팅(`klog.SetLoggerWithOptions`)은 최종 회귀 리뷰에서 번복되어 제거했다(§5 R2, §10 최종 회귀 리뷰) `[D]→[C]`.
4. **샘플러 수용**: 프로덕션 모드의 zap 샘플러((level,message) 키당 초당 첫 100개 통과, 이후 100번째마다 1개)는 업스트림 의도 동작이므로 유지하고 문서화한다. 비활성화는 `logging.development=true` 또는 정수 level ≥ 2뿐이다(`debug`는 해제하지 못한다) `[D]`.
5. **CI 분기**: e2e 배포 파이프라인은 렌더된 Kustomize 인자를 sed로 `--zap-log-level=debug`로 바꿔 V(1) Cloudflare 요청 로그를 트riage용으로 보존하고, conformance는 출하 기본값 그대로 실행해 실클러스터에서 프로덕션 로깅을 검증한다 `[D]`.
6. **범위 외**: #92 리컨사일 루프, #97 AUD, xDS 어댑터 레벨 재매핑, 로그 콜사이트 레벨 변경, `extraArgs`·`stacktraceLevel`·`timeEncoding` 노출, grpclog 어댑터 `[D]`.

---

## 2. 증거와 그 한계

### 2.1 실행 증거 `[E]`

**베이스라인 스모크**(envtest apiserver 1.35.0 + Flareway CRD + Gateway API standard CRD, 루프백 Cloudflare 스텁, `HTTPS_PROXY` 데드 프록시로 외부 egress 차단, 실제 빌드 바이너리 45초 실행):

| 모드 | 인자 | 총 라인 | JSON | 콘솔 | DEBUG | ERROR |
|---|---|---|---|---|---|---|
| a-default | (없음) | 421 | 0 | 349(+72 스택 연속행) | 58 | 12 |
| b-prod | `--zap-devel=false` | 223 | 223 | 0 | 0 | 18(전부 `"stacktrace"` 필드) |
| c-prod-debug | `--zap-devel=false --zap-log-level=debug` | 306 | 306 | 0 | 84 | 17 |
| d-prod-console | `--zap-devel=false --zap-encoder=console` | 331 | 0 | 223(+108) | 0 | 18 |

- 현재 기본값(a)은 콘솔 + DEBUG다. DEBUG의 대부분은 `internal/cloudflare/client.go:231`의 V(1) "Cloudflare API request completed"(45초에 58행)다.
- `--zap-devel=false` 하나로 issue가 요구하는 형태(100% JSON, info+error, 비JSON 0행)가 나온다.
- 모든 모드에서 stdout은 0바이트 — 전부 stderr다. 모든 모드에서 error 엔트리는 스택트레이스를 가진다(콘솔은 연속행, JSON은 `"stacktrace"` 필드).
- 어떤 모드에서도 klog 텍스트(`I0923 …`)나 grpc 텍스트(`YYYY/MM/DD …`) 라인은 관측되지 않았다 — 단, 이는 해당 경로가 이 워크로드에서 발화하지 않았기 때문이다(§2.3).

**klog 전역 호출 트리거**: `DISABLE_HTTP2=1`(존재 기반 — 비어있지 않은 값이면 `=false`도 발화)을 주면 client-go의 transport 구성(`k8s.io/client-go/transport/cache.go` → `k8s.io/apimachinery/pkg/util/net/http.go:134-136`)이 전역 `klog.Info("HTTP2 has been explicitly disabled")`를 호출한다. 베이스라인 바이너리에서 `I0923 16:01:37.377611   16083 http.go:136] HTTP2 has been explicitly disabled` 텍스트 라인을 실측했다. apiserver 없이도 발화하므로 결정적 트리거로 쓴다.

**로거 내부 동작**(throwaway Go 프로그램으로 실행 검증):

- 샘플러: 동일 (level,message) error 500회를 1초 내에 호출 → 프로덕션 기본 104개 방출(첫 100 + 이후 100번째마다), `--zap-log-level=2`와 `--zap-devel=true`는 500개 전부. 샘플 키는 (level,message)뿐이며 필드는 무시된다. 샘플링 창은 zap level -1..5 — **V(1)(zap -1)도 샘플링 대상**이고, V(2) 이하(zap < -1)만 우회한다 `[C: 라운드2에서 "V(1)은 샘플링 안 됨" 문구 정정]`.
- 플래그 우선순위: `--zap-devel=true`는 콘솔+debug를 그대로 복원하고, `--zap-encoder`/`--zap-log-level`은 development 기본값을 개별로 덮어쓴다. `--zap-log-level=warn`·`=0`·`=-1`은 파싱 오류(exit 2, `invalid log level`), `=INFO`는 소문자화되어 수용, 정수 N>0은 logr V(N)으로 매핑된다. `--zap-time-encoding`은 `nano`가 아니라 `nanos`만 수용한다.
- int8 래핑: `--zap-log-level`은 `zapcore.Level(int8(-N))`으로 매핑 — N=129–255는 양수 레벨로 래핑되어 **모든 로그가 침묵**하고, N=256은 info로 래핑된다. 초기 스키마 상한 128의 근거였다 — 최종 회귀 리뷰에서 상한은 6으로 낮아졌다(§5 R5, §10 최종 회귀 리뷰).
- DPanic: 개발 모드에서는 malformed kv(홀수 개 key-value)가 panic을 일으키고, 프로덕션에서는 `"level":"dpanic"` JSON 라인 후 계속 진행한다 — 기본값 변경은 가용성 개선이기도 하다.
- `klog.SetLogger` 후 전역 `klog.Info/Error`는 JSON으로 라우팅되고, `ContextualLogger(true)`는 로거 없는 ctx의 `FromContext` 폴백도 우리 로거로 보내 `--zap-log-level` 게이팅을 따르게 한다. `klog.Fatal*`은 여전히 exit 255지만 메시지가 `logger.Info`로 방출되는 severity 다운그레이드가 있다(알려진 퀴크). 이 배선은 메카닉 검증용으로만 실행됐고 최종 회귀 리뷰에서 번복되어 제거됐다(§5 R2, §10 최종 회귀 리뷰).
- grpclog 기본값은 ERROR 심각도만 stderr 텍스트로 출력하고 warning/info는 discard한다 — 전역 klog 텍스트 라인과 함께 비JSON 라인이 나올 수 있는 문서화된 예외 경로다.
- xDS(go-control-plane) 어댑터의 도달 가능한 Infof는 `open delta watch`(delta watch 생성마다, Envoy당 타입URL당 요청마다)뿐이며 Info 레벨이 적절한 운영 신호다.

**로그 콜사이트 분류**(cmd/+internal/ 비테스트 Go, 155개 유닛): 실제 로그 사이트 61개(Error 43, Info 14, V(1) 4). sensitive·full-object·malformed kv 플래그는 0건 — 레벨/인코더 변경으로 숨겨지거나 깨지는 사이트가 없다.

**성능 계측**: 100k info + 10k error 라인을 io.Discard에 기록 — prod-json 233 ns/line vs dev-console 735 ns/line. JSON이 라인당 약 3배 저렴하다.

### 2.1.1 실행된 것과 계획된 것의 구분

| 구분 | 항목 |
|---|---|
| **실행 완료** `[E]` | 베이스라인 4+1 모드 캡처, klog 트리거, 샘플러·플래그·DPanic·래핑 throwaway 검증, 콜사이트 분류, redaction 정규식 누출 재현, 성능 계측 |
| **별도 추적** | 최종 head의 PR CI — 첫 head는 필수 체크 전부 녹색 + dispatch된 Cloudflare e2e 성공(§10 최종 회귀 리뷰) |

### 2.2 확인된 회귀와 수정 의무

1. **e2e redaction 정규식이 JSON 로그에서 시크릿을 누출한다** `[E]`: 현재 `.github/workflows/e2e.yaml`의 정규식을 그대로 실행하면 `{"authorization":"Bearer tok"}`는 토큰이 남고, `"api_token":"x y"`/`"x,y"`는 공백·콤마 뒤가 노출된다. 콘솔 포맷에서도 같은 누출이 있었으나, 전환 후 스트림이 100% JSON이 되어 노출이 극대화된다 — **이 PR에서 수정이 의무**다(R7).
2. **스키마 `additionalProperties: false`가 `logging` 키를 차단한다** `[E]`: values.schema.json 수정과 values.yaml 추가는 원자적으로 커밋되어야 한다.
3. **최종 회귀 리뷰에서 구현 회귀 2건이 확인되어 수정됐다** `[E]`: klog 라우팅이 bare-context client-go V(8) 응답 본문 로깅(Secret `tls.key` 포함)을 새로 열었고(SEC-01), klog Warning/Fatal을 info로 강등시켰다 — 둘 다 라우팅 제거로 해소하고 스키마 정수 상한을 6으로 낮췄다(§5 R2/R5, §10 최종 회귀 리뷰).

### 2.3 증거의 한계

- 베이스라인에서 klog/grpc 텍스트 라인이 관측되지 않은 것은 "발화 경로가 없다"가 아니라 "이 워크로드에서 발화하지 않았다"다. 전역 klog는 `DISABLE_HTTP2` 트리거로 별도 입증했다.
- 리더 일렉션 획득 라인은 out-of-cluster에서 재현 불가(namespace 파일 부재로 즉시 종료) — 실패 경로만 두 인코더로 캡처했다. 인클러스터 `leaderelection` 라인의 JSON 라우팅은 contextual 경로(`klog.FromContext` → ctrl 주입 로거)라는 `[INFERENCE]`였으나 Kind 스테이지(QA-22)가 실측으로 확인했다 — klog 라우팅 없이도 JSON으로 나온다.
- 샘플러의 실운용 드롭은 이 볼륨(~5 lines/s)에서 관측되지 않았다 — 합성 500회 버스트로만 입증했다.
- 라이브 Cloudflare/실배포 관측은 없다. 모든 증거는 envtest·throwaway·렌더 기반이다.

---

## 3. 근본 원인 분석

### 3.1 발생 — 왜 개발 기본값이 배포까지 도달했는가

1. `cmd/main.go:147-153`이 `zap.Options{Development: true}`로 하드코딩하고 `opts.BindFlags`로 플래그만 바인딩한다 — 플래그는 존재하지만 기본값이 개발 모드다.
2. 차트 `templates/deployment.yaml`과 `config/manager/manager.yaml`은 `--zap-*` 인자를 전달하지 않으므로, 두 패키징 표면 모두 바이너리 기본값을 그대로 상속한다.
3. 더 깊은 원인: **배포에서 보이는 단일 로깅 정책이 없다.** zap(logr 싱크), klog 전역(client-go), grpclog(gRPC)가 각자의 포맷과 게이팅을 가진 세 싱크다. contextual klog 경로만 우리 로거를 재사용하고, 전역 klog 호출은 `I0923 …` 텍스트로 새어 나온다. 최종 설계는 controller-runtime 로거에만 단일 정책을 적용하고 전역 klog·grpclog 텍스트 라인은 문서화된 예외로 남긴다 — klog를 zap에 라우팅하는 접근은 최종 회귀 리뷰에서 번복됐다(§5 R2, §10 최종 회귀 리뷰).
4. 개발 모드는 인코더/레벨 외에도 숨은 의미를 가진다: 샘플러 없음, malformed kv에서 DPanic panic(크래시 위험), KubeAwareEncoder 전체 오브젝트 덤프, Warn 스택트레이스 레벨.

### 3.2 유출 — 왜 기존 방어가 못 막았는가

- `make verify-runtime-defaults`는 env 기본값(GOMEMLIMIT/GODEBUG)만 검사하고 args는 검사하지 않는다 — 패키징 표면의 로깅 정책을 단언하는 게이트가 없었다.
- 어떤 CI 잡이나 테스트도 controller.log를 파싱·단언하지 않는다(아티팩트 덤프 + redaction뿐) — 포맷 회귀를 잡는 관측 지점이 없었다.

### 3.3 억제 — 무엇이 피해를 제한했는가

- 플래그 자체는 완전히 동작하므로 운영자가 `--zap-devel=false`를 알면 수동으로 복구 가능했다 — issue도 "설정 불가"가 아니라 "기본값/설정 표면" 문제로 분류한다.
- 민감정보·전체 오브젝트·malformed 콜사이트가 0건이라 개발 모드 노출의 직접 피해(시크릿 누출, 크래시)는 잠재적이었다.

---

## 4. 대안 비교

| 대안 | 판정 | 근거 |
|---|---|---|
| **A. 채택안**: 바이너리 기본값 prod 전환 + 차트 `logging` 3키 + Kustomize 명시 인자 + 문서 | **채택** `[D]` | issue의 구조적 개선 요구(엔트리포인트 기본값 + 기존 zap 컨트롤 노출 + 세 표면 일관성)를 정확히 충족. 새 로거/추상화 없음. klog 라우팅은 최종 회귀 리뷰에서 제외(§5 R2, §10 최종 회귀 리뷰) |
| B. 차트/Kustomize에만 `--zap-devel=false` 추가(바이너리 기본값 유지) | 기각 `[C]` | standalone 바이너리가 개발 모드로 남아 표면 간 불일치 — issue가 요구하는 "엔트리포인트의 일관된 프로덕션 기본값"에 실패 |
| C. 샘플러 제거용 커스텀 zap core | 기각 `[C]` | `zap.New`/`NewRaw`를 우회해 인코더+싱크+레벨+스택트레이스 배선을 재소유해야 하고 `--zap-*` 플래그 의미를 잃는다. 업스트림 의도 동작을 끄기 위한 비용 대비 이득 없음 — 문서화로 처리 |
| D. grpclog `SetLoggerV2` logr 어댑터 | 기각 `[C]` | ~30행의 새 어댑터 = 새 로깅 추상화. 기본 grpclog는 ERROR 전용·희소 라인이라 문서화된 예외로 충분. `GRPC_GO_LOG_*` env를 차트에 두는 것도 기각(제2의 발산 설정 표면) |
| E. xDS 어댑터 레벨 재매핑(Infof→V(1)) | 기각 `[C]` | `open delta watch`는 "Envoy X가 타입 Y를 구독/ACK"라는 운영자가 Info에서 원하는 신호. V(1)로 내리면 xDS 라이프사이클 가시성이 debug 플래그 뒤로 숨는다 |
| F. CI 전체를 debug로 전환 | 기각 `[C]` | 출하 기본값을 아무 잡도 행사하지 않게 된다. e2e만 debug overlay(V(1) 트riage 스트림 보존), conformance는 출하 기본값 유지로 분기 채택 |
| G. `logging.extraArgs` / stacktraceLevel·timeEncoding 노출 | 기각 `[C]` | 범위 확장. 세 키만 노출하고 나머지는 문서로 명시("세 개만 노출됨") — 필요하면 후속 issue |
| H. `required` 제거(스키마 완화) | 기각 `[C]` | `--set logging=null`/`logging.level=null`이 스키마 오류가 아니라 템플릿 nil-pointer로 실패하는 것을 실행 확인 — `required`는 load-bearing이다. **QA에서 번복 `[C]`**: 헬퍼 `dig` 폴백으로 nil-pointer 원인을 제거하고 `logging` 내부 `required`를 제거(§5 R5, §7.1 (a)) |

---

## 5. 최종 설계 `[D]` (R1–R9)

- **R1** `cmd/main.go`: `zap.Options{Development: false}`(JSON, info, error 스택트레이스). `opts.BindFlags` 유지.
- **R2** `cmd/main.go`: `ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))`. `FlushLogger`·`klog.InitFlags` 없음(`-v`는 비등록 상태로 inert 유지). **번복 `[C]`(최종 회귀 리뷰)**: 초기 설계의 `klog.SetLoggerWithOptions(logger, klog.ContextualLogger(true))` 라우팅과 klog/v2 direct 승격은 제거됐다 — (a) `ContextualLogger(true)`가 로거 없는 ctx의 `klog.FromContext` 폴백을 우리 로거로 돌려 client-go의 V(8) 요청/응답 본문 로깅이 bare context에서도 발화하게 됐고, 시작 경로 `pki.EnsureCA(context.Background(), …)`의 Secret GET에서 `tls.key` 본문이 `--zap-log-level≥8`에 방출됨을 합성 Secret으로 재현(구 바이너리는 전 레벨 침묵, SEC-01); (b) 라우팅된 klog는 `Warning`/`Fatal`을 `logger.Info`로 방출해 severity를 잃었다(`HTTP2_READ_IDLE_TIMEOUT_SECONDS=invalid`로 재현). 제거 후 klog 출력은 베이스라인과 바이트 단위 동일(QA-07/QA-08)하고, 희소한 client-go klog 텍스트 라인은 grpclog ERROR 라인과 같은 문서화된 예외다. `k8s.io/klog/v2`는 indirect 의존으로 남는다.
- **R3** grpclog 어댑터 없음. ERROR 심각도 텍스트 라인은 차트 README Logging 섹션과 QA 스트림 순수성 검사의 문서화된 예외. 전역 klog 텍스트 라인도 같은 예외다(R2 번복).
- **R4** 업스트림 샘플러 유지 + 정확한 문구로 문서화: 키는 (level,message)뿐, 초당 첫 100개 통과 후 100번째마다 1개, **zap level -1..5가 샘플링 대상이므로 debug/V(1)·info·error 모두 샘플링되고 V(N≥2)만 우회**, error는 완전 억제되지 않고 열화됨. 해제는 `logging.development=true` 또는 정수 level ≥ 2(`debug`로는 해제 불가).
- **R5** 차트 `logging: {development: false, level: info, encoder: json}`. 스키마: object + `additionalProperties: false` + `required` 3키 전부(null → nil-pointer 대신 스키마 오류). `level`은 `oneOf [enum debug|info|error|panic, integer 1..6]`(문자열 숫자 거부; 상한 6 — 정수 level ≥8은 client-go V(8) 요청/응답 본문 로깅을 켜므로 차단, §10 최종 회귀 리뷰). `encoder`는 enum json|console. `flareway.loggingArgs` 헬퍼가 세 인자를 **무조건** args 리스트 **끝**에 렌더(index-patch 안전). `extraArgs`·`stacktraceLevel`·`timeEncoding` 없음. 문서는 "명시 level/encoder가 development 기본값을 덮어쓰므로 `development=true` 단독은 JSON/info + dev 의미(샘플러 해제, Warn 스택트레이스, 전체 오브젝트, DPanic panic)"와 "정확한 이전 동작 = development=true + level=debug + encoder=console"을 명시.
  - **R5 정정 `[C]`(QA-16/17/24/25)**: `required` 근거(null → 스키마 오류)는 폐기한다. 스키마는 `additionalProperties: false`·`level` oneOf·`encoder` enum만 유지하고 `logging` 내부 `required`를 제거했다. `flareway.loggingArgs`는 `.Values.logging | default dict`에 `dig "development" false`·`dig "level" "info"`·`dig "encoder" "json"`로 키별 폴백한다(`dig`는 명시적 `false`를 보존). 그 결과 `logging` 키가 없는 구 릴리스의 `helm upgrade --reuse-values`, `--set logging=null`, 부분 맵(`--set logging.level=debug`만) 모두 기본값으로 렌더된다.
  - **R5 정정 2 `[C]`(최종 회귀 리뷰)**: 정수 level 상한을 128에서 6으로 낮췄다. 요청 ctx에 로거를 태운 client-go 호출은 raw `--zap-log-level≥8`에서 API 응답 본문(Secret 데이터 포함)을 덤프한다 — 신·구 바이너리 동일한 선존 동작이지만 차트가 8–128을 허용하면 문서화된 경로로 노출을 켤 수 있었다. level 6까지는 본문 로깅이 없음을 실행 확인했고, 문서는 raw 플래그 ≥8의 위험을 경고한다(§10 최종 회귀 리뷰).
- **R6** `config/manager/manager.yaml`에 동일 세 인자를 기존 args 뒤에 추가. `make verify-runtime-defaults`를 확장해 manager 컨테이너 args로 스코프한 검사: 두 표면 렌더가 `--zap-devel=false`·`--zap-log-level=info`·`--zap-encoder=json`을 각각 정확히 1회 포함하고 다른 `--zap-devel`/`--zap-log-level`/`--zap-encoder`가 없을 것 + `--set logging.development=true --set logging.level=debug --set logging.encoder=console` 와이어링 렌더 1건. 스키마 네거티브·변이 네거티브 컨트롤은 영구 게이트가 아니라 throwaway QA.
- **R7** e2e.yaml 배포 파이프라인은 렌더된 Kustomize의 manager args에서 `--zap-log-level=info`를 `=debug`로 sed 치환(V(1) 트riage 스트림 보존)하고 치환 성공을 grep으로 단언해 조용한 실패를 막는다. conformance(`hack/run-conformance.sh`)는 출하 기본값 유지. e2e redaction 스크립트는 이 PR에서 수정: JSON `"key":"value"`를 값의 공백·콤마·이스케이프 따옴표까지 완전히 redact하고 Bearer 패스가 key 패스에 무력화되지 않게 한다.
  - **R7 정정 `[C]`(QA-21)**: 초기 구현은 이스케이프된 중첩 JSON(`"error":"{\"api_token\":\"…\"}"`)에서 키 뒤 `\"`를 구분자로 인식하지 못해 비밀이 남았고, 값 전체를 `"[REDACTED]"`로 바꾸면서 따옴표 없는 값·무해 라인을 유효하지 않은 JSON으로 만들었다. 수정: 구분자에 선택적 이스케이프 따옴표(`(?:\\?")?`)를 허용하고, 값은 `\"…\"`/`"…"`/따옴표 없음 형태별로 같은 따옴표 스타일을 유지해 마스킹한다. Bearer 패스는 key 패스보다 먼저 실행한다.
  - **R7 정정 2 `[C]`(최종 회귀 리뷰)**: 따옴표 없는 값의 대안이 따옴표가 아닌 위치의 백슬래시(`\\(?!")`)와 종결자가 아닌 위치의 따옴표(`"(?![\s,}]|\Z)`)를 소비하도록 보강했다 — 원래 regex가 redact하던 입력을 새 regex가 놓치는 경우가 없음을 코퍼스 대조로 확인(커버리지 parity 회복, §10 최종 회귀 리뷰).
- **R8** 문서: 차트 README(값 테이블 행 + Logging 섹션: 매핑 표, 샘플러, klog/grpc 텍스트 예외, 복원 레시피, 세 키만 노출, raw `--zap-log-level≥8`의 Secret 본문 로깅 경고), docs/operations/upgrade.md(마이그레이션: console→JSON, debug→info, 연속행 스택트레이스→`"stacktrace"` 필드, 샘플러, klog 텍스트 예외(포맷 불변), Helm·Kustomize 복원 레시피, 로컬 `go run ./cmd --zap-devel=true`), docs/operations/troubleshooting.md(debug 활성화: Helm `--set`, Kustomize JSON6902 append 또는 전체 args 편집 — strategic-merge args 치환 금지, 라이브 deploy에 `kubectl patch`, `logging.level=1`로 요청당 라인, raw 플래그 ≥8 경고, klog/grpc 텍스트 예외와 `jq fromjson?` 필터링), bug_report.yml 힌트. `warn`은 절대 문서화하지 않는다(플래그가 거부).
- **R9** 범위 외: #92, #97, xDS 어댑터 재매핑, 콜사이트 레벨 변경.

---

## 6. 구현 대상 파일

1. `cmd/main.go` — `Development: false` (R1)
2. `charts/flareway/values.yaml` — `logging` 블록 (R5)
3. `charts/flareway/values.schema.json` — `logging` 스키마 (R5, values.yaml과 원자적 커밋)
4. `charts/flareway/templates/_helpers.tpl` — `flareway.loggingArgs` (R5)
5. `charts/flareway/templates/deployment.yaml` — args 끝에 include (R5)
6. `config/manager/manager.yaml` — 세 인자 추가 (R6)
7. `Makefile` — `verify-runtime-defaults` 확장 (R6)
8. `.github/workflows/e2e.yaml` — debug sed + 치환 단언 + redaction 스크립트 수정 (R7)
9. `charts/flareway/README.md`, `docs/operations/upgrade.md`, `docs/operations/troubleshooting.md`, `.github/ISSUE_TEMPLATE/bug_report.yml` (R8)

---

## 7. QA 목록

티어: **throwaway** = 일회성 스모크(실행 후 폐기), **permanent** = `verify-runtime-defaults` 내 상주 게이트, **doc review** = 문서 리뷰, **gate/CI** = 머지 게이트. 결과 열은 구현 후 실행 결과이며, QA에서 발견·수정된 결함은 §7.1에 정리한다.

| ID | 방어하는 주장/위험 | 절차 | 통과 기준(관측 가능) | 차단? | 티어 | 결과 |
|---|---|---|---|---|---|---|
| QA-01 | 기본 배포 = JSON@info, error는 stacktrace와 함께 가시; standalone 기본값 == 차트 정책; #92 error 비은폐 | 하네스 §8.1 `default` 모드: zap 인자 없이 45초 | stderr 전 라인 JSON 파싱; `"level":"info"` ≥1; `"level":"debug"`/`"Level(-N)"` 0; `"level":"error"` `Reconciler error` ≥1 + 비어있지 않은 `"stacktrace"`; `"ts"` RFC3339; stdout 0바이트 | 없음 | throwaway | PASS — default: JSON 216/216, info 205, debug 0, `Level(-N)` 0; `Reconciler error` 11건 모두 `stacktrace` 보유; `ts` RFC3339; stdout 0 B |
| QA-02 | 명시 debug 옵트인이 debug를 방출 | `debug` 모드: `--zap-log-level=debug` | `"level":"debug"` ≥1(`logger:"cloudflare"`, `msg:"Cloudflare API request completed"`); 전부 JSON | 없음 | throwaway | PASS — debug: JSON 293/293, `logger:"cloudflare"` `Cloudflare API request completed` debug 73줄 |
| QA-03 | 명시 encoder 오버라이드 유효 | `console` 모드: `--zap-encoder=console` | 탭 구분 콘솔 라인; JSON 0; `DEBUG` 0; error 여전히 방출 | 없음 | throwaway | PASS — console: 탭 구분 220줄, JSON 0, `DEBUG` 0; `ERROR` 15 + 스택 연속행 90 |
| QA-04 | 이전 동작을 그대로 복원 가능(복원 레시피 동작) | `devel` 모드: `--zap-devel=true --zap-log-level=debug --zap-encoder=console` | 콘솔 + `DEBUG` 라인; error 스택트레이스 연속행 — 베이스라인 모드a 형태와 일치 | 없음 | throwaway | PASS — devel: 콘솔 368줄, `DEBUG` 74, JSON 0, error 스택 연속행 90 — 베이스라인 모드 a와 동일 형태 |
| QA-05 | `development=true` 단독은 dev 콘솔+debug를 복원하지 않음(UX 함정, R5 문서 요건) | `devonly` 모드: `--zap-devel=true --zap-log-level=info --zap-encoder=json`(`logging.development=true`가 렌더하는 그대로) | JSON@info: `DEBUG` 0, 콘솔 0 — development는 샘플러/스택트레이스/인코더 상세도만 토글함을 입증 | 없음 | throwaway | PASS — devonly: JSON 294/294, `DEBUG` 0, 콘솔 0, info 279 |
| QA-06 | 정수 level = logr V(N) | `v1` 모드: `--zap-log-level=1` | `"level":"Level(-1)"` 라인 방출(V(1) API 라인); `"Level(-2)"` 없음; 전부 JSON | 없음 | throwaway | FAIL(기준 오류, 제품 정상) → 기준 정정 후 PASS `[C]` — `--zap-log-level=1`: JSON 294/294, V(1) 74줄이 `"level":"debug"`로 렌더(zap `Level(-1)`==Debug), `Level(-2)` 0; §7.1 (c) |
| QA-07 | R2 번복 후: 전역 klog 라인이 베이스라인과 동일한 텍스트 포맷으로 방출 | `klog` 모드: `DISABLE_HTTP2=1`(존재 기반 — `=false`도 발화; client transport 구성 시 발화) + 유효 kubeconfig(데드 포트 가능). 주의: 이 모드는 실행 내내 클라이언트 HTTP/2를 끈다 — 로그 포맷 스모크로는 허용, 문서화 | `I\d{4} … http.go:136] HTTP2 has been explicitly disabled` 텍스트 라인이 transport 구성당 정확히 1회, 타임스탬프·pid 정규화 후 베이스라인과 바이트 단위 동일; 나머지 라인 전부 JSON | 없음 | throwaway | PASS(기준 정정) `[C]` — `klog` 모드: 221줄 중 220 JSON + `I0923 … http.go:136] HTTP2 has been explicitly disabled` 정확히 1줄, 정규화 후 베이스라인 라인과 동일; §7.1 (c) |
| QA-08 | R2 번복 후: klog Warning severity가 베이스라인과 동일(info 강등 없음) | `idle` 모드: env `HTTP2_READ_IDLE_TIMEOUT_SECONDS=invalid`(client-go transport 구성 경고 발화) | `W\d{4} … http.go:154] Illegal HTTP2_READ_IDLE_TIMEOUT_SECONDS(…)` 텍스트 라인이 베이스라인과 동일 severity·포맷으로 1회; JSON info 강등 0 | 없음 | throwaway | PASS(기준 정정) `[C]` — `idle` 모드: `W0923 … http.go:154] Illegal HTTP2_READ_IDLE_TIMEOUT_SECONDS("invalid"): …` 1줄, 정규화 후 베이스라인과 동일; 나머지 212줄 전부 JSON; §7.1 (c) |
| QA-09 | 플래그 파싱 계약: `--help` 동작; 바이너리가 `warn`/`0`/`-1` 거부(스키마 minimum은 바이너리 거부를 미러) | `/tmp/manager --help`; `--zap-log-level=warn`; `=0`; `=-1` | `--help` exit 0 + zap 플래그 나열; `warn`/`0`/`-1` 각각 exit 2 + `invalid log level "<v>"` | 없음 | throwaway(`--help`는 verify-container 게이트도 커버) | PASS — `--help` exit 0 + zap 플래그 5종 나열; `warn`/`0`/`-1` 각각 exit 2 + `invalid log level "<v>"` |
| QA-10 | DPanic이 더 이상 매니저를 크래시하지 않음(가용성 개선, 회귀 아님) | throwaway Go: prod opts vs dev opts에서 `logger.Info("m", "orphan-key")`(홀수 kv) | prod: `"level":"dpanic"` JSON 후 계속; dev: panic | 없음 | throwaway | PASS — prod: `"level":"dpanic"` JSON 후 계속 실행, exit 0; dev: `DPANIC` 후 panic, exit 2 |
| QA-11 | 스트림 순수성: 문서화된 klog/grpc 텍스트 예외 외 비JSON 0(R3) | 모든 캡처 stderr + Kind pod 로그에 공통 단언 | klog 텍스트(`^[IWEF]\d{4} `)는 문서화된 예외 라인(QA-07/QA-08이 요구하는 것)만 허용, grpc 텍스트(`^\d{4}/\d{2}/\d{2} `)는 `YYYY/MM/DD … ERROR:` 형태만 허용, stdout 0바이트 | 없음 | throwaway(하네스 내장) | PASS — envtest 전 모드 stdout 0 B, grpc 텍스트 0, klog 텍스트는 `klog`/`idle` 모드의 예외 라인 각 1줄뿐; Kind pod 155/155 JSON(단, `kubectl logs`는 stdout/stderr 병합) |
| QA-12 | 기본 Helm 렌더가 정확히 프로덕션 인자를 가짐 | `helm template flareway charts/flareway -n flareway-system --include-crds`; `containers[name=manager].args` 추출 | `--zap-devel=false`·`--zap-log-level=info`·`--zap-encoder=json` 각 1회; 다른 `--zap-*` 없음 | 없음 | throwaway(QA-19로 영구 승격) | PASS — manager args에 `--zap-devel=false`·`--zap-log-level=info`·`--zap-encoder=json` 각 1회, 다른 `--zap-*` 0 |
| QA-13 | 렌더된 인자가 설정값을 반영하고 바이너리가 수용(issue AC) | `helm template` 매트릭스: development ∈ {true,false} × level ∈ {debug,info,error,panic,1,2,6} × encoder ∈ {json,console}; 각 렌더 인자를 `go run -mod=readonly ./cmd <args> --help`에 투입. values 파일 렌더 추가: `{development: true, level: debug, encoder: console}` → 매핑 인자; `level: "2"`(따옴표) → 스키마 거부 | 각 렌더가 정확한 `--zap-*` 삼중으로 매핑; 모든 조합 exit 0; values 파일 int `level: 2` 수용, `"2"` 거부 | 없음 | throwaway | PASS — 28/28 조합(dev{t,f}×level{debug,info,error,panic,1,2,6}×enc{json,console})이 정확한 세 인자 렌더 + 바이너리 `--help` exit 0(대조군 `warn` exit 2); values 파일 `level: 2`→`=2`, `level: 6`→`=6`, `level: 2.0`→`=2`, `"2"`→스키마 거부 |
| QA-14 | Kustomize 렌더가 Helm과 동등(issue AC: 표면 일치) | `bin/kustomize build config/default`; manager 컨테이너 args 추출 | QA-12와 동일 세 zap 인자; `--leader-elect`·`--health-probe-bind-address`·`--metrics-bind-address` 유지 | 없음 | throwaway(QA-19로 영구 승격) | PASS — Kustomize manager args가 QA-12와 동일 세 인자, `--leader-elect`·probe·metrics 인자 유지 |
| QA-15 | 스키마가 무효 입력을 명확한 오류로 거부(enum\|int 1..6) | `helm template` 각각: `level=warn`/`=0`/`=-1`/`=7`/`=128`/`=129`/`=INFO`/`=2.5`, `--set-string level=2`, `encoder=yaml`/`=JSON`, `development=maybe`/`=1`, `logging.bogus=1`; 추가로 `level=2.0`(기록용) | 무효 입력 전부 비영 종료 + `values don't meet the specifications of the schema(s)` + 경로별 사유; Deployment 미렌더; 경계: `=6` 수용, `=7`·`=128` 거부 | 없음 | throwaway | PASS(기준 정정) `[C]` — 무효 입력 전부 exit 1 + 경로별 사유, Deployment 미렌더; `=6` 수용, `=7`·`=128` 거부(`maximum: got 7, want 6`); `--set level=2.0`은 Helm 4가 문자열로 강제해 거부, values 파일 `2.0`은 `=2` 렌더; §7.1 (c) |
| QA-16 | null/누락 멤버 오버라이드가 템플릿 nil-pointer가 아니라 스키마로 실패(`required` 유지 근거) | `helm template --set logging.level=null`; `--set logging.encoder=null`; `--set logging=null` | 각각 경로를 명시한 스키마 `required`/`type` 오류 — `nil pointer evaluating interface {}`가 아님 | 없음 | throwaway | FAIL → 수정 후 PASS(새 기준) `[C]` — 수정 전 `--set logging=null`이 스키마 통과 후 nil-pointer; 수정 후 `logging=null`(`--set`·`--set-json`)·각 키 `=null` 모두 exit 0 + 기본값 렌더, 부분 null은 해당 키만 기본값; §7.1 (a) |
| QA-17 | 업그레이드 경로: `logging` 키 없는 구 values 파일도 렌더; `--reuse-values` 업그레이드가 인자 보존 | `helm template flareway charts/flareway -f old-values.yaml`(`logging` 없음); Kind 스테이지 실행 시 `helm upgrade f96 charts/flareway -n flareway-system --reuse-values` 추가 | 렌더 성공 + 프로덕션 zap 기본 인자; `logging` 부재 스키마 오류 없음; Kind 업그레이드 후 인자 유지 | 없음(Kind 부분 선택 — 차단 시 render-only로 기록) | throwaway | FAIL → 수정 후 PASS `[C]` — 수정 전 Kind `--reuse-values`가 `nil pointer evaluating interface {}.development`; 수정 후 렌더 exit 0 + 프로덕션 세 인자, Kind(c7f2b9e 차트→HEAD) 롤아웃 OK, 155/155 JSON; §7.1 (a) |
| QA-18 | 인자 순서 안전: logging 인자가 끝에 추가; 기존 인덱스 안정(R5/R6) | `bin/kustomize build`와 `helm template`의 args 순서 검사; `manager_metrics_patch.yaml`(args/0 삽입) 결과 유효성 | 두 표면에서 zap 인자가 기존 인자 뒤; `kustomize build` 성공; metrics 패치 출력 유효 | 없음 | throwaway | PASS — 두 표면에서 zap 세 인자가 args 마지막 3개; `kustomize build` 성공, metrics `args/0` 패치 유효 |
| QA-19 | 영구 게이트: `verify-runtime-defaults`가 두 표면의 manager 컨테이너 args를 스코프해 강제, 비공백 입증(R6) | `make verify-runtime-defaults`; 스크래치 사본 변이: (a) `--zap-encoder=json` 제거 → FAIL; (b) zap 인자가 다른 컨테이너에만 → FAIL; (c) `command:`에만 → FAIL; + 와이어링 렌더 `--set development=true,level=debug,encoder=console` | 실트리 exit 0; 각 변이 비영 종료; 와이어링 렌더가 `--zap-devel=true --zap-log-level=debug --zap-encoder=console` 표시 | 없음 | permanent(Makefile/CI) + throwaway 변이 | PASS — `make verify-runtime-defaults` exit 0; 변이 (a)(b)(c)(d) 각각 exit 1 + 의도한 메시지, (e) 비변이 알파벳 정렬 항목 exit 0 |
| QA-20 | R7: e2e 배포 파이프라인이 debug 주입; conformance는 출하 기본값; 치환 실패 시 시끄럽게 실패 | PR의 실제 e2e zap sed를 image sed 뒤에 적용: `bin/kustomize build config/default \| sed "<image sed>" \| sed "<PR zap sed>"`; `containers[name=manager].args`에서 `--zap-log-level=debug` 존재 AND `--zap-log-level=info` 부재 단언; `hack/run-conformance.sh` 렌더 파이프라인은 debug 인자 부재 확인. e2e.yaml 자체가 sed 후 `grep -q -- '--zap-log-level=debug'`로 치환 성공을 단언해야 함 | e2e 렌더 manager args에 `=debug` 있고 `=info` 없음; conformance 렌더는 세 prod 인자만; 워크플로우 grep 단언 존재 | 없음 | throwaway + CI 아티팩트 리뷰 | PASS — e2e.yaml 파이프라인 실행: `=debug` 존재·`=info` 부재; `=info` 부재 렌더에서 `::error::` + exit 1; conformance는 이미지 sed만(기본값 유지) |
| QA-21 | R7: 수정된 redaction 스크립트가 JSON/콘솔 어떤 입력도 누출하지 않음 | PR의 교체 redaction 블록에 투입: `{"api_token":"x y"}`, `{"api_token":"x,y"}`, `{"authorization":"Bearer tok"}`, `{"client_secret":"a\"b"}`, `{"aud":"v"}`, 콘솔 `{"api_token": "v"}`, klog `api_token=v`, + `aud` 유사 부분문자열을 가진 무해 라인 | 어떤 입력도 시크릿 부분문자열이 남지 않음; Bearer 패스가 key 패스에 무력화되지 않음; 무해 라인 무수정(과잉 redaction 검사); redact된 JSON이 파싱 가능하거나 맹글링이 문서화됨 | 없음 — 아티팩트 안전 주장을 차단 | throwaway(스크립트 수정은 PR에 포함) | FAIL → 수정 후 PASS `[C]` — 수정 전 이스케이프된 중첩 JSON `api_token` 누출 + 무해 라인 JSON 파손; 수정 후 문서 입력 23/23 redact·유효 JSON 유지; 최종 regex는 원래 regex가 redact한 입력을 하나도 놓치지 않음(코퍼스 대조 0 회귀); 잔여 누출은 선존 구조적 공백(§9) → §7.1 (b) |
| QA-22 | 렌더된 차트 인자가 바이너리를 구동함을 end-to-end 입증; 인클러스터 리더 일렉션 로깅 | §8.2 Kind 스테이지: `make kind`, `docker build -t flareway:dev`, `kind load`, `helm install --set image.tag=dev --set image.pullPolicy=Never`, `rollout status`, `kubectl logs`; 선택적 `--set logging.level=debug` 재설치 | Pod Ready; pod 로그 전부 JSON; `leaderelection`/리스 획득 라인이 JSON으로 존재; `kubectl get deploy -o jsonpath args`에 세 zap 인자; debug 설치는 `"level":"debug"` 라인 방출 | soft — docker + kindest/node 풀 필요; 차단 시 QA-01/12/13 + 베이스라인 소견8(contextual 경로)로 대체 기록 | throwaway | PASS — Kind: 롤아웃 OK, 로그 155/155 JSON, `leaderelection` 라인 JSON(klog 라우팅 없이도 contextual 경로로 JSON — 실측), args 세 인자; `--reuse-values --set logging.level=debug` 후 debug 4줄·전부 JSON — `logger:"cloudflare"` V(1) 요청 라인 3(인클러스터 Cloudflare 스텁으로 유도) + `logger:"events"` V(1) 1 |
| QA-23 | 샘플러 동작이 문서화된 opt-out과 일치(R4 정정 문구) | 이미 실행됨(§2.1: prod 기본 104/500; level=2와 devel은 500). 로거 구성이 바뀌면 throwaway probe 재실행; 문구는 QA-24로 검증 | prod 기본은 드롭(~104/500); `level=debug`도 여전히 샘플링(V(1)은 -1..5 창 안); `level=2`·`development=true`는 500 전부 | 없음 | throwaway(실행됨; 조건부 재실행) | PASS — error 500회: prod 104/500, `debug` 104/500(샘플링 유지), `level=2` 500/500, `development=true` 500/500 |
| QA-24 | 문서 내용 리뷰: R8 요구 주제 전부 존재·정확 | 차트 README, upgrade.md, troubleshooting.md, bug_report.yml diff 판독 | README: 값 행 + Logging 섹션(매핑 표, 샘플러 정확 문구 — V(1)도 샘플링 대상 포함, klog/grpc 텍스트 예외, 복원 레시피, 세 키만 노출 명시, raw `--zap-log-level≥8` Secret 본문 경고). upgrade.md: console→JSON, debug→info, 연속행→`"stacktrace"` 필드, 샘플러, klog 텍스트 예외(포맷 불변), Helm·Kustomize 복원 레시피, `go run ./cmd --zap-devel=true`. troubleshooting.md: Helm `--set`, Kustomize JSON6902 append 또는 전체 args 편집(strategic-merge args 치환 금지), 라이브 deploy `kubectl patch`, `logging.level=1`, raw 플래그 ≥8 경고, `jq fromjson?` 예시. bug_report.yml: 파싱 가능 + 실존 표면 참조. `warn` 미문서화 | 없음 | doc review | FAIL → 수정 후 PASS `[C]` — 필수 주제 전부 존재·정확; troubleshooting.md Helm debug 레시피만 구 릴리스에서 실패했으나 차트 수정 후 레시피 그대로 성공; `jq -cR 'fromjson? \| select(.level=="error")'`가 JSON+klog+grpc 혼합 스트림에서 error 라인만 통과함을 실행 확인; §7.1 (a) |
| QA-25 | 문서화된 모든 로깅 명령이 그대로 동작 — 라이브 `kubectl patch` 레시피 포함 | 실행: README `--set` 예시; upgrade.md 복원 values 블록; troubleshooting.md Helm `--set logging.level=debug`와 Kustomize JSON6902/전체 args 패치를 스크래치 overlay에 그대로 적용. Kind 스테이지(QA-22)에서 문서화된 `kubectl patch`를 라이브 deployment에 그대로 실행 | 각 `helm template`/`kustomize build` 성공 + 문서화된 인자 렌더; Kustomize 패치는 debug 인자 유효 + `--leader-elect`/metrics/zap 기본 유지(교체 아닌 추가); `kubectl patch`: debug 인자 추가(args 비교체), rollout 성공, pod 로그에 `"level":"debug"`; 문서의 출력 형식 주장이 QA-01..05 관측과 일치. Kind 차단 시 patch 명령은 reviewed-not-executed로 기록 | soft(Kind 부분) | doc review + throwaway | FAIL → 수정 후 PASS `[C]` — `kubectl patch` 롤아웃 + debug 4줄(`logger:"cloudflare"` 3), JSON6902 overlay 롤아웃 + debug 4줄; Helm `--reuse-values --set logging.level=debug`는 수정 전 스키마 거부, 수정 후 구 차트 릴리스에서 롤아웃 + debug 2줄(`logger:"cloudflare"` 포함) |
| QA-26 | 전체 게이트 목록 녹색 | §8.4: `make lint-fix`(이후 `git status` 클린), `make test`, `make verify-generated`, `make verify-artifacts`, `make verify-container`, `make chart`; `go mod tidy && git diff --exit-code go.mod go.sum` | 전부 exit 0; `verify-generated` 후 워크트리 클린; `dist/flareway-*.tgz` 생성; go.mod diff 클린 + klog가 indirect 유지 | 없음 | gate | PASS — `make lint-fix` 0 issues, `make test` 전부 ok, `verify-generated` 커밋 후 클린, `verify-artifacts`·`verify-container` ok, `make chart` ok, `go mod tidy` 클린 |
| QA-27 | PR의 CI 체크 기대치 | push 후 `gh pr checks` | `Generation diff`, `Lint`, `Unit and envtest`, `Envoy component tests`, `Schema, build, Helm, and Kustomize`, `Container build and runtime`, `GatewayHTTP conformance` 녹색; `e2e` 라벨 적용 시 `Cloudflare edge contracts`(권장 — debug overlay + redaction 수정을 행사) | 없음 | CI | PASS — 첫 head의 PR CI 필수 체크 전부 녹색 + PR 브랜치에 dispatch된 Cloudflare e2e 성공(§10 최종 회귀 리뷰); 최종 head의 CI는 별도 추적 |
| QA-28 | SEC-01 재증명: klog 라우팅 제거 후 bare-context Secret 본문이 전 레벨에서 침묵 | throwaway Go: 현재 로거 구성(`ctrl.SetLogger(zap.New(UseFlagOptions))`, klog 라우팅 없음)으로 loopback apiserver에 protobuf/JSON Secret GET — `pki.EnsureCA(context.Background(), …)` 시작 경로와 동일 형태; ctx 변형: bare / `klog.NewContext(ctx, ctrl.Log)`; 레벨 info·debug·6·8·9·10 | bare ctx: Secret 본문(`tls.key`) 라인이 전 레벨 0 — 구 바이너리와 동일; ctx 로거: ≥8에서만 본문 방출(신·구 동일한 선존 동작), 6 이하 0 | 없음 | throwaway | PASS — bare ctx × {cr-protobuf, cr-json, clientgo-json} × info/debug/6/8/9/10 전부 0(라우팅 제거로 회귀 해소); ctxlogr는 8/9/10에서만 본문 1라인(구 바이너리와 동일), 6 이하 0 — 차트 상한 6이 문서화된 경로를 차단; Bearer 토큰 0 |

### 7.1 QA에서 발견된 결함과 수정

- **(a) 구 릴리스 `helm upgrade --reuse-values` 실패 `[E]`→`[C]`**: `logging` 키가 없는 릴리스(c7f2b9e 차트)에서 `--reuse-values`는 `nil pointer evaluating interface {}.development`(`_helpers.tpl`)로, troubleshooting.md의 `--reuse-values --set logging.level=debug` 레시피는 부분 맵이 `required`에 걸려 `missing properties 'development', 'encoder'`로 실패했다. `--set logging=null`도 스키마를 통과한 뒤 템플릿 nil-pointer였다. 수정: 헬퍼 `dig` 폴백 + `logging` 내부 `required` 제거(§5 R5 정정). 재실행: Kind 구 차트→HEAD `--reuse-values` 롤아웃 OK·155/155 JSON, 문서 레시피 롤아웃 OK·debug 2줄, `logging=null`·키별 `null` 모두 exit 0 + 기본값. 네거티브(`level=warn`/`7`/`129`, `encoder=yaml`, `bogus=1`)는 여전히 거부.
- **(b) e2e redaction 누출·과잉 치환 `[E]`→`[C]`**: 이스케이프된 중첩 JSON의 `api_token`이 살아남았고(접두/접미 변형 포함), `{"msg":"authorization: required"}` 같은 라인이 유효하지 않은 JSON이 되었다. 수정: 이스케이프 따옴표 구분자 + 따옴표 스타일 보존 마스크(§5 R7 정정). 재실행: 문서 입력 23/23 redact, 결과 라인 모두 유효 JSON, 무해 라인(`audience`, `audit` 등) 불변. 최종 회귀 리뷰에서 따옴표 없는 값 대안을 한 번 더 보강해 원래 regex 대비 커버리지 parity를 회복했다(§5 R7 정정 2).
- **(c) QA 기준 정정 `[C]`**:
  - QA-06: level 1의 V(1)은 `"level":"Level(-1)"`이 아니라 `"level":"debug"`로 렌더된다 — zap `Level(-1)`이 곧 `DebugLevel`이다. `Level(-N)` 표기는 N≥2에서만 나타난다(`--zap-log-level=2` → `"Level(-2)"`). 의도(level 1 ⇒ V(1) 켜짐, V(2) 꺼짐, 전부 JSON)는 성립.
  - QA-15: Helm 4는 `--set logging.level=2.0`을 문자열로 강제하므로 스키마가 거부한다. values 파일의 `level: 2.0`은 수용되어 `--zap-log-level=2`로 렌더된다. 스키마 자체는 정확하며 행의 `--set` 예측만 틀렸다.
  - QA-16: 새 기대 동작 — `logging=null`과 키별 `null`은 스키마 오류가 아니라 해당 키의 기본값(`false`/`info`/`json`)으로 렌더되고, 부분 null은 명시된 다른 키를 유지한다. `--set logging=null --set logging.level=debug` 조합은 차트 렌더 전 Helm `--set` 파서가 거부하는 Helm CLI 한계다.
  - §8.1 스텁: `{"status":"active"}` 본문은 cloudflare-go SDK 엔벌로프 디코딩에 실패한다 — `{"success":true,"result":{"id":…,"status":"active"}}`로 응답해야 verify가 통과하고 `GET /zones` 500이 `Reconciler error`를 만든다.
  - §8.1 `CLOUDFLARE_BASE_URL`: 저장소 코드에는 없고 cloudflare-go v7.10.0 SDK의 `DefaultClientOptions`가 읽어 `NewClient`에 적용한다. 하네스 설명의 가정대로 동작한다.
  - QA-07/QA-08: R2 번복으로 기준이 "전역 klog가 JSON으로 라우팅"에서 "klog 라인이 베이스라인과 동일한 텍스트 포맷·severity"로 바뀌었다 — klog 텍스트 라인은 문서화된 예외다.
  - QA-13/QA-15: 스키마 정수 범위가 1..128에서 1..6으로 줄어 경계가 `=6` 수용·`=7`/`=128` 거부로 바뀌었다(§5 R5 정정 2).


---

## 8. 하네스 명세

### 8.1 envtest 스모크 하네스

throwaway 파일(게이트 전 삭제; `.qa-*`는 gitignore 대상이 아님):

- `.qa-smoke-96/main.go` — 레포 모듈 내부 Go 하네스(베이스라인 스모크와 동일 패턴):
  - `envtest.Environment`에 `CRDDirectoryPaths = [config/crd/bases, $GOMODCACHE/sigs.k8s.io/gateway-api@v1.6.2/config/crd/standard]`; `env.Start()`가 채우는 `env.KubeConfig []byte`를 `/tmp/f96-kubeconfig`로 기록.
  - namespace `flareway-system` + Secret `smoke-cf-token`(더미 값) 생성.
  - `httptest` Cloudflare 스텁: `GET /user/tokens/verify` → 200 `{"status":"active"}`; 나머지 → 500(`Reconciler error` 유도).
  - 모드별로 `/tmp/flareway-manager-new`를 `KUBECONFIG`, `CLOUDFLARE_BASE_URL=<stub>`, `HTTPS_PROXY=http://127.0.0.1:9`, `NO_PROXY=127.0.0.1,localhost,::1`(egress 차단)로 exec; stdout/stderr → `/tmp/f96-smoke/<mode>.*`; 45초 실행; ~8초에 `CloudflareAccount smoke-account-<i>` 생성; SIGINT 종료.
  - 공통 인자: `--leader-elect=false --metrics-bind-address=0 --health-probe-bind-address=:18081 --xds-bind-address=:18000 --enable-{gateway,access,private-network,device,organization}-controllers=true`.

```sh
make setup-envtest
bin/setup-envtest use 1.35.0 --bin-dir bin -p path
go build -o /tmp/flareway-manager-new ./cmd
go build -o /tmp/f96-harness ./.qa-smoke-96
KUBEBUILDER_ASSETS="$(pwd)/bin/k8s/1.35.0-darwin-arm64" /tmp/f96-harness
```

| 모드 | 추가 인자/env | QA |
|---|---|---|
| `default` | — | QA-01, QA-11 |
| `debug` | `--zap-log-level=debug` | QA-02 |
| `console` | `--zap-encoder=console` | QA-03 |
| `devel` | `--zap-devel=true --zap-log-level=debug --zap-encoder=console` | QA-04 |
| `devonly` | `--zap-devel=true --zap-log-level=info --zap-encoder=json` | QA-05 |
| `v1` | `--zap-log-level=1` | QA-06 |
| `klog` | env `DISABLE_HTTP2=1`(존재 기반; 실행 내내 클라이언트 HTTP/2 비활성 — 문서화됨) | QA-07, QA-11 |
| `idle` | env `HTTP2_READ_IDLE_TIMEOUT_SECONDS=invalid`(client-go transport 구성 경고 발화) | QA-08, QA-11 |
| `badlevel` | `--zap-log-level=warn`(5초 내 비영 종료 예상, 45초 대기 생략) | QA-09 |

단언 패스(`/tmp/f96-assert.py` 또는 하네스 내장): stderr 각 라인을 `json` / `klog-text`(`^[IWEF]\d{4} `) / `grpc-text`(`^\d{4}/\d{2}/\d{2} `) / `console` / `stack-continuation`(콘솔 모드만 허용)으로 분류하고 모드별 통과 기준 적용; PASS/FAIL 표 출력, 실패 시 비영 종료.

### 8.2 Kind 스테이지(QA-22, QA-25 patch 부분, QA-17 upgrade 부분)

```sh
make kind
docker build -t flareway:dev .
bin/kind create cluster --name f96 --image kindest/node:v1.35.0
bin/kind load docker-image flareway:dev --name f96
kubectl create namespace flareway-system
helm install f96 charts/flareway -n flareway-system \
  --set image.repository=flareway --set image.tag=dev --set image.pullPolicy=Never
kubectl -n flareway-system rollout status deploy/f96-flareway-controller-manager --timeout=3m
kubectl -n flareway-system logs deploy/f96-flareway-controller-manager -c manager > /tmp/f96-kind.log
kubectl -n flareway-system get deploy f96-flareway-controller-manager \
  -o jsonpath='{.spec.template.spec.containers[0].args}'
# QA-17: helm upgrade f96 charts/flareway -n flareway-system --reuse-values → 인자 유지
# QA-25: 문서화된 kubectl patch를 그대로 실행 → debug 인자 추가, rollout 성공, debug 라인
# 선택: helm upgrade f96 charts/flareway -n flareway-system --set logging.level=debug → debug 라인
bin/kind delete cluster --name f96
```

### 8.3 렌더 + 스키마 검사(클러스터 불필요)

```sh
# QA-15 네거티브 — 각각 스키마 검증 실패해야 함:
for v in logging.level=warn logging.level=0 logging.level=-1 logging.level=7 \
         logging.level=128 logging.level=129 logging.level=INFO logging.level=2.5 \
         logging.encoder=yaml logging.encoder=JSON logging.development=maybe \
         logging.development=1 logging.bogus=1; do
  helm template f96 charts/flareway --set "$v"   # 비영 종료 예상
done
helm template f96 charts/flareway --set-string logging.level=2   # 비영 종료(문자열 숫자 거부, R5)
helm template f96 charts/flareway --set logging.level=6          # 경계: 수용
helm template f96 charts/flareway --set logging.level=2.0        # Helm 4 --set 문자열 강제로 거부; values 파일의 2.0은 =2 렌더
# QA-16 null:
helm template f96 charts/flareway --set logging.level=null       # 스키마 오류, nil-pointer 아님
# QA-20 e2e overlay(PR의 실제 zap sed 적용 후 manager args 단언):
bin/kustomize build config/default | sed "s|image: controller:latest|image: x|" | sed "<PR zap sed>" \
  | awk '/--zap-log-level=debug/{ok=1} /--zap-log-level=info/{bad=1} END{exit !(ok&&!bad)}'
```

### 8.4 게이트 목록(QA-26)

```sh
make lint-fix && git status --porcelain    # 클린
make test                                  # unit + envtest
make verify-generated                      # 재생성 == 커밋됨
make verify-artifacts                      # parity + go build + helm + kustomize + runtime-defaults(QA-19)
make verify-container                      # docker build + 이미지 검사(--help 포함, QA-09)
make chart                                 # lint + render + package -> dist/
go mod tidy && git diff --exit-code go.mod go.sum
```

---

## 9. 범위 외와 비주장(non-claims)

- **범위 외** `[D]`: #92 status/reconcile 루프(독립 결함 — 로그 레벨 변경은 그것을 고치지도 숨기지도 않는다; 샘플러는 초당 첫 100개를 항상 통과시키므로 `Reconciler error`는 관측 가능하게 남는다), #97 AUD, xDS 어댑터 레벨 재매핑, 로그 콜사이트 레벨 변경(jevify가 변경 필요 사이트 0건 확인), `extraArgs`/`stacktraceLevel`/`timeEncoding` 노출, grpclog 어댑터, Chart.yaml 버전 범프(릴리스가 주입).
- **주장하지 않음**: 라이브 Cloudflare·실배포에서의 로그 형태 — 모든 증거는 envtest/throwaway/렌더/Kind 기반이며 Kind 스테이지조차 실엣지가 아니다.
- **주장하지 않음**: CPU·인제스천 비용 절감 — issue 자체가 성능 주장을 기각했고, 계측(233 vs 735 ns/line)은 회귀 없음의 증거이지 절감 주장이 아니다.
- **주장하지 않음**: 샘플러 동작은 우리가 추가한 것이 아니라 controller-runtime 프로덕션 기본값 — 문서화 의무만 우리 것이다.
- **주장하지 않음**: 최종 head의 PR 체크 결과 — 첫 head의 필수 체크와 dispatch된 Cloudflare e2e는 녹색이었으나(§10 최종 회귀 리뷰) 최종 head의 CI는 별도 추적이다.
- **범위 외(후속 과제)** `[E]`: 확장 QA-21 입력에서 드러난 redaction 공백 — 원래 regex도 동일하게 놓치므로 이 변경의 회귀가 아니며 여기서 고치지 않는다. (1) `resources.yaml`의 `audTags` 키(CloudflareTunnel Access AUD 목록): YAML 블록(`audTags:` 다음 줄 `- …`)·플로우(`audTags: ["…"]`)·JSON(`"audTags":[…]`) 모두 누출 — 키 대안 `aud` 바로 뒤에 구분자가 와야 해서 매칭되지 않는다. (2) YAML 블록 값: `key:` 뒤 줄바꿈 리스트는 `\s*`가 줄을 넘어 `-`만 마스킹하고, `|` 리터럴 블록은 `|`만 마스킹한다(무해한 `authorization:` 블록 YAML도 훼손). (3) JSON 배열·객체 값(`"aud":[…]`, `"tunnel_token":{…}`): 누출 + JSON 파손. (4) 이중 이스케이프 중첩(`\\\"api_token\\\"`): 누출. 문서는 e2e 아티팩트에 AUD가 포함되면 안 된다고 명시하므로 별도 후속 과제로 추적한다(구분자 `[ \t]*` + YAML 시퀀스/블록 처리, 또는 `resources.yaml` 구조적 redaction).
- **범위 외(선존 동작, 문서화)** `[E]`: 요청 ctx에 로거를 태운 client-go 호출은 raw `--zap-log-level≥8`에서 API 요청/응답 본문(Secret 데이터 포함)을 덤프한다 — 신·구 바이너리 동일한 선존 client-go 동작이며 이 PR은 차트 스키마 상한 6과 문서 경고로만 닫는다. 바이너리 플래그 자체는 베이스라인과 동일하게 ≥8을 수용한다. bare-context 경로는 klog 라우팅 제거로 전 레벨 침묵을 회복했다(QA-28).

## 10. 합의 기록

세 렌즈가 독립 QA 목록을 작성하고 2라운드 투표로 수렴했다.

### 렌즈

- **운영·패키징(OP)**: Helm/Kustomize 패키징, 스키마 UX, 렌더링 인자 parity, 운영자 문서.
- **적대적 회귀(RG)**: 제안 설계가 기존 동작을 망가뜨리는 모든 경로. 실행 확인 회귀 2건 발견(redaction 누출, schema atomicity).
- **검증 설계(VF)**: 검증 설계와 테스트 엄밀성 — 실바이너리 트리거(`DISABLE_HTTP2`), 하네스 명세, 영구-vs-일회성 판별.

### 라운드 1 — 수정(amendment)으로 반영된 항목

- D2: 로거 값을 캡처해 재사용(`logger := zap.New(...)`), `FlushLogger`/`InitFlags` 금지, klog→direct go.mod + tidy 게이트(VF). — klog 라우팅 번복으로 direct 승격 부분은 moot; klog는 indirect로 남는다(§5 R2).
- D3: grpclog 예외는 운영자 문서(chart README Logging 섹션)에 명시(OP/VF).
- D4: 샘플러 opt-out 문구 정밀화(OP/RG/VF) — 라운드 2에서 한 번 더 정정(아래).
- D5: 정수 level 상한 128(int8 wrap 침묵 footgun `[E]`), 문자열 숫자 형식 제거, `required` 유지 근거(null→schema error), args 끝 append, development 의미 문서화(OP/RG/VF). — 상한은 최종 회귀 리뷰에서 6으로 정정(§5 R5 정정 2).
- D6: `verify-runtime-defaults`를 manager 컨테이너 args 범위 + exact-once + wiring render로(OP/RG/VF).
- D7: e2e debug overlay로 V(1) triage 스트림 보존 + redaction 수정을 같은 PR에(RG).
- D8: stacktrace 형식 변화, klog 텍스트 예외(포맷 불변), `go run` UX, index-patch 지침 추가(RG/VF). — "klog 텍스트→JSON" 문서화는 R2 번복으로 "klog 텍스트 예외"로 정정.

### 라운드 2 — CONSENT WITH CHANGES로 반영된 항목

- **R4 문구 정정 `[C]`**: "V(N≥1)은 샘플링되지 않는다"는 사실 오류. 샘플러는 zap 레벨 -1..5를 커버하므로 debug/V(1), info, warn, error 항목이 **모두** 샘플링되고 V(N≥2)만 우회. opt-out은 `development=true` 또는 정수 `level ≥ 2`뿐(RG 실행 검증 `zapcore/sampler.go:219-227`).
- **QA-09 정정 `[C]`**: `--zap-log-level=0`/`-1`은 "조용히 수용"이 아니라 바이너리가 exit 2로 거부(`invalid log level "<v>"`) — OP 실행 확인.
- **QA-20 강화**: PR의 실제 e2e zap sed를 적용하고 `containers[name=manager].args` 범위에서 `=debug` 존재 + `=info` 부재를 assert; 워크플로 자체가 치환 적용을 grep으로 assert해 loud fail(OP+RG).
- **QA-25 확장**: 문서화된 `kubectl patch`/Kustomize JSON6902 debug 레시피를 Kind 단계에서 verbatim 실행(append-not-replace + debug 라인 관측)(OP).
- **QA-13**: values 파일 경로 추가 — `level: 2` 정수 수용, `level: "2"` 문자열 거부(OP).
- **QA-15**: `level=2.0`(integral float) — Helm validator가 정수로 수용해 `--zap-log-level=2` 렌더링; 기록된 동작이며 결함 아님(OP). — 실행 정정: values 파일의 `2.0`만 수용되고 `--set`의 `2.0`은 Helm 4가 문자열로 강제해 거부(§7.1 (c)).
- **QA-07**: `DISABLE_HTTP2`는 presence-based이고 해당 실행의 client-side HTTP/2를 끄는 부수 효과를 명시(RG).
- **QA-17**: Kind 단계가 돌면 `helm upgrade --reuse-values`로 args 보존 확인(OP).
- **잔여 [INFERENCE]**: QA-22 Kind 단계가 skip되면 in-cluster `leaderelection` JSON 라우팅은 baseline finding 8 `[INFERENCE]`에 의존 — contextual 경로는 이미 입증됐으므로 수용 가능한 잔여로 합의(RG). — Kind 스테이지가 실행되어 실측으로 해소; klog 라우팅 없이도 `leaderelection` 라인은 JSON(QA-22).

### Drop된 라운드 1 항목

| Source ID | 이유 |
|---|---|
| OP-05 | R5에서 문자열-정수 level 형식 제거로 moot; `--set-string logging.level=2` 거부는 QA-15에 흡수 |
| OP-10 | QA-26 게이트에 흡수(`verify-helm`/`helm lint`는 이미 게이트와 CI에서 실행) |
| RG-02 | QA-13과 동일 경로(세 값 `--set` render) — 별개 위험 아님 |
| RG-16 | QA-01과 동일 경로(default 모드가 이미 ≥1 `Reconciler error` JSON 라인 요구) |
| RG-17 | R5에서 `extraArgs` 기각으로 moot; "세 키만 노출" 문서 명시는 QA-24에 흡수 |
| RG-15 | 이미 실행·종결(prod-json 233 ns/line vs dev-console 735 ns/line — 성능 회귀 없음); 증거로 보존 |

### 최종 회귀 리뷰

구현 후 세 독립 리뷰어(런타임, 패키징/CI, 보안)가 PR diff를 검토했고, judge가 18개 hunk를 triage했다(10개 flag, 전부 정독).

- **SEC-01(보안, high) — 수정됨**: `klog.SetLoggerWithOptions(logger, klog.ContextualLogger(true))`가 로거 없는 ctx의 `klog.FromContext` 폴백을 우리 로거로 돌려, client-go의 V(8) 요청/응답 본문 로깅이 bare context에서도 발화했다. 시작 경로 `pki.EnsureCA(context.Background(), …)`의 protobuf Secret GET에서 `tls.key` 본문이 `--zap-log-level≥8`에 방출됨을 합성 Secret으로 재현했고 구 바이너리는 전 레벨 침묵이었다. 수정: klog 라우팅 제거 + 스키마 정수 상한 128→6(§5 R2 번복, R5 정정 2). 재증명 QA-28.
- **klog severity 강등(런타임) — 수정됨**: 라우팅된 klog는 `Warning`/`Fatal`을 `logger.Info`로 방출해 severity를 잃었다(`HTTP2_READ_IDLE_TIMEOUT_SECONDS=invalid`로 재현). 라우팅 제거로 해소 — klog 출력이 베이스라인과 바이트 단위 동일(QA-07/QA-08).
- **redaction 따옴표 없는 값 커버리지(보안) — 수정됨**: unquoted 대안이 백슬래시·따옴표를 소비하지 못해 원래 regex가 잡던 입력을 놓쳤다. lookahead 보강으로 parity 회복(§5 R7 정정 2, QA-21).
- **패키징/CI — 소견 없음**: 528개 Helm 조합(정수 1–128 + 명명 레벨 × development × encoder — 상한 6 변경 전 측정), BSD awk + 9개 변이로 `verify-runtime-defaults` 검증, ubuntu CI의 verify-artifacts 잡이 awk 경로를 행사(mawk 경로는 CI가 커버). 문서 정확도 지적 1건(`--set level=2.0` 거부)은 §7.1 (c)에 반영.
- **PR CI**: 첫 head에서 필수 체크 전부 녹색, PR 브랜치에 dispatch된 Cloudflare e2e 실행 성공. 최종 head의 CI는 별도 추적.
