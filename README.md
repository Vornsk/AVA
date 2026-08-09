# 점검항목 데이터셋 (3층 구조)

정의서 §6에 정의한 **Detector / VulnDef / CheckItem** 3층을 인코딩한 데이터셋.

## 파일
| 파일 | 층 | 내용 |
|---|---|---|
| `detectors.yaml` | 1층 | 탐지 로직(재사용). `방식`(rule/tool/llm 조합), `도구`, `파괴성` |
| `vulndefs.yaml` | 2층 | 취약점 정의(설명·CWE). `detector` 참조. 스킴 간 중복 제거 |
| `checkitems.kii.yaml` | 3층 | 주요정보통신기반시설(웹, 21) · `context: 일반` |
| `checkitems.mobile.yaml` | 3층 | 모바일(13) · `context: 클라이언트앱` |
| `checkitems.fin.yaml` | 3층 | 전자금융(48) · `context: 전자거래`(WEB-FIN) / `일반`(WEB-SER) |

## 통계
- Detector 65 · VulnDef 65 · CheckItem 82 (KII 21 / MOB 13 / FIN 48)
- 무결성: 미사용/미정의 VulnDef 0, detector 참조 정상, FIN 위험도 전부 채움

## 핵심 규칙
- **재사용**: 스킴에 중복되는 취약점(SQLi·XSS·CSRF 등)은 같은 `VulnDef`/`Detector`를 공유하고 `CheckItem`만 스킴별로 둔다.
- **1:N 통합**(`통합: true`): 주요정보통신의 복합 항목은 하위 다수 VulnDef를 `vuln[]`으로 결합하고 `상세설명`에서 분할한다. 현재 대상: `KII-01, KII-05, KII-16, KII-17(부분), KII-20`.
- **context**: `전자거래`는 거래 수행 시점 진단, `클라이언트앱`은 별도 툴체인(모바일).
- **파괴성**: `true`인 Detector는 기본 제외 + 명시적 opt-in(정의서 FR-3.2).

## 항목 추가 방법
1. 새 취약점이면 `detectors.yaml`·`vulndefs.yaml`에 추가.
2. `checkitems.<scheme>.yaml`에 CheckItem 추가(`vuln`은 배열, 위험도·context 지정).
3. 생성기 `gen_checklist.py`로 일괄 재생성해도 된다(무결성 자동 검증 포함).

> 위험도가 비어(`null`) 있는 주요정보통신 항목은 기관 기준값을 채우면 된다.
