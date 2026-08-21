# 참조

- 현재 상태와 다음 작업: @docs/HANDOFF.md
- 코드베이스 감사 결과: @docs/CODEBASE.md (§0 갱신 블록의 면책 범위를 먼저 확인할 것)

# 빌드 순서 (중요)

- frontend에서 `npm run build`를 먼저 실행해야 `go build`가 성공한다.
  `backend/internal/webui/dist`는 `//go:embed` 대상이며 git에 커밋되지 않는다.
- `npm run build`는 `tsc --noEmit`을 먼저 돌린다. 타입 에러면 vite가 아예 안 돌아
  **dist가 갱신되지 않는다** — JS를 안 고쳤는데 go build가 옛 화면을 embed하는 상황이 아니라,
  프론트 빌드가 먼저 실패한다. 타입만 빠르게 보려면 `npm run typecheck`.

# 이 프로젝트의 함정

- 영속화 파일 경로가 상대경로다. 작업 디렉터리를 바꿔 실행하면 상태가 조용히 빈 값으로 시작한다.
- `internal/webui`, `internal/mcpserver`, `frontend/src` 전체에 테스트가 없다.
- `gh` CLI가 설치돼 있지 않다. GitHub 조작은 API를 쓴다.

# 워크플로

- 요청 범위 밖의 파일은 수정하지 않는다. 특히 `backend/` 하위 `.go` 파일.
- 새 라이브러리·새 추상화 도입 전에 반드시 묻는다.
- `git -C` 대신 작업 디렉터리를 이동해서 실행한다 (worktree가 엉뚱한 경로에 생긴 사례 있음).

# 검증 규칙

- 수치를 주장할 때 재현 명령을 병기한다. 실행하지 않은 값은 "추정"으로 명시.
- 서브에이전트 보고의 핵심 수치는 직접 재확인한다.
