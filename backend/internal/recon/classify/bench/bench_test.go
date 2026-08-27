package bench

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"proxypoc/internal/llm"
	"proxypoc/internal/recon/classify"
)

// TestClassifyBench — 정답셋(docs/classify-groundtruth/*.yaml) 전체를 순회해 룰(+옵션 LLM)
// 분류 정확도를 의미 라벨 기준 micro P/R/F1 로 낸다 (이슈 #61, classify 착수 #41).
//
//	재현: cd backend && go test ./internal/recon/classify/bench -run ClassifyBench -v -count=1
//	특정 정답셋만: CLASSIFYBENCH_GT=../../../../../docs/classify-groundtruth/juice-shop.yaml go test ...
//	LLM 포함: CLASSIFYBENCH_LLM=mock|ollama|anthropic|openai (+ _MODEL/_ENDPOINT/_KEY) go test ...
//	          미설정이면 프로바이더를 건드리지 않는다 — 캐시가 실행 간 공유되므로 룰만 켰다가
//	          LLM 을 켜는 순서로 두 번 돌리면 두 번째는 캐시가 오염될 수 있다. 비교하려면
//	          -count=1 로 각각 새 프로세스에서 실행할 것(go test 는 매 실행이 새 프로세스라 안전).
func TestClassifyBench(t *testing.T) {
	files, err := GTFiles()
	if err != nil {
		t.Fatalf("정답셋 탐색 실패: %v", err)
	}
	if len(files) == 0 {
		t.Skip("정답셋 YAML 없음 (docs/classify-groundtruth/*.yaml)")
	}

	if p := os.Getenv("CLASSIFYBENCH_LLM"); p != "" {
		llm.SetProvider(llm.New(p, os.Getenv("CLASSIFYBENCH_LLM_MODEL"), os.Getenv("CLASSIFYBENCH_LLM_ENDPOINT"), os.Getenv("CLASSIFYBENCH_LLM_KEY")))
		t.Logf("LLM 프로바이더: %s (CLASSIFYBENCH_LLM)", p)
	} else {
		t.Logf("LLM 프로파일 skip — 프로바이더 미설정, 룰만 채점 (CLASSIFYBENCH_LLM=mock|ollama|anthropic|openai)")
	}

	for _, f := range files {
		gt, err := LoadGroundTruth(f)
		if err != nil {
			t.Errorf("%s 로드 실패: %v", f, err)
			continue
		}
		name := gt.App
		if name == "" {
			name = filepath.Base(f)
		}
		t.Run(name, func(t *testing.T) {
			var results []EntryResult
			for _, ep := range gt.Endpoints {
				in := classify.Input{Method: ep.Method, Path: ep.Path, ParamKeys: ep.Params}
				res := classify.Classify(context.Background(), in)
				results = append(results, ScoreEntry(ep, res.Labels, res.From))
			}
			m := Score(results)
			t.Logf("의미 분류 벤치마크 — app=%s (GT %d개 엔드포인트, 의미 라벨 쌍 기준)", gt.App, len(gt.Endpoints))
			t.Logf("%s", m.Summary(15))
			t.Logf("↑ 이 수치를 baseline 으로 기록하세요 (docs/classify-groundtruth/README.md, 이슈 #61).")
		})
	}
}
