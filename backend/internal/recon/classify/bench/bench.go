// Package bench — 의미 분류(classify, 이슈 #41) 품질 계기판 (이슈 #61).
//
// recon/bench(#22)·scanengine/bench(#49)가 정찰·스캔에 해준 것을 분류에도 한다 —
// "룰이 실제로 얼마나 맞는가"를 숫자로 잰다. classify 는 대상에 요청을 보내지 않는 순수
// 함수(구조적 입력 → 라벨)라 정찰·스캔 벤치와 달리 살아있는 서버가 필요 없다.
//
// 채점은 의미 라벨(semantic-only: auth·payment·upload·admin·pii·search)만 본다.
// 구조 라벨(api·static)은 경로에 rest/api/vN·정적 확장자가 있으면 기계적으로 참이 되어
// 스코어에 넣으면 사실상 "경로 문자열 매칭"만 재는 것이 되므로 뺀다 — 의미 라벨이야말로
// 규제 매핑(#42)·스캔 우선순위가 실제로 쓰는 신호다.
package bench

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// GTEndpoint — 정답셋 한 항목. expect 가 비어 있으면 "의미 라벨 없음(api/static/other 만)"이 정답이다.
type GTEndpoint struct {
	Method string   `yaml:"method"`
	Path   string   `yaml:"path"`
	Params []string `yaml:"params,omitempty"`
	Expect []string `yaml:"expect"`
}

// GroundTruth — 앱별 정답셋 (docs/classify-groundtruth/<app>.yaml).
type GroundTruth struct {
	App       string       `yaml:"app"`
	Endpoints []GTEndpoint `yaml:"endpoints"`
}

// LoadGroundTruth — YAML 정답셋 로드.
func LoadGroundTruth(path string) (GroundTruth, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return GroundTruth{}, err
	}
	var gt GroundTruth
	if err := yaml.Unmarshal(b, &gt); err != nil {
		return GroundTruth{}, fmt.Errorf("%s: %w", path, err)
	}
	if len(gt.Endpoints) == 0 {
		return gt, fmt.Errorf("%s: endpoints 비어 있음", path)
	}
	return gt, nil
}

// GTFiles — 채점할 정답셋 파일 목록.
//
//	CLASSIFYBENCH_GT=<file>    : 그 파일 하나만.
//	CLASSIFYBENCH_GT_DIR=<dir> : 해당 폴더의 *.yaml 전부 (기본 docs/classify-groundtruth).
func GTFiles() ([]string, error) {
	if f := os.Getenv("CLASSIFYBENCH_GT"); f != "" {
		return []string{f}, nil
	}
	dir := os.Getenv("CLASSIFYBENCH_GT_DIR")
	if dir == "" {
		dir = "../../../../../docs/classify-groundtruth"
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

// semantic — 스코어에 넣을 라벨. classify.go 의 semantic 맵과 같은 집합이지만, bench 를
// classify 패키지에 의존시키지 않으려고(순환 없음·독립 계기판) 상수로 다시 적는다.
var semantic = map[string]bool{"auth": true, "payment": true, "upload": true, "admin": true, "pii": true, "search": true}

// filterSemantic — 라벨 목록에서 의미 라벨만 남긴다.
func filterSemantic(labels []string) map[string]bool {
	out := map[string]bool{}
	for _, l := range labels {
		if semantic[strings.ToLower(l)] {
			out[strings.ToLower(l)] = true
		}
	}
	return out
}

// EntryResult — 항목 1개의 채점.
type EntryResult struct {
	Method, Path string
	Expected     []string
	Predicted    []string
	From         string // classify.Result.From — "rule"|"llm"|"cache"
	TP, FP, FN   []string
}

// Metrics — 정답셋 전체의 micro P/R/F1(모든 (엔드포인트,라벨) 쌍을 합산).
type Metrics struct {
	Pairs                 int // 채점 대상 (엔드포인트,라벨) 쌍 총수 = TP+FP+FN
	TP, FP, FN            int
	Precision, Recall, F1 float64
	RuleHits, LLMHits     int
	MissedList, ExtraList []string
}

// Score — EntryResult 목록을 micro 집계한다.
func Score(results []EntryResult) Metrics {
	var m Metrics
	for _, r := range results {
		m.TP += len(r.TP)
		m.FP += len(r.FP)
		m.FN += len(r.FN)
		switch r.From {
		case "llm":
			m.LLMHits++
		default:
			m.RuleHits++
		}
		for _, l := range r.FN {
			m.MissedList = append(m.MissedList, r.Method+" "+r.Path+" → "+l)
		}
		for _, l := range r.FP {
			m.ExtraList = append(m.ExtraList, r.Method+" "+r.Path+" → "+l)
		}
	}
	m.Pairs = m.TP + m.FP + m.FN
	if m.TP+m.FP > 0 {
		m.Precision = float64(m.TP) / float64(m.TP+m.FP)
	}
	if m.TP+m.FN > 0 {
		m.Recall = float64(m.TP) / float64(m.TP+m.FN)
	}
	if m.Precision+m.Recall > 0 {
		m.F1 = 2 * m.Precision * m.Recall / (m.Precision + m.Recall)
	}
	return m
}

// ScoreEntry — 한 엔드포인트의 예측 라벨을 정답과 비교해 TP/FP/FN(의미 라벨만)을 낸다.
func ScoreEntry(gt GTEndpoint, predicted []string, from string) EntryResult {
	exp := filterSemantic(gt.Expect)
	got := filterSemantic(predicted)

	r := EntryResult{Method: gt.Method, Path: gt.Path, Expected: sortedKeys(exp), Predicted: sortedKeys(got), From: from}
	for l := range got {
		if exp[l] {
			r.TP = append(r.TP, l)
		} else {
			r.FP = append(r.FP, l)
		}
	}
	for l := range exp {
		if !got[l] {
			r.FN = append(r.FN, l)
		}
	}
	sort.Strings(r.TP)
	sort.Strings(r.FP)
	sort.Strings(r.FN)
	return r
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Summary — 사람이 읽는 요약(README/이슈에 그대로 붙여넣기 좋은 형태).
func (m Metrics) Summary(topN int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "쌍=%d TP=%d FP=%d FN=%d  P=%.1f%% R=%.1f%% F1=%.1f%%  룰=%d LLM=%d\n",
		m.Pairs, m.TP, m.FP, m.FN, m.Precision*100, m.Recall*100, m.F1*100, m.RuleHits, m.LLMHits)
	if len(m.MissedList) > 0 {
		fmt.Fprintf(&b, "  누락(FN) %d: %s\n", len(m.MissedList), head(m.MissedList, topN))
	}
	if len(m.ExtraList) > 0 {
		fmt.Fprintf(&b, "  오탐(FP) %d: %s\n", len(m.ExtraList), head(m.ExtraList, topN))
	}
	return b.String()
}

func head(ss []string, n int) string {
	if len(ss) <= n {
		return strings.Join(ss, ", ")
	}
	return strings.Join(ss[:n], ", ") + fmt.Sprintf(", …(+%d)", len(ss)-n)
}
