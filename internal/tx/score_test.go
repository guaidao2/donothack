package tx

import (
	"strconv"
	"testing"
)

// 的回归：类目槽位溢出必须**可观测**，不能静默丢弃。
//
// `byCat` 只有 16 个槽，而 mixed 模式的裁决按类目阈值算 ——
// 第 17 个类目的分数原先只进 Total、不进类目分，等于"分数算进去了但永远拦不住"。
// 当前类目集合是硬编码的 9 个，打不到；但类目一旦可配置，这就是静默漏检。
func TestScoreOverflowIsCounted(t *testing.T) {
	var s Score
	// 填满 16 个槽
	for i := 0; i < 16; i++ {
		s.Add("cat"+strconv.Itoa(i), 1)
	}
	if s.Overflow != 0 {
		t.Fatalf("还没溢出就计数了：%d", s.Overflow)
	}
	if s.Total != 16 {
		t.Fatalf("Total 应为 16，实际 %d", s.Total)
	}

	// 第 17 个类目
	s.Add("cat17", 5)
	if s.Overflow != 1 {
		t.Errorf("溢出的类目必须被计数，实际 Overflow=%d", s.Overflow)
	}
	// 分数仍然进 Total（不至于漏判总量）
	if s.Total != 21 {
		t.Errorf("溢出类目的分数仍应计入 Total（21），实际 %d", s.Total)
	}
	// 已知类目照常累加，不受溢出影响
	s.Add("cat0", 3)
	if got := s.Get("cat0"); got != 4 {
		t.Errorf("已有类目应累加到 4，实际 %d", got)
	}
	if s.Overflow != 1 {
		t.Errorf("命中有槽类目不该增加溢出计数，实际 %d", s.Overflow)
	}

	// Reset 必须清掉它（事务池复用，残留会让下一个请求的统计虚高）
	s.Reset()
	if s.Overflow != 0 || s.Total != 0 || s.nCat != 0 {
		t.Errorf("Reset 之后应当全部归零：%+v", s)
	}
}
