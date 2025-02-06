package dirscan

import (
	"fmt"
	"github.com/fatih/color"
	"strings"
)

const (
	progressBarWidth = 60 // 进度条总长度（字符数）
)

func percent() {
	// 计算百分比
	percentVal := (float64(succeCount) / float64(countall)) * 100.00

	// 生成进度条
	progressBar := generateProgressBar(percentVal)

	// 完成状态处理
	statusSymbol := " "
	if percentVal == 100 {
		statusSymbol = "√"
	}

	// 格式化输出
	percentStr := fmt.Sprintf("%.2f%%", percentVal)
	fmt.Printf("\r[%s] %s %s",
		color.YellowString(progressBar),
		color.RedString(percentStr),
		color.GreenString(statusSymbol),
	)
}

// 生成进度条字符串
func generateProgressBar(percent float64) string {
	filledWidth := int(percent / 100 * progressBarWidth)

	// 构建进度条
	bar := strings.Repeat("=", filledWidth)
	if filledWidth < progressBarWidth {
		bar += ">" // 添加进度箭头
		bar += strings.Repeat(" ", progressBarWidth-filledWidth-1)
	} else {
		bar = strings.Repeat("=", progressBarWidth) // 100%时全填充
	}
	return bar
}
