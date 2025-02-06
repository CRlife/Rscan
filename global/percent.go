package global

import (
	"fmt"
	"github.com/fatih/color"
	"strings"
)

const (
	progressBarWidth = 60 // 进度条总长度（字符数）
)

// Percent 输出进度条
func Percent(succeCount, countall uint32) {
	PrintLock.Lock()
	defer PrintLock.Unlock()

	if countall == 0 {
		fmt.Printf("\r[%s] %s %s",
			color.YellowString(strings.Repeat(" ", progressBarWidth)),
			color.RedString("0.00%%"),
			color.GreenString(" "),
		)
		return
	}
	percentVal := (float64(succeCount) / float64(countall)) * 100.00
	progressBar := generateProgressBar(percentVal)

	// 完成状态处理
	statusSymbol := " "
	if percentVal == 100 {
		statusSymbol = "√"
	}

	percentStr := fmt.Sprintf("%.2f%%", percentVal)
	fmt.Printf("\r[%s] %s %s",
		color.YellowString(progressBar),
		color.RedString(percentStr),
		color.GreenString(statusSymbol),
	)
}

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
