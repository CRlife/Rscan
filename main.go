package main

import (
	"fmt"
	"rscan/cmd"
	"time"
)

func main() {
	start := time.Now()
	cmd.Execute()
	end := time.Now().Sub(start)
	fmt.Printf("[*] 任务结束,耗时: %s\n", end)
}
