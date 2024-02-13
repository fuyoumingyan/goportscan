package main

import (
	"encoding/json"
	"fmt"
	"github.com/fuyoumingyan/goportscan/fingerprintx"
	"github.com/fuyoumingyan/goportscan/ping"
	"github.com/fuyoumingyan/goportscan/scan"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/projectdiscovery/gologger"
	"os"
	"sort"
	"time"
)

// PrintTable 输出漂亮的表格 ~
func PrintTable(results map[string][]fingerprintx.Service) {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetAutoIndex(true)
	t.SetStyle(table.StyleRounded)
	t.Style().Options.SeparateRows = true
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, Align: text.AlignLeft},
		{Number: 2, Align: text.AlignLeft},
		{Number: 3, Align: text.AlignLeft},
	})
	t.AppendHeader(table.Row{"IP", "Port", "Protocol"})
	for ip, ports := range results {
		for _, port := range ports {
			t.AppendRow([]interface{}{ip, port.Port, port.Protocol})
		}
	}
	t.AppendSeparator()
	t.Render()
}

func main() {
	start := time.Now()
	ips := []string{"123.254.105.104"}
	// ICMP 探测存活主机
	aliveHosts := ping.GetAliveHosts(ips, 10, false)
	// SYN 扫描全端口开放
	resultMap := scan.NewScan(aliveHosts, 6, false, 3, 10).RunEnumeration().WaitAndClose().GetResult()
	// fingerprintx 指纹识别
	results := fingerprintx.NewFingerPrint(resultMap, false).GetFingerPrints().GetResultMap()
	// 对端口号进行排序 这里只是为了输出 json 的美观
	for _, services := range results {
		sort.Slice(services, func(i, j int) bool {
			return services[i].Port < services[j].Port
		})
	}
	jsonData, _ := json.MarshalIndent(results, "", "    ")
	fmt.Println(string(jsonData))
	gologger.Info().Msgf("用时 : %v\n", time.Since(start).String())
}
