# goportscan

同 fuyoumingyan/cdncheck 该项目是构建 goauto 信息收集自动化的一环。

该项目实现的功能：

1. ICMP 检查主机存活
2. SYN 全端口扫描
3. fingerprintx 开放端口指纹识别

> PS: windows 需要安装 npcap 驱动 ~

使用：

```
go get github.com/fuyoumingyan/goportscan@v1.0.0
go mod tidy
```

```go
func main() {
	start := time.Now()
	ips := []string{"123.254.105.104"}
	// ICMP 探测存活主机
	aliveHosts := ping.GetAliveHosts(ips, 10, false)
	// SYN 扫描全端口开放
	resultMap := scan.NewScan(aliveHosts, 3000, false, 10).RunEnumeration().WaitAndClose().GetResult()
	// fingerprintx 指纹识别
	results := fingerprintx.NewFingerPrint(resultMap, false, 10).GetFingerPrints().GetResultMap()
	// 输出结果
	PrintTable(results)
	gologger.Info().Msgf("用时 : %v\n", time.Since(start).String())
}
```

![image-20240225161420267](https://gallery-1310215391.cos.ap-beijing.myqcloud.com/img/image-20240225161420267.png)
