package ping

import (
	"github.com/fuyoumingyan/utils/limiter"
	"github.com/fuyoumingyan/utils/progress"
	"github.com/go-ping/ping"
	"github.com/projectdiscovery/gologger"
	"sync"
	"time"
)

func SinglePing(host string) bool {
	pinger, err := ping.NewPinger(host)
	if err != nil {
		return false
	}
	pinger.Count = 1
	pinger.Timeout = 800 * time.Millisecond
	pinger.SetPrivileged(true)
	if pinger.Run() != nil { // Blocks until finished. return err
		return false
	}
	if stats := pinger.Statistics(); stats.PacketsRecv > 0 {
		return true
	}
	return false
}

func GetAliveHosts(hosts []string, limitSize int, show bool) []string {
	var bar = progress.NewProgressbar(int64(len(hosts)), "主机验活", show)
	var resultsMap sync.Map
	var limit = limiter.New(limitSize)
	for _, host := range hosts {
		limit.Add()
		go func(host string) {
			defer func() {
				limit.Done()
				err := bar.Add(1)
				if err != nil {
					gologger.Info().Msg(err.Error())
				}
			}()
			resultsMap.Store(host, SinglePing(host))
		}(host)
	}
	limit.WaitAndClose()
	err := bar.Finish()
	if err != nil {
		gologger.Info().Msg(err.Error())
	}
	err = bar.Close()
	if err != nil {
		gologger.Info().Msg(err.Error())
	}
	var aliveHosts []string
	resultsMap.Range(func(key, value interface{}) bool {
		if value.(bool) {
			aliveHosts = append(aliveHosts, key.(string))
		}
		return true
	})
	return aliveHosts
}
