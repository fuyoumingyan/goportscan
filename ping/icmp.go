package ping

import (
	"github.com/fuyoumingyan/utils/limiter"
	"github.com/go-ping/ping"
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

func GetAliveHosts(hosts []string, limitSize int) []string {
	var resultsMap sync.Map
	var limit = limiter.New(limitSize)
	for _, host := range hosts {
		limit.Add()
		go func(host string) {
			defer func() {
				limit.Done()
			}()
			resultsMap.Store(host, SinglePing(host))
		}(host)
	}
	limit.WaitAndClose()
	var aliveHosts []string
	resultsMap.Range(func(key, value interface{}) bool {
		if value.(bool) {
			aliveHosts = append(aliveHosts, key.(string))
		}
		return true
	})
	return aliveHosts
}
