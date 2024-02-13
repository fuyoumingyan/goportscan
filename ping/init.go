//go:build linux

package ping

import (
	"github.com/projectdiscovery/gologger"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
)

func init() {
	currentUser, err := user.Current()
	if err != nil {
		gologger.Fatal().Msgf("user.Current() error: %v", err.Error())
	}
	homeDir := currentUser.HomeDir
	hiddenDir := filepath.Join(homeDir, ".goportscan")
	_, err = os.Stat(hiddenDir)
	if err != nil {
		if os.IsNotExist(err) {
			err = os.Mkdir(hiddenDir, 0700)
			if err != nil {
				gologger.Fatal().Msgf("os.Mkdir error: %v", err.Error())
			}
		} else {
			gologger.Fatal().Msgf("os.Stat error: %v", err.Error())
		}
	}
	flagFile := filepath.Join(hiddenDir, "ping-flag")
	_, err = os.Stat(flagFile)
	if err != nil {
		if os.IsNotExist(err) {
			err = exec.Command("sudo", "sysctl", "-w", "net.ipv4.ping_group_range=\"0 2147483647\"").Run()
			if err != nil {
				gologger.Fatal().Msgf("exec.Command error: %v", err.Error())
			}
			_, err = os.Create(flagFile)
			if err != nil {
				gologger.Fatal().Msgf("os.Create error: %v", err.Error())
			}
		} else {
			gologger.Fatal().Msgf("os.Stat error: %v", err.Error())
		}
	}
}
