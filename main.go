package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	nsscache "github.com/MiLk/nsscache-go"
)

var (
	systemShells []string

	minUID = pflag.Int("min-uid", 2000, "Minimum UID number to accept")
	minGID = pflag.Int("min-gid", 2000, "Minimum GID number to accept")

	defHomeDir = pflag.String("homedir", "/tmp/{UID}", "Home directory to provide if none is available from NetAuth")
	defShell   = pflag.String("shell", "/bin/nologin", "Default shell to use if none is provided in the directory")

	outDir  = pflag.String("out", "/etc", "Output directory for cache files")
	cfgfile = pflag.String("config", "", "Config file to use")

	log hclog.Logger
)

func initialize() {
	// Grab a listing of system shells and add them here
	bytes, err := ioutil.ReadFile("/etc/shells")
	if err != nil {
		log.Error("Error reading /etc/shells %s", "error", err)
		os.Exit(2)
	}
	shellString := string(bytes[:])
	for _, s := range strings.Split(shellString, "\n") {
		if s != "" {
			systemShells = append(systemShells, s)
		}
	}
	log.Info("The system will accept the following shells")
	for _, s := range systemShells {
		log.Info(fmt.Sprintf("  %s", s))
	}
}

func main() {
	log = hclog.L().Named("nsscache")

	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)
	if *cfgfile != "" {
		viper.SetConfigFile(*cfgfile)
	} else {
		viper.SetConfigName("config")
		viper.AddConfigPath("/etc/netauth/")
		viper.AddConfigPath("$HOME/.netauth")
		viper.AddConfigPath(".")
	}
	if err := viper.ReadInConfig(); err != nil {
		fmt.Println("Error reading config:", err)
		os.Exit(1)
	}

	// Perform initialization
	initialize()

	filler, err := NewCacheFiller(int32(*minUID), int32(*minGID), *defShell, *defHomeDir, systemShells)
	if err != nil {
		log.Error("Error initializing Cache Filler: ", "error", err)
		os.Exit(1)
	}

	cm := nsscache.NewCaches()
	if err := cm.FillCaches(filler); err != nil {
		log.Error("Unable to fill caches: ", "error", err)
		os.Exit(1)
	}

	err = cm.WriteFiles(&nsscache.WriteOptions{
		Directory: *outDir,
	})
	if err != nil {
		log.Error("Error writing updated caches: ", "error", err)
	}
	log.Info("Caches Updated")
}
