package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/bnkrr/app-divert"
)

func main() {
	exe, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	path := flag.String("config", filepath.Join(filepath.Dir(exe), "config.json"), "configuration file")
	check := flag.Bool("check", false, "validate configuration without opening WinDivert")
	flag.Parse()
	cfg, err := divert.LoadConfig(*path)
	if err != nil {
		log.Fatal(err)
	}
	proxy, err := divert.New(cfg, divert.Options{DLLDir: filepath.Dir(exe)})
	if err != nil {
		log.Fatal(err)
	}
	if *check {
		log.Print("configuration OK")
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err = proxy.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
