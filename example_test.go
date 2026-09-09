package divert_test

import (
	"context"
	"fmt"
	"log"

	"github.com/bnkrr/app-divert"
)

func ExampleNew() {
	proxy, err := divert.New(divert.Config{
		Apps:   []string{"game.exe"},
		SOCKS5: "127.0.0.1:1080",
	}, divert.Options{Logger: log.Default()})
	if err != nil {
		log.Fatal(err)
	}
	// This runnable example cancels before startup, so it needs no driver.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fmt.Println(proxy.Run(ctx))
	// Output: <nil>
}
