package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/funbox/nfqueue-go/nfqueue"
)

func realCallback(payload *nfqueue.Payload) {
	fmt.Println("Real callback")
	fmt.Printf("  id: %d\n", payload.ID)
	fmt.Printf("  mark: %d\n", payload.GetNFMark())
	fmt.Printf("  in  %d      out  %d\n", payload.GetInDev(), payload.GetOutDev())
	fmt.Printf("  Φin %d      Φout %d\n", payload.GetPhysInDev(), payload.GetPhysOutDev())
	fmt.Println(hex.Dump(payload.Data))
	fmt.Println("-- ")
	payload.SetVerdict(nfqueue.NFAccept)
}

func main() {
	q := new(nfqueue.Queue)

	q.SetCallback(realCallback)

	q.Init()
	defer q.Close()

	q.Unbind(syscall.AF_INET)
	q.Bind(syscall.AF_INET)

	q.CreateQueue(0)
	q.SetMode(nfqueue.NFQNLCopyPacket)

	c := make(chan os.Signal, 1)

	signal.Notify(c, os.Interrupt)

	go func() {
		for sig := range c {
			// sig is a ^C, handle it
			_ = sig
			q.Close()
			os.Exit(0)
			// XXX we should break gracefully from loop
		}
	}()

	// XXX Drop privileges here

	// XXX this should be the loop
	q.TryRun()

	fmt.Printf("hello, world\n")
}
