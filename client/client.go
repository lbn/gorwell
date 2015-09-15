package main

import (
	//"bufio"
	"net"
	"os"

	"github.com/lbn/gorwell"
)

var client gorwell.PGP = gorwell.NewPGP()

func identify(conn net.Conn) {
	// C: IDENTIFY <fingerprint>
	identifyMsg := []byte("IDENTIFY ")
	fingerprint := client.ExportFingerprint()
	for _, b := range fingerprint {
		identifyMsg = append(identifyMsg, b)
	}
	identifyMsg = append(identifyMsg, byte('\n'))
	conn.Write(identifyMsg)
}

func expectTokenReq(conn net.Conn) {
	// S: TOKEN REQ <encrypted token>
	resp := make([]byte, 512)
	conn.Read(resp)
}

func main() {
	client.DecryptEntity()

	bytes := client.EncryptBytes([]byte("testToken"), client.PublicEntities)
	f, _ := os.Create("./msg.gpg")
	f.Write(gorwell.ToArmor(bytes, gorwell.PGPMessage))
	f.Close()

	f, _ = os.Create("./public.asc")
	f.Write(gorwell.ToArmor(client.ExportPublicKey(), gorwell.PGPPublicKey))
	f.Close()

	conn, _ := net.Dial("tcp", "127.0.0.1:8081")

	identify(conn)

	expectTokenReq(conn)
}
