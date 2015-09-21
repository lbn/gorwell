package main

import (
	//"bufio"
	"log"
	"net"
	//"os"

	"github.com/jmcvetta/napping"
	"github.com/lbn/gorwell"
)

var client *gorwell.PGP

func identify() {
	fingerprint := client.ExportFingerprint()
}

func main() {
	var err error
	client, err = gorwell.NewPGP()
	if err != nil {
		panic(err)
	}
	client.DecryptEntity()

	//bytes, err := client.EncryptBytes([]byte("testToken"), client.PublicEntities)
	if err != nil {
		panic(err)
	}
	//f, _ := os.Create("./msg.gpg")
	//f.Write(gorwell.ToArmor(bytes, gorwell.PGPMessage))
	//f.Close()

	//f, _ = os.Create("./public.asc")
	//f.Write(gorwell.ToArmor(client.ExportPublicKey(), gorwell.PGPPublicKey))
	//f.Close()

	//encToken := readTokenReq(conn)
	//log.Println(encToken)
}
