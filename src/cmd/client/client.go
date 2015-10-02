package main

import (
	//"bufio"
	"encoding/base64"
	"net/http"
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	"github.com/jmcvetta/napping"
	"pkg/pgp"
)

var client pgp.PGP

type TokenChallenge struct {
	Token string
}

func (tc *TokenChallenge) Decrypt() {
	token, _ := base64.StdEncoding.DecodeString(tc.Token)
	token = client.DecryptBytes(token)
	tc.Token = base64.StdEncoding.EncodeToString(token)
}

func register() {
	pkPayload := struct {
		PublicKey string
	}{string(pgp.ToArmor(client.PublicKey(), pgp.PGPPublicKey))}
	var pkResult TokenChallenge
	log.WithFields(log.Fields{"PublicKey": pkPayload.PublicKey}).Debug("Register")

	resp, _ := napping.Post("http://localhost:8080/register", &pkPayload,
		&pkResult, nil)

	if resp.Status() == http.StatusAccepted {
		log.WithFields(log.Fields{"encToken": pkResult.Token}).Debug("Register - challenge received")
	} else {
		log.WithFields(log.Fields{"status": resp.Status()}).Fatal("Register - unknown status")
	}

	registerToken(pkResult)
}

func registerToken(tc TokenChallenge) {
	tc.Decrypt()
	resp, _ := napping.Post("http://localhost:8080/register/token", &tc,
		nil, nil)

	if resp.Status() == http.StatusCreated {
		log.Debug("Register - success")
	} else if resp.Status() == http.StatusForbidden {
		log.Fatal("Register - user with the same fingerprint already registered")
	} else {
		log.WithFields(log.Fields{"status": resp.Status()}).Fatal("Register - unknown status")
	}
}

func identify() {
	tokenPayload := struct {
		Fingerprint string
	}{base64.StdEncoding.EncodeToString(client.Fingerprint())}

	log.WithFields(
		log.Fields{"fingerprint": tokenPayload.Fingerprint}).Debug("Identify")

	var identifyResult TokenChallenge
	// Identify - send fingerprint
	resp, err := napping.Post("http://localhost:8080/identify", &tokenPayload,
		&identifyResult, nil)
	if err != nil {
		log.Fatal(err)
	}

	if resp.Status() == http.StatusNotFound {
		log.Fatal("Identify - not registered")
		return
	}

	// Replace the token with the decrypted version
	identifyResult.Decrypt()

	test := make(map[string]string)
	resp, _ = napping.Post("http://localhost:8080/identify/token",
		&identifyResult, test, nil)
	if resp.Status() == 200 {
		log.Debug("Identify/Token - success")
	} else {
		log.Fatal("Identify/Token - failure")
	}
}

func init() {
	log.SetLevel(log.DebugLevel)
}

func main() {
	var err error
	client = pgp.NewPGP()
	if err != nil {
		panic(err)
	}
	client.DecryptEntity()

	app := cli.NewApp()
	app.Name = "pgp-client"
	app.Usage = ""
	app.Action = func(c *cli.Context) {
		identify()
	}
	app.Commands = []cli.Command{
		{
			Name:    "register",
			Aliases: []string{"r"},
			Usage:   "",
			Action: func(c *cli.Context) {
				register()
			},
		},
	}

	app.Run(os.Args)

	//identify()

	//bytes, err := client.EncryptBytes([]byte("testToken"), client.PublicEntities)
	//f, _ := os.Create("./msg.gpg")
	//f.Write(pgp.ToArmor(bytes, pgp.PGPMessage))
	//f.Close()

	//f, _ = os.Create("./public.asc")
	//f.Write(pgp.ToArmor(client.ExportPublicKey(), pgp.PGPPublicKey))
	//f.Close()

	//encToken := readTokenReq(conn)
	//log.Println(encToken)
}
