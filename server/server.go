package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"io"
	"log"
	"net/http"

	"github.com/emicklei/go-restful"
	"github.com/lbn/gorwell"
	_ "github.com/mattn/go-sqlite3"
)

var (
	db  *sql.DB
	pgp gorwell.PGP
)

func main() {
	var err error
	db, err = sql.Open("sqlite3", "./users.sqlite3")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	pgp = gorwell.NewPGP()

	ws := new(restful.WebService)
	ws.Route(ws.POST("/identify").To(handleIdentify).
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON))
	ws.Route(ws.POST("/identify/token").To(handleIdentifyToken).
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON))

	restful.Add(ws)
	http.ListenAndServe(":8080", nil)
}

type IdentifyRequest struct {
	Fingerprint string
}

func handleIdentify(req *restful.Request, res *restful.Response) {
	//test := make(map[string]interface{})
	var identReq *IdentifyRequest = new(IdentifyRequest)
	err := req.ReadEntity(identReq)
	if err != nil {
		res.AddHeader("Content-Type", "text/plain")
		res.WriteErrorString(http.StatusInternalServerError, err.Error())
		return
	} else if identReq.Fingerprint == "" {
		res.AddHeader("Content-Type", "text/plain")
		res.WriteErrorString(http.StatusBadRequest, "Property fingerprint not given")
		return
	}

	// Get public key
	stmt, err := db.Prepare("SELECT public_key FROM users WHERE fingerprint = ?")
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()

	var publicKey string
	stmt.QueryRow(identReq.Fingerprint).Scan(&publicKey)

	// Generate and encrypt token
	token := make([]byte, 64)
	rand.Read(token)
	client := gorwell.PublicKeyToPGPClient(publicKey)

	encToken := base64.StdEncoding.EncodeToString(client.Encrypt(token))

	resObj := make(map[string]string)
	resObj["token"] = encToken
	res.WriteEntity(resObj)
}

func handleIdentifyToken(req *restful.Request, res *restful.Response) {
	io.WriteString(res, "test")
}
