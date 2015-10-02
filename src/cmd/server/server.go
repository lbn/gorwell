package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"io"
	"net/http"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/emicklei/go-restful"
	"github.com/garyburd/redigo/redis"
	_ "github.com/mattn/go-sqlite3"
	"pkg/pgp"
)

var (
	db        *sql.DB
	serverPGP pgp.PGP
	pool      *redis.Pool
)

func init() {
	log.SetLevel(log.DebugLevel)
}

func main() {
	// Redis
	pool = &redis.Pool{
		MaxIdle:     3,
		IdleTimeout: 240 * time.Second,
		Dial: func() (redis.Conn, error) {
			c, err := redis.Dial("tcp", ":6379")
			if err != nil {
				log.Fatal(err)
			}
			return c, err
		},
		TestOnBorrow: func(c redis.Conn, t time.Time) error {
			_, err := c.Do("PING")
			return err
		},
	}

	var err error
	db, err = sql.Open("sqlite3", "./users.sqlite3")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	serverPGP = pgp.NewPGP()

	ws := new(restful.WebService)
	ws.Route(ws.POST("/register").To(handleRegister).
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON))
	ws.Route(ws.POST("/register/token").To(handleRegisterToken).
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON))
	ws.Route(ws.POST("/identify").To(handleIdentify).
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON))
	ws.Route(ws.POST("/identify/token").To(handleIdentifyToken).
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON))

	restful.Add(ws)
	addr := ":8080"
	log.WithFields(log.Fields{"address": addr}).Info("Listen")
	http.ListenAndServe(addr, nil)
}

func handleRegister(req *restful.Request, res *restful.Response) {
	var regReq struct {
		PublicKey string
	}
	req.ReadEntity(&regReq)

	client := pgp.PublicKeyToPGPClient(regReq.PublicKey)
	fingerprint := base64.StdEncoding.EncodeToString(client.Fingerprint())
	log.WithFields(log.Fields{
		"fingerprint": fingerprint,
	}).Debug("Received Register request")

	conn := pool.Get()
	defer conn.Close()

	token := NewToken(regReq.PublicKey)

	conn.Do("HMSET", "reg:token:"+token.Clear,
		"fingerprint", fingerprint,
		"public_key", regReq.PublicKey)

	challenge := make(map[string]string)
	challenge["token"] = token.Encrypted

	res.WriteHeaderAndEntity(http.StatusAccepted, challenge)
}

type IdentifyRequest struct {
	Fingerprint string
}

type Token struct {
	Clear     string
	Encrypted string
}

func NewToken(publicKey string) Token {
	// Generate and encrypt token
	token := make([]byte, 64)
	rand.Read(token)
	b64Token := base64.StdEncoding.EncodeToString(token)

	client := pgp.PublicKeyToPGPClient(publicKey)

	b64EncToken := base64.StdEncoding.EncodeToString(client.Encrypt(token))

	return Token{b64Token, b64EncToken}
}

func handleIdentify(req *restful.Request, res *restful.Response) {
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

	if publicKey == "" {
		res.WriteHeader(404)
		return
	}

	token := NewToken(publicKey)

	resObj := make(map[string]string)
	resObj["token"] = token.Encrypted
	res.WriteEntity(resObj)
}

func handleIdentifyToken(req *restful.Request, res *restful.Response) {
	io.WriteString(res, "test")
}

func handleRegisterToken(req *restful.Request, res *restful.Response) {
	log.Debug("Received Register/Token request")

	conn := pool.Get()
	defer conn.Close()

	tokenEntity := make(map[string]string)
	err := req.ReadEntity(&tokenEntity)
	if err != nil {
		log.Fatal(err)
	}

	key := "reg:token:" + tokenEntity["Token"]
	log.Println(key)
	fingerprint, err := redis.String(conn.Do("HGET", key, "fingerprint"))
	if err != nil {
		log.Fatal(err)
	}
	publicKey, err := redis.String(conn.Do("HGET", key, "public_key"))
	if err != nil {
		log.Fatal(err)
	}

	log.Debug(fingerprint)
	log.Debug(publicKey)

	stmt, err := db.Prepare("INSERT INTO users (fingerprint, public_key) VALUES (?, ?)")
	if err != nil {
		log.Fatal(err)
	}

	_, err = stmt.Exec(fingerprint, publicKey)
	if err != nil {
		res.WriteHeader(http.StatusForbidden)
	} else {
		res.WriteHeader(http.StatusCreated)
	}
}
