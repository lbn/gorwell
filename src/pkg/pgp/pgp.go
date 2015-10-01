package pgp

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"

	log "github.com/Sirupsen/logrus"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/ssh/terminal"
)

type BlockType string

const (
	PGPMessage   = "PGP MESSAGE"
	PGPPublicKey = "PGP PUBLIC KEY"
)

type PGP struct {
	PrivateEntities openpgp.EntityList
	PublicEntities  openpgp.EntityList
}

func NewPGP() PGP {
	gnupg := path.Join(os.Getenv("HOME"), ".gnupg")

	// Keyring
	keyringFileBuffer, err := os.Open(path.Join(gnupg, "secring.gpg"))
	if err != nil {
		log.Fatal(err)
	}
	privateEntities, err := openpgp.ReadKeyRing(keyringFileBuffer)
	defer keyringFileBuffer.Close()

	// Keyring
	publicKeyringFile, err := os.Open(path.Join(gnupg, "pubring.gpg"))
	if err != nil {
		log.Fatal(err)
	}
	publicEntities, err := openpgp.ReadKeyRing(publicKeyringFile)
	for _, entity := range publicEntities {
		log.Println(entity)
	}
	defer publicKeyringFile.Close()

	return PGP{privateEntities, publicEntities}
}

func (client PGP) DecryptEntity() {
	fmt.Println("Enter passphrase:")
	pw, _ := terminal.ReadPassword(0)

	// Decrypt private key
	client.PrivateEntities[0].PrivateKey.Decrypt(pw)

	for _, subkey := range client.PrivateEntities[0].Subkeys {
		subkey.PrivateKey.Decrypt(pw)
	}

	log.Debug("Identities:")
	for _, id := range client.PrivateEntities[0].Identities {
		log.Debug("Name: %s | Email: %s\n", id.UserId.Name, id.UserId.Email)
	}
}

func (client PGP) DecryptBytes(esecret []byte) []byte {
	md, err := openpgp.ReadMessage(bytes.NewBuffer(esecret), client.PrivateEntities, nil, nil)
	if err != nil {
		panic(err)
	}
	bytes, _ := ioutil.ReadAll(md.UnverifiedBody)
	return bytes
}

func (client PGP) EncryptBytes(secret []byte, target openpgp.EntityList) []byte {
	// encrypt string
	buf := new(bytes.Buffer)
	w, _ := openpgp.Encrypt(buf, target, nil, nil, nil)
	w.Write(secret)
	w.Close()

	bytes, _ := ioutil.ReadAll(buf)
	f, _ := os.Create("./msg.asc")
	f.Write(ToArmor(bytes, PGPMessage))
	defer f.Close()
	return bytes
}

func (client PGP) PublicKey() []byte {
	buf := new(bytes.Buffer)
	client.PublicEntities[0].Serialize(buf)
	bytes, _ := ioutil.ReadAll(buf)
	return bytes
}

func (client PGP) Fingerprint() []byte {
	return client.PublicEntities[0].PrimaryKey.Fingerprint[:]
}

func ToArmor(secret []byte, blockType BlockType) []byte {
	buf := new(bytes.Buffer)
	w, err := armor.Encode(buf, string(blockType), nil)
	if err != nil {
		panic(err)
	}
	_, err = w.Write(secret)
	if err != nil {
		panic(err)
	}
	w.Close()
	bytes, _ := ioutil.ReadAll(buf)
	return bytes
}

type PGPClient struct {
	Entities openpgp.EntityList
}

func PublicKeyToPGPClient(publicKey string) PGPClient {
	block, err := armor.Decode(strings.NewReader(publicKey))
	if err != nil {
		panic(err)
	}
	entity, err := openpgp.ReadEntity(packet.NewReader(block.Body))
	if err != nil {
		panic(err)
	}
	return PGPClient{openpgp.EntityList{entity}}
}

func (pgpClient PGPClient) Encrypt(data []byte) []byte {
	// encrypt string
	buf := new(bytes.Buffer)
	w, _ := openpgp.Encrypt(buf, pgpClient.Entities, nil, nil, nil)
	w.Write(data)
	w.Close()

	bytes, _ := ioutil.ReadAll(buf)
	return bytes
}

func (pgpClient PGPClient) Fingerprint() []byte {
	return pgpClient.Entities[0].PrimaryKey.Fingerprint[:]
}
