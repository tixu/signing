package main

import (
	"crypto/dsa"
	"crypto/md5"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"

	"github.com/boltdb/bolt"
	"github.com/go-ini/ini"
	"github.com/gorilla/mux"
)

var db *bolt.DB
var addr string

var privatekeycollection = []byte("privatekey")
var publickeycollection = []byte("publickey")

// Requestsign rekfldmkfldk
type Requestsign struct {
	Origin string
	Msg    string
}

// SignedMessage zrerf
type SignedMessage struct {
	Origin    string
	Msg       string
	Signature []byte
}

// VerifiedSignedMessage mdlfmldsmfù
type VerifiedSignedMessage struct {
	Origin    string
	Msg       string
	Signature []byte
	Status    bool
}

func main() {
	var err error
	db, err = bolt.Open("my.db", 0600, nil)

	if err != nil {
		log.Fatal(err)
		panic(err)
	}
	initsign()

	router := mux.NewRouter()
	router.HandleFunc("/sign", signhandler).Methods("POST")
	router.HandleFunc("/verify", verifyhandler).Methods("POST")
	http.Handle("/", router)
	log.Fatal(http.ListenAndServe(addr, nil))

}

func verifyhandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var message SignedMessage
	b, _ := ioutil.ReadAll(r.Body)
	json.Unmarshal(b, &message)
	var response VerifiedSignedMessage
	response.Msg = message.Msg
	response.Origin = message.Origin
	response.Signature = message.Signature

	status, err := verifywithbyte(message.Origin, message.Msg, message.Signature)
	if err != nil {
		http.Error(w, "unable to verify ", 500)
		return
	}
	response.Status = status

	resp, _ := json.Marshal(response)

	w.Write(resp)
}

func signhandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var message Requestsign
	b, _ := ioutil.ReadAll(r.Body)
	json.Unmarshal(b, &message)
	signature, err := signasbyte(message.Origin, message.Msg)
	if err != nil {
		http.Error(w, "unable to sign ", 500)
		return
	}
	var response SignedMessage
	response.Msg = message.Msg
	response.Origin = message.Origin
	response.Signature = signature
	resp, _ := json.Marshal(response)
	w.Write(resp)
}

func generateKey() (*dsa.PrivateKey, dsa.PublicKey) {
	params := new(dsa.Parameters)

	// see http://golang.org/pkg/crypto/dsa/#ParameterSizes
	if err := dsa.GenerateParameters(params, rand.Reader, dsa.L1024N160); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	localprivatekey := new(dsa.PrivateKey)
	localprivatekey.PublicKey.Parameters = *params
	dsa.GenerateKey(localprivatekey, rand.Reader) // this generates a public & private key pair

	publickey := localprivatekey.PublicKey

	return localprivatekey, publickey
}

func getPrivateKeyFromDB(id string) (*dsa.PrivateKey, error) {
	var localprivatekey dsa.PrivateKey
	err := db.View(func(tx *bolt.Tx) error {

		b := tx.Bucket(privatekeycollection)
		v := b.Get([]byte(id))
		if v == nil {
			return errors.New("eee")
		}
		json.Unmarshal(v, &localprivatekey)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &localprivatekey, nil
}

func getPublicKeyFromDB(id string) (*dsa.PublicKey, error) {
	var localpublickey dsa.PublicKey

	err := db.View(func(tx *bolt.Tx) error {

		b := tx.Bucket(publickeycollection)
		v := b.Get([]byte(id))
		if v == nil {
			return errors.New("eee")
		}

		json.Unmarshal(v, &localpublickey)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &localpublickey, err
}

func initsign() {
	cfg, err := ini.Load("sign.ini")
	if err != nil {
		log.Fatal(err)
	}

	keys := cfg.Section("customer").KeyStrings()

	for _, key := range keys {
		log.Printf("Processing tag defintion %s \n", key)
		vals := cfg.Section("customer").Key(key).Strings(",")

		for _, customer := range vals {
			add(customer)
		}
	}

	addr = cfg.Section("server").Key("addr").String()
}

func add(customer string) (err error) {
	log.Printf("adding customer %s", customer)
	privatekey, publickey := generateKey()
	privateencoded, err := json.Marshal(privatekey)
	publicencoded, err := json.Marshal(publickey)

	db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(privatekeycollection)
		if b.Get([]byte(customer)) == nil {
			err = b.Put([]byte(customer), privateencoded)
		}
		b, err = tx.CreateBucketIfNotExists(publickeycollection)
		if b.Get([]byte(customer)) == nil {
			err = b.Put([]byte(customer), publicencoded)
		}

		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}
		return nil
	})

	return err
}

func initDB() (err error) {

	log.Println("creating bucket")
	db.Update(func(tx *bolt.Tx) error {
		privatekey, publickey := generateKey()
		privateencoded, err := json.Marshal(privatekey)
		publicencoded, err := json.Marshal(publickey)

		b, err := tx.CreateBucketIfNotExists(privatekeycollection)

		err = b.Put([]byte("onss"), privateencoded)
		b, err = tx.CreateBucketIfNotExists(publickeycollection)
		err = b.Put([]byte("onss"), publicencoded)

		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}
		return nil
	})

	return err
}

func signasbyte(customerid, msg string) (signature []byte, err error) {
	r, s, err := sign(customerid, msg)
	if err != nil {
		return nil, err
	}
	signature = r.Bytes()
	signature = append(signature, s.Bytes()...)
	return signature, nil
}

func sign(customerid, msg string) (r, s *big.Int, err error) {
	log.Println("about to sign")

	var h hash.Hash
	h = md5.New()
	r = big.NewInt(0)
	s = big.NewInt(0)
	io.WriteString(h, msg)
	signhash := h.Sum(nil)
	privateKey, err := getPrivateKeyFromDB(customerid)
	if err != nil {
		return nil, nil, err
	}
	r, s, err = dsa.Sign(rand.Reader, privateKey, signhash)
	if err != nil {
		return nil, nil, err
	}

	log.Printf("R : %d\n S : %d", r, s)

	signature := r.Bytes()
	log.Printf("%d", len(signature))
	signature = append(signature, s.Bytes()...)

	log.Printf("Signature : %x\n", signature)
	return r, s, nil
}

func verifywithbyte(customerid string, msg string, signature []byte) (status bool, err error) {
	r := big.NewInt(0)
	s := big.NewInt(0)

	r = r.SetBytes(signature[0:20])
	s = s.SetBytes(signature[20:])
	return verify(customerid, msg, r, s)
}

func verify(customerid string, msg string, r, s *big.Int) (status bool, err error) {
	var h hash.Hash
	h = md5.New()

	io.WriteString(h, msg)
	signhash := h.Sum(nil)
	publickey, err := getPublicKeyFromDB(customerid)
	if err != nil {
		return false, err
	}
	status = dsa.Verify(publickey, signhash, r, s)
	return status, nil

}
