package main

import (
	"crypto"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/sec51/twofactor"
	"io/ioutil"
	"net/http"
	"os"
)

const issuer = "Example 2FA"

func saveOTPForEmail(email string, bytes []byte) error{
	f, err := os.Create(fmt.Sprintf("%s.txt", email))
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(bytes)
	if err != nil {
		return err
	}

	return nil
}

func getOTPForEmail(email string)(bytes []byte, err error){
	bytes, err = ioutil.ReadFile(fmt.Sprintf("%s.txt", email))
	if err != nil{
		return nil, err
	}
	return
}

func login(email string, code string) (err error){
	bytes, err := getOTPForEmail(email)
	if err != nil{
		return err
	}
	otp, err := twofactor.TOTPFromBytes(bytes, issuer)
	if err != nil {
		return err
	}

	//Verify the user provided token, coming from the google authenticator app
	err = otp.Validate(code)
	if err != nil {
		return err
	}
	return nil
}

func generateQRCode(email string) (qrBytes []byte, err error){
	//Init the totp object via:
	otp, err := twofactor.NewTOTP(email, issuer, crypto.SHA1, 6)
	if err != nil {
		return nil, err
	}

	bytes, err := otp.ToBytes()
	if err != nil{
		return nil, err
	}

	err = saveOTPForEmail(email, bytes)
	if err != nil{
		return nil, err
	}

	//Display the PNG QR code to the user and an input text field, so that he can insert the token generated from his device
	qrBytes, err = otp.QR()
	if err != nil {
		return nil, err
	}

	return
}

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/qr/{email}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		email := vars["email"]

		qBytes, err := generateQRCode(email)
		if err != nil{
			panic(err)
		}

		_, err = w.Write(qBytes)
		if err != nil{
			panic(err)
		}

	})
	r.HandleFunc("/confirm/{email}/{code}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		code := vars["code"]
		email := vars["email"]
		err := login(email, code)
		if err != nil{
			w.Write([]byte(err.Error()))
		} else {
			w.Write([]byte("Success login"))
		}
	})
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./html/")))

	err := http.ListenAndServe("127.0.0.1:1122", r)
	if err != nil{
		panic(err)
	}
}
