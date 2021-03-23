package OPFSKEM

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
	"time"
)

func TestPrint(t *testing.T) {
	l := 300
	pk, sk, _ := KGen(rand.Reader, l)

	ta := time.Now().Unix()
	time0 := fmt.Sprintf("%032b", ta)

	// time0 := "1011"
	key1, ct, _ := Enc(rand.Reader, pk, time0)
	key2, err := Dec(rand.Reader, pk, sk, time0, ct)
	if err != nil {
		fmt.Println("errrrrrrrrrrrrrrrrrrrror:", err)
	}
	if bytes.Equal(key1.Marshal(), key2.Marshal()) {
		fmt.Println("Decapsulate Success!")
	}

	// time3 := "1000"
	ta = time.Now().Unix() + 1234567
	time3 := fmt.Sprintf("%032b", ta)

	_, skp3 := PnctInt(pk, sk, time3)

	key3, err := Dec(rand.Reader, pk, skp3, time0, ct)
	if err != nil {
		fmt.Println("errrrrrrrrrrrrrrrrrrrror:", err)
	}
	if bytes.Equal(key1.Marshal(), key3.Marshal()) {
		fmt.Println("Correctness of PFSKEM - 1 !")
	}

	start := time.Now()
	// time4 := "1100"
	ta = time.Now().Unix() + 222
	time4 := fmt.Sprintf("%032b", ta)

	_, ct4, _ := Enc(rand.Reader, pk, time4)
	_, skp4 := PnctCxt(pk, sk, time4, ct4)
	key4, _ := Dec(rand.Reader, pk, skp4, time0, ct)
	if bytes.Equal(key1.Marshal(), key4.Marshal()) {
		fmt.Println("Correctness of PFSKEM - 2 !")
	}
	fmt.Printf("%v", time.Since(start))

}
