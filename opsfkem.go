package OPFSKEM

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"hibkem"
	"io"
	"ots"
)

type PK struct {
	mpk *HIBKEM.Params
	otp *OTS.Params
}

type SK = []*HIBKEM.PrivateKey

type Ciphertext struct {
	ctibkem *HIBKEM.Ciphertext
	sig     *OTS.Signature
	vk      *OTS.VerKey
}

type Key = *HIBKEM.SessionKey

////////////////////////
func KGen(r io.Reader, l int) (*PK, SK, error) {
	pk := &PK{}
	var err error

	msk := &HIBKEM.PrivateKey{}
	if pk.mpk, msk, err = HIBKEM.Setup(r, l); err != nil {
		return nil, nil, err
	}

	if pk.otp, err = OTS.Setup(r); err != nil {
		return nil, nil, err
	}

	return pk, SK{msk}, nil

}

func Enc(r io.Reader, pk *PK, t string) (Key, *Ciphertext, error) {
	ct := &Ciphertext{}
	var symkey Key

	vk, sk, err := pk.otp.KeyGen(r)
	if err != nil {
		return nil, nil, err
	}

	idstr := pk.mpk.RootID + t + SHA256ToBin(vk.Marshal())
	if symkey, ct.ctibkem, err = HIBKEM.Encapsulate(r, pk.mpk, idstr); err != nil {
		return nil, nil, err
	}
	if ct.sig, err = sk.Sign(r, ct.ctibkem.Marshal()); err != nil {
		return nil, nil, err
	}
	ct.vk = vk

	return symkey, ct, nil
}

func PnctCxt(pk *PK, sk SK, t string, ct *Ciphertext) (SK, SK) {
	idstr := pk.mpk.RootID + t + SHA256ToBin(ct.vk.Marshal())
	return HIBKEM.PunctureTree(pk.mpk, sk, idstr)
}

func PnctInt(pk *PK, sk SK, t string) (SK, SK) {
	return HIBKEM.PunctureTree(pk.mpk, sk, pk.mpk.RootID+t)
}

func Dec(r io.Reader, pk *PK, sk SK, t string, ct *Ciphertext) (Key, error) {
	if !ct.sig.Verify(pk.otp, ct.vk, ct.ctibkem.Marshal()) {
		return nil, errors.New("Ill-formed ciphertext!")
	}

	idstr := pk.mpk.RootID + t + SHA256ToBin(ct.vk.Marshal())

	for _, item := range sk {
		if idstr == item.ID {
			return HIBKEM.Decapsulate(item, ct.ctibkem), nil
		}
		if HIBKEM.IsAncestor(item.ID, idstr) {
			tempsk, err := HIBKEM.KeyGen(r, pk.mpk, item, idstr)
			if err != nil {
				return nil, err
			}
			return HIBKEM.Decapsulate(tempsk, ct.ctibkem), nil
		}
	}
	return nil, errors.New("Decrypt error!")
}

func SHA256ToBin(s []byte) string {
	idstr := ""
	for _, b := range sha256.Sum256(s) {
		idstr += fmt.Sprintf("%08b", b)
	}
	return idstr
}
