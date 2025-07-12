package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"strings"

	indigo "github.com/bluesky-social/indigo/atproto/crypto"
	"github.com/go-piv/piv-go/v2/piv"
	"github.com/manifoldco/promptui"
	"github.com/notjuliet/grove/cbor"
	"github.com/urfave/cli/v3"
)

func main() {
	cmd := &cli.Command{
		Usage: "yubikey did:plc stuff",
		Commands: []*cli.Command{
			{
				Name:   "init",
				Usage:  "generate a new NIST-P256 private key on the yubikey, overwriting slot 9C",
				Action: doInit,
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "please-overwrite-my-keyslot",
						Usage: "skip the interactive prompt, for use in testing etc.",
					},
				},
			},
			{
				Name:   "pubkey",
				Usage:  "print the corresponding public key to stdout, in did:key format",
				Action: doPubkey,
			},
			{
				Name:   "sign",
				Usage:  "sign a did:plc operation (reads and writes JSON on stdio)",
				Action: doSign,
			},
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}

func findYubikey() (*piv.YubiKey, error) {
	// List all smartcards connected to the system.
	cards, err := piv.Cards()
	if err != nil {
		return nil, err
	}

	// Find a YubiKey and open the reader.
	var yk *piv.YubiKey
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			if yk, err = piv.Open(card); err != nil {
				return nil, err
			}
			break
		}
	}
	if yk == nil {
		return nil, errors.New("no yubikeys present?")
	}
	return yk, nil
}

func pubkeyToDidKey(pubkey crypto.PublicKey) (string, error) {
	ecdsa_pubkey, ok := pubkey.(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("P256 public key expected")
	}

	if ecdsa_pubkey.Curve != elliptic.P256() {
		return "", errors.New("P256 public key expected")
	}

	// these APIs are weird... I'm not doing ECDH but elliptic.Marshal is deprecated
	ecdh_pubkey, err := ecdsa_pubkey.ECDH()
	if err != nil {
		return "", err
	}

	indigo_pubkey, err := indigo.ParsePublicUncompressedBytesP256(ecdh_pubkey.Bytes())
	if err != nil {
		return "", err
	}

	return indigo_pubkey.DIDKey(), nil
}

func doInit(ctx context.Context, cmd *cli.Command) error {
	yk, err := findYubikey()
	if err != nil {
		return err
	}

	if !cmd.Bool("please-overwrite-my-keyslot") {
		fmt.Println("⚠️  This action is destructive!!! ⚠️")
		fmt.Println("")
		fmt.Println("It will overwrite any existing key in the 'Digital Signature' slot, aka 9C")
		fmt.Println("")
		prompt := promptui.Prompt{
			Label: "Please type 'I understand' to continue",
		}
		result, err := prompt.Run()
		if err != nil {
			return err
		}
		if !strings.EqualFold(result, "I understand") {
			return errors.New("the user does not understand")
		}
	}

	key := piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   piv.PINPolicyAlways,
		TouchPolicy: piv.TouchPolicyAlways,
	}
	pubkey, err := yk.GenerateKey(piv.DefaultManagementKey, piv.SlotSignature, key)
	if err != nil {
		return err
	}

	didkey, err := pubkeyToDidKey(pubkey)
	if err != nil {
		return err
	}

	fmt.Println("Success! Here's the public key:")
	fmt.Println(didkey)
	return nil
}

func doPubkey(ctx context.Context, cmd *cli.Command) error {
	yk, err := findYubikey()
	if err != nil {
		return err
	}

	cert, err := yk.Attest(piv.SlotSignature)
	if err != nil {
		return err
	}

	didkey, err := pubkeyToDidKey(cert.PublicKey)
	if err != nil {
		return err
	}

	fmt.Println(didkey)
	return nil
}

func asn1SigToCompact(asn1sig []byte) ([]byte, error) {
	var rs struct {
		R, S *big.Int
	}
	_, err := asn1.Unmarshal(asn1sig, &rs)
	if err != nil {
		return nil, err
	}

	var compact [64]byte
	rs.R.FillBytes(compact[:32])
	rs.S.FillBytes(compact[32:])

	return compact[:], nil
}

func signWithYubikey(msg []byte) ([]byte, error) {
	// begin doing the signing
	yk, err := findYubikey()
	if err != nil {
		return nil, err
	}

	// necessary to extract out the pubkey
	cert, err := yk.Attest(piv.SlotSignature)
	if err != nil {
		return nil, err
	}

	auth := piv.KeyAuth{PIN: piv.DefaultPIN} // TODO: option to prompt for pin interactively
	privkey, err := yk.PrivateKey(piv.SlotSignature, cert.PublicKey, auth)
	if err != nil {
		return nil, err
	}

	ecdsa_privkey, ok := privkey.(*piv.ECDSAPrivateKey)
	if !ok {
		return nil, errors.New("expected ECDSA key")
	}

	digest := sha256.Sum256(msg)
	fmt.Fprintln(os.Stderr, "please boop your yubikey now")
	return ecdsa_privkey.Sign(nil, digest[:], crypto.SHA256)
}

func doSign(ctx context.Context, cmd *cli.Command) error {
	// prepare the data to be signed
	stdin, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	var unmarshalled map[string]any
	if err := json.Unmarshal(stdin, &unmarshalled); err != nil {
		return err
	}
	delete(unmarshalled, "sig") // remove any existing sig
	cbor_bytes, err := cbor.Encode(unmarshalled)
	if err != nil {
		return err
	}

	asn1sig, err := signWithYubikey(cbor_bytes)
	if err != nil {
		return err
	}

	compactsig, err := asn1SigToCompact(asn1sig)
	if err != nil {
		return err
	}

	unmarshalled["sig"] = base64.RawURLEncoding.EncodeToString(compactsig)

	remarshalled, err := json.MarshalIndent(unmarshalled, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(remarshalled))
	return nil
}
