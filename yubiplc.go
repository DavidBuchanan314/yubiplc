package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/go-piv/piv-go/v2/piv"
	"github.com/manifoldco/promptui"
	"github.com/urfave/cli/v3"
)

func main() {
	cmd := &cli.Command{
		Usage: "yubikey did:plc stuff",
		Commands: []*cli.Command{
			{
				Name:   "init",
				Usage:  "generate a new private key on the yubikey",
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
				Usage:  "print the public key to stdout, in did:key format",
				Action: doPubkey,
			},
			{
				Name:   "sign",
				Usage:  "sign a did:plc operation (reads JSON from stdin)",
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

	// Generate a private key on the YubiKey.
	key := piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   piv.PINPolicyAlways,
		TouchPolicy: piv.TouchPolicyAlways,
	}
	_, err = yk.GenerateKey(piv.DefaultManagementKey, piv.SlotSignature, key)
	if err != nil {
		return err
	}

	fmt.Println("success") // TODO: print pubkey
	return nil
}

func doPubkey(ctx context.Context, cmd *cli.Command) error {
	// TODO
	return nil
}

func doSign(ctx context.Context, cmd *cli.Command) error {
	// TODO
	return nil
}
