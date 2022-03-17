// Copyright 2020 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

//go:build !darwin
// +build !darwin

package main

import (
	"fmt"
	"os"
	"time"

	"github.com/twpayne/go-pinentry-minimal/pinentry"
)

func getPIN(serial uint32, retries int) (string, error) {
	client, err := pinentry.NewClient(
		pinentry.WithBinaryNameFromGnuPGAgentConf(),
		pinentry.WithGPGTTY(),
		pinentry.WithTitle("yubikey-agent PIN Prompt"),
		pinentry.WithDesc(fmt.Sprintf("YubiKey serial number: %d (%d tries remaining)", serial, retries)),
		pinentry.WithPrompt("Please enter your PIN:"),
		// Enable opt-in external PIN caching (in the OS keychain).
		// https://gist.github.com/mdeguzis/05d1f284f931223624834788da045c65#file-info-pinentry-L324
		pinentry.WithOption(pinentry.OptionAllowExternalPasswordCache),
		pinentry.WithKeyInfo(fmt.Sprintf("--yubikey-id-%d", serial)),
	)
	if err != nil {
		return "", err
	}
	defer client.Close()

	for retry := 0; retry < 16; retry++ {
		pin, _, err := client.GetPIN()
		if err == nil && len(pin) > 0 {
			return pin, err
		}

		if len(pin) == 0 {
			fmt.Fprintf(os.Stderr, "Unexpected blank PIN. Retrying getPIN, try #%d\n", retry)
		} else {
			fmt.Fprintf(os.Stderr, "Unexpected error. Retrying getPIN, try #%d: %s\n", err.Error())
		}
		time.Sleep(250 * time.Millisecond)
	}

	return "", err

}
