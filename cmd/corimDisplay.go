// Copyright 2021-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/veraison/corim/corim"
	"github.com/veraison/corim/cots"
)

var (
	corimDisplayCorimFile *string
	corimDisplayShowTags  *bool
)

var corimDisplayCmd = NewCorimDisplayCmd()

func NewCorimDisplayCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "display",
		Short: "display the content of a CoRIM as JSON",
		Long: `display the content of a CoRIM as JSON

	Display the contents of the signed CoRIM signed-corim.cbor 
	
	  cocli corim display --file signed-corim.cbor

	Display the contents of the signed CoRIM yet-another-signed-corim.cbor and
	also unpack any embedded CoMID, CoSWID and CoTS
	
	  cocli corim display --file yet-another-signed-corim.cbor --show-tags
	`,

		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkCorimDisplayArgs(); err != nil {
				return err
			}

			return display(*corimDisplayCorimFile, *corimDisplayShowTags)
		},
	}

	corimDisplayCorimFile = cmd.Flags().StringP("file", "f", "", "a CoRIM file (in CBOR format)")
	corimDisplayShowTags = cmd.Flags().BoolP("show-tags", "v", false, "display embedded tags")

	return cmd
}

func checkCorimDisplayArgs() error {
	if corimDisplayCorimFile == nil || *corimDisplayCorimFile == "" {
		return errors.New("no CoRIM supplied")
	}

	return nil
}

func display(corimFile string, showTags bool) error {
	var (
		corimCBOR []byte
		err       error
	)

	// read the CoRIM file
	if corimCBOR, err = afero.ReadFile(fs, corimFile); err != nil {
		return fmt.Errorf("error loading CoRIM from %s: %w", corimFile, err)
	}

	// try to decode as a signed CoRIM
	var s corim.SignedCorim
	if err = s.FromCOSE(corimCBOR); err == nil {
		// successfully decoded as signed CoRIM
		metaJSON, err := json.MarshalIndent(&s.Meta, "", "  ")
		if err != nil {
			return fmt.Errorf("error encoding CoRIM Meta from %s: %w", corimFile, err)
		}

		fmt.Println("Meta:")
		fmt.Println(string(metaJSON))

		corimJSON, err := json.MarshalIndent(&s.UnsignedCorim, "", "  ")
		if err != nil {
			return fmt.Errorf("error encoding unsigned CoRIM from %s: %w", corimFile, err)
		}

		fmt.Println("Corim:")
		fmt.Println(string(corimJSON))

		if showTags {
			fmt.Println("Tags:")
			// convert []corim.Tag to [][]byte
			tags := make([][]byte, len(s.UnsignedCorim.Tags))
			for i, tag := range s.UnsignedCorim.Tags {
				tags[i] = tag
			}
			displayTags(tags)
		}

		return nil
	}

	// if decoding as signed CoRIM failed, attempt to decode as unsigned CoRIM
	var u corim.UnsignedCorim
	if err = u.FromCBOR(corimCBOR); err != nil {
		return fmt.Errorf("error decoding CoRIM (signed or unsigned) from %s: %w", corimFile, err)
	}

	// successfully decoded as unsigned CoRIM
	corimJSON, err := json.MarshalIndent(&u, "", "  ")
	if err != nil {
		return fmt.Errorf("error encoding unsigned CoRIM from %s: %w", corimFile, err)
	}

	fmt.Println("Corim:")
	fmt.Println(string(corimJSON))

	if showTags {
		fmt.Println("Tags:")
		// convert []corim.Tag to [][]byte
		tags := make([][]byte, len(u.Tags))
		for i, tag := range u.Tags {
			tags[i] = tag
		}
		displayTags(tags)
	}

	return nil
}

// displayTags processes and displays embedded tags within a CoRIM
func displayTags(tags [][]byte) {
	for i, e := range tags {
		// ensure the tag has at least 4 bytes (3 for tag identifier and 1 for data)
		if len(e) < 4 {
			fmt.Printf(">> skipping malformed tag at index %d\n", i)
			continue
		}

		// Split tag identifier from data
		cborTag, cborData := e[:3], e[3:]

		hdr := fmt.Sprintf(">> [ %d ]", i)

		switch {
		case bytes.Equal(cborTag, corim.ComidTag):
			if err := printComid(cborData, hdr); err != nil {
				fmt.Printf(">> skipping malformed CoMID tag at index %d: %v\n", i, err)
			}
		case bytes.Equal(cborTag, corim.CoswidTag):
			if err := printCoswid(cborData, hdr); err != nil {
				fmt.Printf(">> skipping malformed CoSWID tag at index %d: %v\n", i, err)
			}
		case bytes.Equal(cborTag, cots.CotsTag):
			if err := printCots(cborData, hdr); err != nil {
				fmt.Printf(">> skipping malformed CoTS tag at index %d: %v\n", i, err)
			}
		default:
			fmt.Printf(">> unmatched CBOR tag: %x\n", cborTag)
		}
	}
}

func init() {
	corimCmd.AddCommand(corimDisplayCmd)
}
