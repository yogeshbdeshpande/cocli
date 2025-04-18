// Copyright 2021-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"github.com/veraison/corim/cots"
	"github.com/veraison/swid"
)

var (
	corimCreateCorimFile   *string
	corimCreateCoswidFiles []string
	corimCreateCoswidDirs  []string
	corimCreateComidFiles  []string
	corimCreateComidDirs   []string
	corimCreateCotsFiles   []string
	corimCreateCotsDirs    []string
	corimCreateOutputFile  *string
)

var corimCreateCmd = NewCorimCreateCmd()

func NewCorimCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "create a CBOR-encoded CoRIM from the supplied JSON template, CoMID(s), CoSWID(s) and/or CoTS",
		Long: `create a CBOR-encoded CoRIM from the supplied JSON template, CoMID(s), CoSWID(s) and/or CoTS,

	Create a CoRIM from template t1.json, adding CoMIDs found in the comid/
	directory, CoSWIDs found in the coswid/ directory and CoTS found in the cots/ directory.  Since no explicit
	output file is set, the (unsigned) CoRIM is saved to the current directory
	with tag-id as basename and a .cbor extension.

	  cocli corim create --template=t1.json --comid-dir=comid --coswid-dir=coswid --cots-dir=cots
	 
	Create a CoRIM from template corim-template.json, adding CoMID stored in
	comid1.cbor and the two CoSWIDs stored in coswid1.cbor and dir/coswid2.cbor
	and a CoTS stored in cots1.cbor.
	The (unsigned) CoRIM is saved to corim.cbor.

	  cocli corim create --template=corim-template.json \
	                   --comid=comid1.cbor \
	                   --coswid=coswid1.cbor \
	                   --coswid=dir/coswid2.cbor \
					   --cots=cots1.cbor
	                   --output=corim.cbor
	`,

		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkCorimCreateArgs(); err != nil {
				return err
			}

			comidFilesList := filesList(corimCreateComidFiles, corimCreateComidDirs, ".cbor")
			coswidFilesList := filesList(corimCreateCoswidFiles, corimCreateCoswidDirs, ".cbor")
			cotsFilesList := filesList(corimCreateCotsFiles, corimCreateCotsDirs, ".cbor")

			if len(comidFilesList)+len(coswidFilesList)+len(cotsFilesList) == 0 {
				return errors.New("no CoMID, CoSWID or CoTS files found")
			}

			// checkCorimCreateArgs makes sure corimCreateCorimFile is not nil
			cborFile, err := corimTemplateToCBOR(*corimCreateCorimFile,
				comidFilesList, coswidFilesList, cotsFilesList, corimCreateOutputFile)
			if err != nil {
				return err
			}
			fmt.Printf(">> created %q from %q\n", cborFile, *corimCreateCorimFile)

			return nil
		},
	}

	corimCreateCorimFile = cmd.Flags().StringP("template", "t", "", "a CoRIM template file (in JSON format)")

	cmd.Flags().StringArrayVarP(
		&corimCreateComidDirs, "comid-dir", "M", []string{}, "a directory containing CBOR-encoded CoMID files",
	)

	cmd.Flags().StringArrayVarP(
		&corimCreateComidFiles, "comid", "m", []string{}, "a CBOR-encoded CoMID file",
	)

	cmd.Flags().StringArrayVarP(
		&corimCreateCoswidDirs, "coswid-dir", "S", []string{}, "a directory containing CBOR-encoded CoSWID files",
	)

	cmd.Flags().StringArrayVarP(
		&corimCreateCoswidFiles, "coswid", "s", []string{}, "a CBOR-encoded CoSWID file",
	)

	cmd.Flags().StringArrayVarP(
		&corimCreateCotsDirs, "cots-dir", "C", []string{}, "a directory containing CBOR-encoded CoTS files",
	)

	cmd.Flags().StringArrayVarP(
		&corimCreateCotsFiles, "cots", "c", []string{}, "a CBOR-encoded CoTS file",
	)

	corimCreateOutputFile = cmd.Flags().StringP("output", "o", "", "name of the generated (unsigned) CoRIM file")

	return cmd
}

func checkCorimCreateArgs() error {
	if corimCreateCorimFile == nil || *corimCreateCorimFile == "" {
		return errors.New("no CoRIM template supplied")
	}

	if len(corimCreateComidDirs)+len(corimCreateComidFiles)+
		len(corimCreateCoswidDirs)+len(corimCreateCoswidFiles)+
		len(corimCreateCotsDirs)+len(corimCreateCotsFiles) == 0 {
		return errors.New("no CoMID, CoSWID or CoTS files or folders supplied")
	}

	return nil
}

func corimTemplateToCBOR(tmplFile string, comidFiles, coswidFiles, cotsFiles []string, outputFile *string) (string, error) {
	var (
		tmplData, corimCBOR []byte
		c                   corim.UnsignedCorim
		corimFile           string
		err                 error
	)

	if tmplData, err = afero.ReadFile(fs, tmplFile); err != nil {
		return "", fmt.Errorf("error loading template from %s: %w", tmplFile, err)
	}

	if err = c.FromJSON(tmplData); err != nil {
		return "", fmt.Errorf("error decoding template from %s: %w", tmplFile, err)
	}

	// append CoMID(s)
	for _, comidFile := range comidFiles {
		var (
			comidCBOR []byte
			m         comid.Comid
		)

		comidCBOR, err = afero.ReadFile(fs, comidFile)
		if err != nil {
			return "", fmt.Errorf("error loading CoMID from %s: %w", comidFile, err)
		}

		err = m.FromCBOR(comidCBOR)
		if err != nil {
			return "", fmt.Errorf("error loading CoMID from %s: %w", comidFile, err)
		}

		if c.AddComid(&m) == nil {
			return "", fmt.Errorf(
				"error adding CoMID from %s (check its validity using the %q sub-command)",
				comidFile, "comid validate",
			)
		}
	}

	// append CoSWID(s)
	for _, coswidFile := range coswidFiles {
		var (
			coswidCBOR []byte
			s          swid.SoftwareIdentity
		)

		coswidCBOR, err = afero.ReadFile(fs, coswidFile)
		if err != nil {
			return "", fmt.Errorf("error loading CoSWID from %s: %w", coswidFile, err)
		}

		err = s.FromCBOR(coswidCBOR)
		if err != nil {
			return "", fmt.Errorf("error loading CoSWID from %s: %w", coswidFile, err)
		}

		if c.AddCoswid(&s) == nil {
			return "", fmt.Errorf("error adding CoSWID from %s", coswidFile)
		}
	}

	// append CoTS(s)
	for _, cotsFile := range cotsFiles {
		var (
			cotsCBOR []byte
			t        cots.ConciseTaStore
		)

		cotsCBOR, err = afero.ReadFile(fs, cotsFile)
		if err != nil {
			return "", fmt.Errorf("error loading CoTS from %s: %w", cotsFile, err)
		}

		err = t.FromCBOR(cotsCBOR)
		if err != nil {
			return "", fmt.Errorf("error loading CoTS from %s: %w", cotsFile, err)
		}

		if c.AddCots(&t) == nil {
			return "", fmt.Errorf("error adding CoTS from %s", cotsFile)
		}
	}

	// check the result
	if err = c.Valid(); err != nil {
		return "", fmt.Errorf("error validating CoRIM: %w", err)
	}

	corimCBOR, err = c.ToCBOR()
	if err != nil {
		return "", fmt.Errorf("error encoding CoRIM to CBOR: %w", err)
	}

	if outputFile == nil || *outputFile == "" {
		corimFile = makeFileName("", tmplFile, ".cbor")
	} else {
		corimFile = *outputFile
	}

	err = afero.WriteFile(fs, corimFile, corimCBOR, 0644)
	if err != nil {
		return "", fmt.Errorf("error saving CoRIM to file %s: %w", corimFile, err)
	}

	return corimFile, nil
}

func init() {
	corimCmd.AddCommand(corimCreateCmd)
}
