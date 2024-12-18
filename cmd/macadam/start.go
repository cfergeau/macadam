//go:build amd64 || arm64

package main

import (
	"fmt"

	"github.com/cfergeau/macadam/cmd/macadam/registry"
	macadam "github.com/cfergeau/macadam/pkg/machinedriver"
	ldefine "github.com/containers/podman/v5/libpod/define"
	"github.com/containers/podman/v5/pkg/machine"
	"github.com/spf13/cobra"
)

var (
	startCmd = &cobra.Command{
		Use:     "start [options] [MACHINE]",
		Short:   "Start an existing machine",
		Long:    "Start a managed virtual machine ",
		RunE:    start,
		Args:    cobra.MaximumNArgs(1),
		Example: `macadam start podman-machine-default`,
	}
	startOpts = machine.StartOptions{}
)

func init() {
	registry.Commands = append(registry.Commands, registry.CliCommand{
		Command: startCmd,
	})

	flags := startCmd.Flags()
	noInfoFlagName := "no-info"
	flags.BoolVar(&startOpts.NoInfo, noInfoFlagName, false, "Suppress informational tips")

	quietFlagName := "quiet"
	flags.BoolVarP(&startOpts.Quiet, quietFlagName, "q", false, "Suppress machine starting status output")
}

func start(_ *cobra.Command, args []string) error {
	machineName := defaultMachineName
	if len(args) > 0 {
		if len(args[0]) > maxMachineNameSize {
			return fmt.Errorf("machine name %q must be %d characters or less", args[0], maxMachineNameSize)
		}
		machineName = args[0]

		if !ldefine.NameRegex.MatchString(initOpts.Name) {
			return fmt.Errorf("invalid name %q: %w", initOpts.Name, ldefine.RegexError)
		}
	}
	driver, err := macadam.GetDriverByMachineName(machineName)
	if err != nil {
		return err
	}

	// we cannot start the start command if it was not init immediately before
	return driver.Start()
}
