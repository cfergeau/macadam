package registry

import (
	"github.com/spf13/cobra"
)

type CliCommand struct {
	Command *cobra.Command
	Parent  *cobra.Command
}

var (
	exitCode = 0

	// Commands holds the cobra.Commands to present to the user, including
	// parent if not a child of "root"
	Commands []CliCommand
)

func SetExitCode(code int) {
	exitCode = code
}

func GetExitCode() int {
	return exitCode
}
