// Command rdcli is a console RustDesk client: remote shell, port forwarding
// and file copy over the RustDesk protocol.
package main

import (
	"os"

	"github.com/bropines/rdcli/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
