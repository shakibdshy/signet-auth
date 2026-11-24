// Command signet-openapi prints the OpenAPI description of Signet's HTTP API.
package main

import (
	"fmt"
	"os"

	"github.com/shakibdshy/signet-auth/internal/httpapi"
)

func main() {
	data, err := httpapi.Generate(httpapi.ContractFor())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(data); err != nil {
		fmt.Fprintln(os.Stderr, "write spec:", err)
		os.Exit(1)
	}
}
