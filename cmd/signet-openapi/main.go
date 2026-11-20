// Command signet-openapi prints the OpenAPI description of Signet's HTTP API.
package main

import (
	"fmt"
	"os"

	"github.com/shakibdshy/signet/internal/httpapi"
)

func main() {
	data, err := httpapi.Generate(httpapi.ContractFor())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_, _ = os.Stdout.Write(data)
}
