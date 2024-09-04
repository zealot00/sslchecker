package main

import (
	"fmt"
	"sslchecker/internal/base"
	"sslchecker/pkg/cli"
	"sslchecker/pkg/scanner"
)

func main() {
	fmt.Println(cli.Banner)
	fmt.Println(cli.Banner_Step)
	args := base.InitFlags()
	hostname := fmt.Sprintf("%s:%s", args.Host, args.Port)
	url := "https://" + hostname

	sslchecker := scanner.NewSslChecker(hostname)
	sslchecker.GoToCheckVersion()
	sslchecker.GoToCheckCipherSuite()

	headerchecker := scanner.NewHeaderChecker(args.UA, url)
	headerchecker.GoToCheckHeader()

}
