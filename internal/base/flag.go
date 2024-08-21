package base

import (
	"flag"
	"fmt"
	"os"
)

type CliArgs struct {
	Host       string
	Port       string
	UA         string
	OutputType string
	OutputPath string
}

func InitFlags() CliArgs {
	host := flag.String("host", "127.0.0.1", "host to connect to")
	port := flag.String("port", "443", "port to connect to")
	useragent := flag.String("useragent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36", "useragent")
	outputtype := flag.String("outputtype", "stdout", "output type,you can use stdout or json,default stdout")
	outputpath := flag.String("outputpath", "./", "if you chose json,you should set outputpath.default ./")

	flag.Parse()
	if len(flag.Args()) == 0 {
		fmt.Println("waring: not enough arguments,Unless you confirm to scan the local loopback address")
		flag.Usage = func() {
			fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
			flag.PrintDefaults()
		}
		//os.Exit(2)
	}
	CliArgs := CliArgs{
		Host:       *host,
		Port:       *port,
		UA:         *useragent,
		OutputType: *outputtype,
		OutputPath: *outputpath,
	}
	return CliArgs
}
