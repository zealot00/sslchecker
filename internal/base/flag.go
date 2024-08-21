package base

import (
	"flag"
)

type CliArgs struct {
	Host       string
	Port       string
	OutputType string
	OutputPath string
}

func InitFlags() CliArgs {
	host := flag.String("host", "127.0.0.1", "host to connect to")
	port := flag.String("port", "443", "port to connect to")
	outputtype := flag.String("outputtype", "stdout", "output type,you can use stdout or json,default stdout")
	outputpath := flag.String("outputpath", "./", "if you chose json,you should set outputpath.default ./")
	flag.Parse()
	CliArgs := CliArgs{
		Host:       *host,
		Port:       *port,
		OutputType: *outputtype,
		OutputPath: *outputpath,
	}
	return CliArgs
}
