# sslchecker
When it is tormented by various compliance, it leaves a small tool for testing the TLS status of the corresponding address, the algorithm, the configuration of various header information, etc


# Usage 
go build main.go 
```
./main -h  
  -host string 
        host to connect to (default "127.0.0.1")  
  -outputpath string  
        if you chose json,you should set outputpath.default ./ (default "./")  
  -outputtype string  
        output type,you can use stdout or json,default stdout (default "stdout")  
  -port string  
        port to connect to (default "443")   
```

# Options  
- host string
- port string
- outputpath string if you chose json, you should set outputpath.default ./
- outputtype striing output type,you can use stdout or json,default stdout. //TODO