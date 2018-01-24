package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/coreos/go-systemd/dbus"
)

var debugOn bool
var tlsOn bool

var clientCertFilePath string
var clientKeyFilePath string

type Checker interface {
	Check() bool
}

type URLChecker struct {
	URL string
}

type SystemdChecker struct {
	UnitName string
}

type serviceProperties struct {
	serviceURL  string
	serviceName string
}

func (c SystemdChecker) Check() bool {

	if c.UnitName != "" {
		systemdConn, err := dbus.NewSystemdConnection()
		if err != nil {
			log.Fatalln("Cant connect to systemd")
		}

		defer systemdConn.Close()

		unitState, err := systemdConn.GetUnitProperty(c.UnitName, "ActiveState")
		if err != nil {
			log.Fatalln("Cant get service state")
		}

		if unitState.Value.String() == "\"active\"" {
			if debugOn {
				log.Print(c.UnitName, " is alive")
			}
			return true
		} else {
			if debugOn {
				log.Print(c.UnitName, " is not alive")
			}
			return false
		}
	}

	return true

}

func tryOpenFile(paramFilePath string) string {
	_, err := os.Stat(paramFilePath)
	if err != nil {
		log.Fatalf("can not open ", paramFilePath, err)
	}
	return paramFilePath
}

func tlsCheck(paramURL string) bool {

	certpair, err := tls.LoadX509KeyPair(clientCertFilePath, clientKeyFilePath)
	if err != nil {
		log.Fatalln("can not load certificate-key pair", err)
	}
	conn, err := tls.Dial("tcp", paramURL, &tls.Config{Certificates: []tls.Certificate{certpair}})
	if err != nil {
		if debugOn {
			log.Print(paramURL, " is not alive or unavailable")
		}
		return false
	}

	defer conn.Close()

	return true
}

func httpCheck(paramURL string) bool {

	client := http.Client{
		Timeout: 10 * time.Second,
	}

	httpcode, err := client.Get(paramURL)
	if err != nil {
		log.Print("cant connect to ", paramURL, err)
		return false
	}

	defer httpcode.Body.Close()

	if strconv.Itoa(httpcode.StatusCode) != "200" {
		if debugOn {
			log.Print(paramURL, " is not alive")
		}
		return false
	}

	if debugOn {
		log.Print(paramURL, " is alive")
	}

	return true
}

func (c URLChecker) Check() bool {
	if c.URL != "" {
		if tlsOn {
			return tlsCheck(c.URL)
		}
		return httpCheck(c.URL)
	}
	return true
}

func makeHandler(checkers []Checker) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		for _, check := range checkers {
			if check.Check() == false {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		w.Write([]byte("Service alive"))
	}
}

func main() {

	unitnamePtr := flag.String("s", "", "systemd unit name")
	urlPtr := flag.String("url", "", "url for check")
	debugPtr := flag.Bool("d", false, "debug mode")
	tlsPtr := flag.Bool("tls", false, "enable tls mode")
	tlscertPrt := flag.String("cert", "server.crt", "path to server certificate")
	tlskeyPrt := flag.String("key", "server.key", "path to server private key")
	locationPrt := flag.String("l", "/healthz", "healthcheck service location")
	portPtr := flag.String("p", "8989", "healthcheck service port")
	ipPtr := flag.String("ip", "", "healthcheck service IP address")
	flag.Parse()

	tlsOn = *tlsPtr
	debugOn = *debugPtr
	listendAddress := *ipPtr + ":" + *portPtr

	if tlsOn {
		clientCertFilePath = tryOpenFile(*tlscertPrt)
		clientKeyFilePath = tryOpenFile(*tlskeyPrt)
	}

	if *unitnamePtr == "" && *urlPtr == "" {
		fmt.Println("no checks defined")
		flag.PrintDefaults()
		os.Exit(1)
	}

	serviceChecks := []Checker{
		SystemdChecker{
			UnitName: *unitnamePtr,
		},
		URLChecker{
			URL: *urlPtr,
		},
	}

	log.Print("Try to start service on ", *ipPtr, ":", *portPtr, *locationPrt)
	http.HandleFunc(*locationPrt, makeHandler(serviceChecks))
	http.ListenAndServe(listendAddress, nil)
}
