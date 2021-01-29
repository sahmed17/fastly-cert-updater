package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/fastly/go-fastly/fastly"
)

func init() {
	log.SetOutput(os.Stdout)
}

func uploadCert(client *fastly.Client, cert, chain, key []byte, domainName, latestCertID string) {
	// Create private key
	log.Println("INFO Uploading private key.")
	_, keyErr := client.CreatePrivateKey(&fastly.CreatePrivateKeyInput{
		Key:  string(key[:]),
		Name: domainName,
	})
	if keyErr != nil {
		log.Fatal("FATAL Problem uploading private key. " + keyErr.Error())
	}

	// Create certificate
	log.Println("INFO Uploading fullchain.")
	// Format data for post request
	encodedData := []byte(`{"data":{"type":"tls_certificate","attributes":{"cert_blob":"` +
		strings.Replace(string(cert[:]), "\n", "\\n", -1) + `","intermediates_blob":"` +
		strings.Replace(string(chain[:]), "\n", "\\n", -1) + `","name":"` + domainName + `"}}}`)
	var postData interface{}
	err := json.Unmarshal(encodedData, &postData)
	if err != nil {
		log.Fatal("FATAL Problem creating json. " + err.Error())
	}

	postResp, err := client.PostJSON("/tls/certificates", postData, &fastly.RequestOptions{})
	if err != nil {
		log.Fatal("FATAL Problem uploading certificate. " + err.Error())
	}
	defer postResp.Body.Close()

	// Check if post request succeeded (201 Created)
	if postResp.StatusCode == 201 {
		// Remove old cert if exists
		if latestCertID != "" {
			log.Println("INFO Deleting old cert.")
			delResp, err := client.Delete("/tls/certificates/"+latestCertID, &fastly.RequestOptions{})
			if err != nil {
				log.Println("ERROR Problem deleting old certificate. " + err.Error())
			}
			defer delResp.Body.Close()
			log.Println("INFO Successfully updated certificate!")
		}
	} else {
		log.Fatal("FATAL Problem uploading certificate. Status: " + postResp.Status)
	}
}

// Structs for certificate list returned by GET /tls/certificates
type CertAttributes struct {
	Created_At          *time.Time
	Issued_To           string
	Issuer              string
	Name                string
	Not_After           *time.Time
	Not_Before          *time.Time
	Replace             bool
	Serial_Number       string
	Signature_Algorithm string
	Updated_At          *time.Time
}

type CertDomainData struct {
	ID   string
	Type string
}

type CertDomains struct {
	Data *[]CertDomainData
}

type CertRelationships struct {
	TLS_Domains CertDomains
}

type CertData struct {
	ID            string
	Type          string
	Attributes    CertAttributes
	Relationships CertRelationships
}

type CertLinks struct {
	Self  string
	First string
	Prev  string
	Next  string
	Last  string
}

type CertMeta struct {
	Per_Page     int
	Current_Page int
	Record_Count int
	Total_Pages  int
}

type CertResponse struct {
	Data  *[]CertData
	Links CertLinks
	Meta  CertMeta
}

func main() {
	// Check help flag
	helpText := `This is a Go script to update Fastly certificate for a domain with local certificate.

Takes the following args:

config-path: Path to config file. (/etc/letsencrypt/renewal/online-dev.syr.edu.conf)
domain-name: Domain name of certificates. (online-dev.syr.edu)
fastly-api-token: Private key for api requests.
`

	help := flag.Bool("help", false, "Displays the following: \n"+helpText)

	flag.Parse()

	if *help {
		fmt.Println(helpText)
		os.Exit(0)
	}

	// Gets args
	if len(os.Args) != 4 {
		log.Fatal("FATAL Error reading args. Must pass 3 arguments: Path to renewal config file, domain name, and fastly api token. Use -help flag for more info.")
	}

	renewalConf := os.Args[1]
	domainName := os.Args[2]
	fastlyToken := os.Args[3]

	// Get cert and key paths
	log.Println("INFO Retrieving local certificate.")
	configFile, err := ioutil.ReadFile(renewalConf)
	if err != nil {
		log.Fatal("FATAL Error with renewal config path given. " + err.Error())
	}
	config := string(configFile)

	pat := regexp.MustCompile(`cert = .*`)
	substring := pat.FindString(config)
	cert_path := strings.TrimSuffix(strings.Split(substring, "= ")[1], "\r")

	pat = regexp.MustCompile(`privkey = .*`)
	substring = pat.FindString(config)
	key_path := strings.TrimSuffix(strings.Split(substring, "= ")[1], "\r")

	pat = regexp.MustCompile(`chain = .*`)
	substring = pat.FindString(config)
	chain_path := strings.TrimSuffix(strings.Split(substring, "= ")[1], "\r")

	pat = regexp.MustCompile(`fullchain = .*`)
	substring = pat.FindString(config)
	fullchain_path := strings.TrimSuffix(strings.Split(substring, "= ")[1], "\r")

	// Get cert and key
	cert, err := ioutil.ReadFile(cert_path)
	if err != nil {
		log.Fatal("FATAL " + err.Error())
	}
	chain, err := ioutil.ReadFile(chain_path)
	if err != nil {
		log.Fatal("FATAL " + err.Error())
	}
	fullchain, err := ioutil.ReadFile(fullchain_path)
	if err != nil {
		log.Fatal("FATAL " + err.Error())
	}
	key, err := ioutil.ReadFile(key_path)
	if err != nil {
		log.Fatal("FATAL " + err.Error())
	}

	// Check if empty
	log.Println("INFO Validating local certificate.")
	if (string(cert[:]) == "") || (string(chain[:]) == "") || (string(fullchain[:]) == "") || (string(key[:]) == "") {
		log.Fatal("FATAL Empty .pem files.")
	}

	// Create cert obj
	block, _ := pem.Decode(fullchain)
	if block == nil {
		log.Fatal("FATAL Failed to decode fullchain.")
	}
	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal("FATAL Failed to parse certificate: " + err.Error())
	}

	// Validate domain
	verifyErr := parsedCert.VerifyHostname(domainName)
	if verifyErr != nil {
		log.Fatal("FATAL Failed to verify certificate with given domain name. " + verifyErr.Error())
	}

	// Get date 30 days from now
	thirtyDays := time.Now().AddDate(0, 0, 30).UTC()

	// Validate date
	expDate := parsedCert.NotAfter
	if thirtyDays.After(expDate) {
		log.Fatal("FATAL Certificate provided has expired or expires in 30 days.")
	}

	// Validate cert/key pair
	_, tlsErr := tls.LoadX509KeyPair(fullchain_path, key_path)
	if tlsErr != nil {
		log.Fatal("FATAL " + tlsErr.Error())
	}

	// Create a client object
	log.Println("INFO Creating Fastly client.")
	client, err := fastly.NewClient(fastlyToken)
	if err != nil {
		log.Fatal("FATAL " + err.Error())
	}

	// Get old cert and key
	log.Println("INFO Retrieving Fastly certificate.")
	// Create variables
	url := "/tls/certificates"
	nextUrl := url
	var latestCertExp *time.Time
	latestCertID := ""
	// Set flag to break to
outside:
	// Iterate through each certificate to find one with relevant domain
	for nextUrl != "" {
		resp, err := client.Get(url, &fastly.RequestOptions{})
		if err != nil {
			log.Fatal("FATAL Invalid fastly api token provided. " + err.Error())
		}
		defer resp.Body.Close()
		// Decode response body to go struct
		var data CertResponse
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			log.Fatal("FATAL " + err.Error())
		}
		// Iterate through each certificate on current page
		for _, certData := range *data.Data {
			// Iterate through each domain name on current certificate
			for _, domain := range *certData.Relationships.TLS_Domains.Data {
				if domain.ID == domainName {
					latestCertID = certData.ID
					latestCertExp = certData.Attributes.Not_After
					break outside
				}
			}
		}
		// Save url to next page
		nextUrl = data.Links.Next
	}

	// Upload cert if none exists
	if latestCertID == "" {
		log.Println("INFO No certificate is available. Uploading local cert.")
		uploadCert(client, cert, chain, key, domainName, latestCertID)
	} else { // Upload cert if old one expires in 30 days
		if thirtyDays.After(*latestCertExp) {
			log.Println("INFO Certificate is old. Uploading local cert.")
			uploadCert(client, cert, chain, key, domainName, latestCertID)
		} else {
			log.Println("INFO Old certificate does not expire in 30 days. Nothing changed.")
		}
	}
}
