# Update Fastly Certificates

Go script to update Fastly certificate for a domain with local certificate.

Takes the following args:

```
CONFIG_PATH: Path to config file. (/etc/letsencrypt/renewal/myfile.conf)
DOMAIN_NAME: Domain name of certificates. (example.com)
FASTLY_API_TOKEN: Private key for api requests.
```

To run .go file use:
```
go get "github.com/fastly/go-fastly/fastly"
go run fastly-cert-updater.go **args
```

To build binary from .go file use:
```
go get "github.com/fastly/go-fastly/fastly"
go build
```

To build in container, put args in env then run
```
docker-compose up
```

To run container, create .env file and run
```
docker run --env-file .env fastly-cert-updater_updater
```