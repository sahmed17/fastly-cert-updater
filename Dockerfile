FROM golang:latest

RUN mkdir /build/
RUN go get "github.com/fastly/go-fastly/fastly"
COPY fastly-cert-updater.go /go/fastly-cert-updater.go
RUN chmod +x /go/fastly-cert-updater.go
RUN go build
RUN mv /go/go /build/update-cert

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"] 
