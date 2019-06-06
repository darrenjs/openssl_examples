.PHONY: all
all: ## make all the targets
	make -C server_src
	make -C client_src

.PHONY: clean
clean: ## clean all the targets
	make -C server_src clean
	make -C client_src clean
	rm -f server client vgcore*

.PHONY: certs
certs: ## gen certificates
	openssl genrsa -out rootCA.key 2048 # generates rootCA key
	openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 1024 -out rootCA.pem # self sign
	openssl genrsa -out server.key 2048 # generate server key
	openssl req -new -key server.key -out server.csr # generate Certificate Signing Request
	openssl x509 -req -in server.csr -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out server.crt -days 500 -sha256 # sign the damn thing
	openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 1024 -out rootCA.pem # self sign
	openssl genrsa -out client.key 2048 # generate client key
	openssl req -new -key client.key -out client.csr # generate Certificate Signing Request
	openssl x509 -req -in client.csr -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out client.crt -days 500 -sha256 # sign the damn thing
	rm *.csr
	cp server.crt server.key rootCA.pem server_src
	cp client.crt client.key rootCA.pem client_src

.PHONY:client_test
client_test: ## run default openssl client
	openssl s_client -connect 127.0.0.1:55555 -msg -debug -state -showcerts

.PHONY:server_test
server_test: ## run default openssl server
	openssl s_server -port 55555 -cert server.crt -key server.key -msg -debug -state -verify 1

.PHONY: help
help:	## display options
	@grep -E '^[a-zA-Z_-]+:.*## .*' Makefile | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

