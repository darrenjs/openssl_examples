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
	openssl genrsa -des3 -passout pass:ABCD -out server.pass.key 2048
	openssl rsa -passin pass:ABCD -in server.pass.key -out server.key
	rm -f server.pass.key
	openssl req -new -key server.key -out server.csr
	openssl x509 -req -sha256 -days 365 -in server.csr -signkey server.key -out server.crt
	rm -f server.csr
	openssl genrsa -des3 -passout pass:ABCD -out client.pass.key 2048
	openssl rsa -passin pass:ABCD -in client.pass.key -out client.key
	rm -f client.pass.key
	openssl req -new -key client.key -out client.csr
	openssl x509 -req -sha256 -days 365 -in client.csr -signkey client.key -out client.crt
	rm -f client.csr
	cp server.crt server.key server_src
	cp client.crt client.key client_src

.PHONY: help
help:	## display options
	@grep -E '^[a-zA-Z_-]+:.*## .*' Makefile | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
