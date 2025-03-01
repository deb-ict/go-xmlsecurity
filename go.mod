module github.com/deb-ict/go-xmlsecurity

go 1.23.1

toolchain go1.23.6

require (
	github.com/beevik/etree v1.5.0
	github.com/deb-ict/go-xml v0.0.1-alpha
)

replace (
	github.com/deb-ict/go-xml v0.0.1-alpha => ../go-xml
)