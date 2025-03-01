package xmlsecurity

import (
	"crypto/x509"

	"github.com/deb-ict/go-xml"
)

type X509CertificateProvider interface {
	GetX509Certificate(context xml.Context) (*x509.Certificate, error)
}
