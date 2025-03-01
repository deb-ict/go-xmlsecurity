package xmlsecurity

import (
	"crypto/x509"
	"errors"
	"strings"

	"github.com/beevik/etree"
	"github.com/deb-ict/go-xml"
)

type Reference interface {
	xml.XmlNode
	X509CertificateProvider
	GetUri() string
	SetUri(uri string)
	GetValueType() string
	SetValueType(valueType string)
}

type reference struct {
	Uri       string
	ValueType string
}

func NewReference(resolver xml.XmlResolver) (Reference, error) {
	return &reference{}, nil
}

func NewReferenceNode(resolver xml.XmlResolver) (xml.XmlNode, error) {
	return NewReference(resolver)
}

func (node *reference) GetUri() string {
	return node.Uri
}

func (node *reference) SetUri(uri string) {
	node.Uri = uri
}

func (node *reference) GetValueType() string {
	return node.ValueType
}

func (node *reference) SetValueType(valueType string) {
	node.ValueType = valueType
}

func (node *reference) GetX509Certificate(resolver xml.XmlResolver) (*x509.Certificate, error) {
	if strings.HasPrefix(node.GetUri(), "#") {
		uri := node.GetUri()[1:]
		ref := resolver.GetDocument().FindElement("@Id='" + uri + "'")
		if ref == nil {
			return nil, errors.New("reference not found")
		}

		refConstructor, err := resolver.GetTypeConstructor(ref.Space, ref.Tag)
		if err != nil {
			return nil, err
		}
		refNode, err := refConstructor(resolver)
		if err != nil {
			return nil, err
		}
		err = refNode.LoadXml(resolver, ref)
		if err != nil {
			return nil, err
		}

		provider, ok := refNode.(X509CertificateProvider)
		if !ok {
			return nil, errors.New("reference not a X509CertificateProvider")
		}
		return provider.GetX509Certificate(resolver)

	} else {
		return nil, errors.New("unsupported URI format")
	}
}

func (node *reference) LoadXml(resolver xml.XmlResolver, el *etree.Element) error {
	err := xml.ValidateElement(el, "Reference", WsseNamespace)
	if err != nil {
		return err
	}

	node.SetUri(el.SelectAttrValue("URI", ""))
	node.SetValueType(el.SelectAttrValue("ValueType", ""))

	return nil
}

func (node *reference) GetXml(resolver xml.XmlResolver) (*etree.Element, error) {
	el := etree.NewElement("Reference")
	el.Space = resolver.GetNamespacePrefix(WsseNamespace)

	el.CreateAttr("URI", node.GetUri())
	if node.GetValueType() != "" {
		el.CreateAttr("ValueType", node.GetValueType())
	}

	return el, nil
}
