package xmlsecurity

import (
	"crypto/x509"
	"errors"
	"strings"

	"github.com/beevik/etree"
	"github.com/deb-ict/go-xml"
)

type Reference interface {
	xml.Node
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

func NewReference(context xml.Context) (Reference, error) {
	return &reference{}, nil
}

func NewReferenceNode(context xml.Context) (xml.Node, error) {
	return NewReference(context)
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

func (node *reference) GetX509Certificate(context xml.Context) (*x509.Certificate, error) {
	if strings.HasPrefix(node.GetUri(), "#") {
		uri := node.GetUri()[1:]
		ref := context.GetDocument().FindElement("@Id='" + uri + "'")
		if ref == nil {
			return nil, errors.New("reference not found")
		}

		refConstructor, err := context.GetTypeConstructor(ref.Space, ref.Tag)
		if err != nil {
			return nil, err
		}
		refNode, err := refConstructor(context)
		if err != nil {
			return nil, err
		}
		err = refNode.LoadXml(context, ref)
		if err != nil {
			return nil, err
		}

		provider, ok := refNode.(X509CertificateProvider)
		if !ok {
			return nil, errors.New("reference not a X509CertificateProvider")
		}
		return provider.GetX509Certificate(context)

	} else {
		return nil, errors.New("unsupported URI format")
	}
}

func (node *reference) LoadXml(context xml.Context, el *etree.Element) error {
	err := xml.ValidateElement(el, "Reference", WsseNamespace)
	if err != nil {
		return err
	}

	node.SetUri(el.SelectAttrValue("URI", ""))
	node.SetValueType(el.SelectAttrValue("ValueType", ""))

	return nil
}

func (node *reference) GetXml(context xml.Context) (*etree.Element, error) {
	el := etree.NewElement("Reference")
	el.Space = context.GetNamespacePrefix(WsseNamespace)

	el.CreateAttr("URI", node.GetUri())
	if node.GetValueType() != "" {
		el.CreateAttr("ValueType", node.GetValueType())
	}

	return el, nil
}
