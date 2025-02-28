package xmlsecurity

import (
	"github.com/beevik/etree"
	"github.com/deb-ict/go-xml"
)

type Reference interface {
	xml.XmlNode
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
