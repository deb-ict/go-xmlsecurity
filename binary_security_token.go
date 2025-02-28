package xmlsecurity

import (
	"github.com/beevik/etree"
	"github.com/deb-ict/go-xml"
)

type BinarySecurityToken interface {
	xml.XmlNode
	GetId() string
	SetId(id string)
	GetValueType() string
	SetValueType(valueType string)
	GetEncodingType() string
	SetEncodingType(encodingType string)
	GetValue() string
	SetValue(value string)
}

type binarySecurityToken struct {
	Id           string
	ValueType    string
	EncodingType string
	Value        string
}

func NewBinarySecurityToken(resolver xml.XmlResolver) (BinarySecurityToken, error) {
	return &binarySecurityToken{}, nil
}

func NewBinarySecurityTokenNode(resolver xml.XmlResolver) (xml.XmlNode, error) {
	return NewBinarySecurityToken(resolver)
}

func (node *binarySecurityToken) GetId() string {
	return node.Id
}

func (node *binarySecurityToken) SetId(id string) {
	node.Id = id
}

func (node *binarySecurityToken) GetValueType() string {
	return node.ValueType
}

func (node *binarySecurityToken) SetValueType(valueType string) {
	node.ValueType = valueType
}

func (node *binarySecurityToken) GetEncodingType() string {
	return node.EncodingType
}

func (node *binarySecurityToken) SetEncodingType(encodingType string) {
	node.EncodingType = encodingType
}

func (node *binarySecurityToken) GetValue() string {
	return node.Value
}

func (node *binarySecurityToken) SetValue(value string) {
	node.Value = value
}

func (node *binarySecurityToken) LoadXml(resolver xml.XmlResolver, el *etree.Element) error {
	err := xml.ValidateElement(el, "BinarySecurityToken", WsseNamespace)
	if err != nil {
		return err
	}

	node.SetId(GetWsuId(resolver, el))
	node.SetValueType(el.SelectAttrValue("ValueType", ""))
	node.SetEncodingType(el.SelectAttrValue("EncodingType", ""))
	node.SetValue(el.Text())

	return nil
}

func (node *binarySecurityToken) GetXml(resolver xml.XmlResolver) (*etree.Element, error) {
	el := etree.NewElement("BinarySecurityToken")
	el.Space = resolver.GetNamespacePrefix(WsseNamespace)

	if node.GetId() != "" {
		SetWsuId(resolver, el, node.GetId())
	}
	if node.GetValueType() != "" {
		el.CreateAttr("ValueType", node.GetValueType())
	}
	if node.GetEncodingType() != "" {
		el.CreateAttr("EncodingType", node.GetEncodingType())
	}
	el.SetText(node.Value)

	return el, nil
}
