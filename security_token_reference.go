package xmlsecurity

import (
	"github.com/beevik/etree"
	"github.com/deb-ict/go-xml"
)

type SecurityTokenReference interface {
	xml.XmlNode
	GetId() string
	SetId(id string)
	GetUsage() string
	SetUsage(usage string)
	GetTokenType() string
	SetTokenType(tokenType string)
	GetContent() xml.XmlNode
	SetContent(content xml.XmlNode)
}

type securityTokenReference struct {
	Id        string
	Usage     string
	TokenType string
	Content   xml.XmlNode
}

func NewSecurityTokenReference(resolver xml.XmlResolver) (SecurityTokenReference, error) {
	return &securityTokenReference{}, nil
}

func NewSecurityTokenReferenceNode(resolver xml.XmlResolver) (xml.XmlNode, error) {
	return NewSecurityTokenReference(resolver)
}

func (node *securityTokenReference) GetId() string {
	return node.Id
}

func (node *securityTokenReference) SetId(id string) {
	node.Id = id
}

func (node *securityTokenReference) GetUsage() string {
	return node.Usage
}

func (node *securityTokenReference) SetUsage(usage string) {
	node.Usage = usage
}

func (node *securityTokenReference) GetTokenType() string {
	return node.TokenType
}

func (node *securityTokenReference) SetTokenType(tokenType string) {
	node.TokenType = tokenType
}

func (node *securityTokenReference) GetContent() xml.XmlNode {
	return node.Content
}

func (node *securityTokenReference) SetContent(content xml.XmlNode) {
	node.Content = content
}

func (node *securityTokenReference) LoadXml(resolver xml.XmlResolver, el *etree.Element) error {
	err := xml.ValidateElement(el, "SecurityTokenReference", WsseNamespace)
	if err != nil {
		return err
	}

	node.SetId(GetWsuId(resolver, el))
	node.SetUsage(el.SelectAttrValue("Usage", ""))
	node.SetTokenType(el.SelectAttrValue("TokenType", ""))

	for _, child := range el.ChildElements() {
		namespaceUri := resolver.GetNamespaceUri(child.Space)
		typeConstructor, err := resolver.GetTypeConstructor(namespaceUri, child.Tag)
		if err == xml.ErrNoTypeConstructor {
			continue
		}
		if err != nil {
			return err
		}

		content, err := typeConstructor(resolver)
		if err != nil {
			return err
		}
		err = content.LoadXml(resolver, child)
		if err != nil {
			return err
		}
		node.SetContent(content)
	}

	return nil
}

func (node *securityTokenReference) GetXml(resolver xml.XmlResolver) (*etree.Element, error) {
	el := etree.NewElement("SecurityTokenReference")
	el.Space = resolver.GetNamespacePrefix(WsseNamespace)

	if node.GetId() != "" {
		SetWsuId(resolver, el, node.GetId())
	}
	if node.GetUsage() != "" {
		el.CreateAttr("Usage", node.GetUsage())
	}
	if node.GetTokenType() != "" {
		el.CreateAttr("TokenType", node.GetTokenType())
	}

	if node.GetContent() != nil {
		contentEl, err := node.GetContent().GetXml(resolver)
		if err != nil {
			return nil, err
		}
		el.AddChild(contentEl)
	}

	return el, nil
}
