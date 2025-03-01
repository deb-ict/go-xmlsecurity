package xmlsecurity

import (
	"crypto/x509"
	"errors"

	"github.com/beevik/etree"
	"github.com/deb-ict/go-xml"
)

type SecurityTokenReference interface {
	xml.Node
	X509CertificateProvider
	GetId() string
	SetId(id string)
	GetUsage() string
	SetUsage(usage string)
	GetTokenType() string
	SetTokenType(tokenType string)
	GetContent() xml.Node
	SetContent(content xml.Node)
}

type securityTokenReference struct {
	Id        string
	Usage     string
	TokenType string
	Content   xml.Node
}

func NewSecurityTokenReference(context xml.Context) (SecurityTokenReference, error) {
	return &securityTokenReference{}, nil
}

func NewSecurityTokenReferenceNode(context xml.Context) (xml.Node, error) {
	return NewSecurityTokenReference(context)
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

func (node *securityTokenReference) GetContent() xml.Node {
	return node.Content
}

func (node *securityTokenReference) SetContent(content xml.Node) {
	node.Content = content
}

func (node *securityTokenReference) GetX509Certificate(context xml.Context) (*x509.Certificate, error) {
	if node.Content == nil {
		return nil, errors.New("x509 certificate not available")
	}
	provider, ok := node.Content.(X509CertificateProvider)
	if !ok {
		return nil, errors.New("x509 certificate not available")
	}

	return provider.GetX509Certificate(context)
}

func (node *securityTokenReference) LoadXml(context xml.Context, el *etree.Element) error {
	err := xml.ValidateElement(el, "SecurityTokenReference", WsseNamespace)
	if err != nil {
		return err
	}

	node.SetId(GetWsuId(context, el))
	node.SetUsage(el.SelectAttrValue("Usage", ""))
	node.SetTokenType(el.SelectAttrValue("TokenType", ""))

	for _, child := range el.ChildElements() {
		namespaceUri := context.GetNamespaceUri(child.Space)
		typeConstructor, err := context.GetTypeConstructor(namespaceUri, child.Tag)
		if err == xml.ErrNoTypeConstructor {
			continue
		}
		if err != nil {
			return err
		}

		content, err := typeConstructor(context)
		if err != nil {
			return err
		}
		err = content.LoadXml(context, child)
		if err != nil {
			return err
		}
		node.SetContent(content)
	}

	return nil
}

func (node *securityTokenReference) GetXml(context xml.Context) (*etree.Element, error) {
	el := etree.NewElement("SecurityTokenReference")
	el.Space = context.GetNamespacePrefix(WsseNamespace)

	if node.GetId() != "" {
		SetWsuId(context, el, node.GetId())
	}
	if node.GetUsage() != "" {
		el.CreateAttr("Usage", node.GetUsage())
	}
	if node.GetTokenType() != "" {
		el.CreateAttr("TokenType", node.GetTokenType())
	}

	if node.GetContent() != nil {
		contentEl, err := node.GetContent().GetXml(context)
		if err != nil {
			return nil, err
		}
		el.AddChild(contentEl)
	}

	return el, nil
}
