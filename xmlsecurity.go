package xmlsecurity

import "github.com/deb-ict/go-xml"

const (
	WsuNamespace    string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	WsseNamespace   string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	Wsse11Namespace string = "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd"
)

func ConfigureResolver(resolver xml.XmlResolver) {
	resolver.SetNamespacePrefix("wsu", WsuNamespace)
	resolver.SetNamespacePrefix("wsse", WsseNamespace)
	resolver.SetNamespacePrefix("wsse11", Wsse11Namespace)

	resolver.RegisterTypeConstructor(WsseNamespace, "BinarySecurityToken", NewBinarySecurityTokenNode)
	resolver.RegisterTypeConstructor(WsseNamespace, "SecurityTokenReference", NewSecurityTokenReferenceNode)
	resolver.RegisterTypeConstructor(WsseNamespace, "Reference", NewReferenceNode)
}
