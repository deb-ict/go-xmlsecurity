package xmlsecurity

import "github.com/deb-ict/go-xml"

const (
	WsuNamespace    string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	WsseNamespace   string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	Wsse11Namespace string = "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd"
)

func ConfigureContext(context xml.Context) {
	context.SetNamespacePrefix("wsu", WsuNamespace)
	context.SetNamespacePrefix("wsse", WsseNamespace)
	context.SetNamespacePrefix("wsse11", Wsse11Namespace)

	context.RegisterTypeConstructor(WsseNamespace, "BinarySecurityToken", NewBinarySecurityTokenNode)
	context.RegisterTypeConstructor(WsseNamespace, "SecurityTokenReference", NewSecurityTokenReferenceNode)
	context.RegisterTypeConstructor(WsseNamespace, "Reference", NewReferenceNode)
}
