package xmlsecurity

import (
	"github.com/beevik/etree"
	"github.com/deb-ict/go-xml"
)

func GetWsuId(resolver xml.XmlResolver, el *etree.Element) string {
	attr := el.SelectAttr(resolver.GetNamespacePrefix(WsuNamespace) + ":Id")
	if attr != nil {
		return attr.Value
	}

	return ""
}

func SetWsuId(resolver xml.XmlResolver, el *etree.Element, id string) {
	attr := el.SelectAttr(resolver.GetNamespacePrefix(WsuNamespace) + ":Id")
	if attr != nil {
		attr.Value = id
		return
	}

	el.CreateAttr(resolver.GetNamespacePrefix(WsuNamespace)+":Id", id)
}
