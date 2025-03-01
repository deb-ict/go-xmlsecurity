package xmlsecurity

import (
	"github.com/beevik/etree"
	"github.com/deb-ict/go-xml"
)

func GetWsuId(context xml.Context, el *etree.Element) string {
	attr := el.SelectAttr(context.GetNamespacePrefix(WsuNamespace) + ":Id")
	if attr != nil {
		return attr.Value
	}

	return ""
}

func SetWsuId(context xml.Context, el *etree.Element, id string) {
	attr := el.SelectAttr(context.GetNamespacePrefix(WsuNamespace) + ":Id")
	if attr != nil {
		attr.Value = id
		return
	}

	el.CreateAttr(context.GetNamespacePrefix(WsuNamespace)+":Id", id)
}
