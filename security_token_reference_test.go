package xmlsecurity

import (
	"fmt"
	"testing"

	"github.com/beevik/etree"
	"github.com/deb-ict/go-xml"
)

func Test_SecurityTokenReference_LoadXml_InvalidElement(t *testing.T) {
	// Create test case XML
	testCaseXml := fmt.Sprintf(
		`<wsse:InvalidTag xmlns:wsse="%s"/>`,
		WsseNamespace,
	)

	// Prepare the test case
	testCaseDocument := etree.NewDocument()
	err := testCaseDocument.ReadFromString(testCaseXml)
	if err != nil {
		t.Fatal(err)
	}
	testCaseContext := xml.NewContext(testCaseDocument)

	// Create test case SecurityTokenReference
	testCaseSecurityTokenReference, err := NewSecurityTokenReference(testCaseContext)
	if err != nil {
		t.Fatal(err)
	}

	// Load test case SecurityTokenReference
	err = testCaseSecurityTokenReference.LoadXml(testCaseContext, testCaseDocument.Root())
	if err != xml.ErrInvalidElementTag {
		t.Fatal(err)
	}
}

func Test_SecurityTokenReference_LoadXml(t *testing.T) {
	const (
		id        = "123"
		usage     = "test"
		tokenType = "x509"
	)
	// Create test case
	testCase := struct {
		id        string
		usage     string
		tokenType string
	}{
		id:        id,
		usage:     usage,
		tokenType: tokenType,
	}

	// Create test case XML
	testCaseXml := fmt.Sprintf(
		`<wsse:SecurityTokenReference TokenType="%s" Usage="%s" wsu:Id="%s" xmlns:wsse="%s" xmlns:wsu="%s"/>`,
		testCase.tokenType,
		testCase.usage,
		testCase.id,
		WsseNamespace,
		WsuNamespace,
	)

	// Prepare the test case
	testCaseDocument := etree.NewDocument()
	err := testCaseDocument.ReadFromString(testCaseXml)
	if err != nil {
		t.Fatal(err)
	}
	testCaseContext := xml.NewContext(testCaseDocument)
	testCaseContext.SetNamespacePrefix("wsu", WsuNamespace)

	// Create test case Reference
	testCaseSecurityTokenReference, err := NewSecurityTokenReference(testCaseContext)
	if err != nil {
		t.Fatal(err)
	}

	// Load test case Reference
	err = testCaseSecurityTokenReference.LoadXml(testCaseContext, testCaseDocument.Root())
	if err != nil {
		t.Fatal(err)
	}

	// Validate test case Reference
	if testCaseSecurityTokenReference.GetId() != testCase.id {
		t.Fatalf("SecurityTokenReference.Id = %s; want %s", testCaseSecurityTokenReference.GetId(), testCase.id)
	}
	if testCaseSecurityTokenReference.GetUsage() != testCase.usage {
		t.Fatalf("SecurityTokenReference.Usage = %s; want %s", testCaseSecurityTokenReference.GetUsage(), testCase.usage)
	}
	if testCaseSecurityTokenReference.GetTokenType() != testCase.tokenType {
		t.Fatalf("SecurityTokenReference.TokenType = %s; want %s", testCaseSecurityTokenReference.GetTokenType(), testCase.tokenType)
	}
}

func Test_SecurityTokenReference_LoadXml_WithReference(t *testing.T) {
	const (
		id        = "123"
		usage     = "test"
		tokenType = "x509"
	)
	// Create test case
	testCase := struct {
		id        string
		usage     string
		tokenType string
	}{
		id:        id,
		usage:     usage,
		tokenType: tokenType,
	}

	// Create test case XML
	testCaseXml := fmt.Sprintf(
		`<wsse:SecurityTokenReference TokenType="%s" Usage="%s" wsu:Id="%s" xmlns:wsse="%s" xmlns:wsu="%s"><wsse:Reference URI="#123"/></wsse:SecurityTokenReference>`,
		testCase.tokenType,
		testCase.usage,
		testCase.id,
		WsseNamespace,
		WsuNamespace,
	)

	// Prepare the test case
	testCaseDocument := etree.NewDocument()
	err := testCaseDocument.ReadFromString(testCaseXml)
	if err != nil {
		t.Fatal(err)
	}
	testCaseContext := xml.NewContext(testCaseDocument)
	testCaseContext.SetNamespacePrefix("wsu", WsuNamespace)
	testCaseContext.SetNamespacePrefix("wsse", WsseNamespace)
	testCaseContext.RegisterTypeConstructor(WsseNamespace, "Reference", NewReferenceNode)

	// Create test case Reference
	testCaseSecurityTokenReference, err := NewSecurityTokenReference(testCaseContext)
	if err != nil {
		t.Fatal(err)
	}

	// Load test case Reference
	err = testCaseSecurityTokenReference.LoadXml(testCaseContext, testCaseDocument.Root())
	if err != nil {
		t.Fatal(err)
	}

	// Validate test case Reference
	if testCaseSecurityTokenReference.GetId() != testCase.id {
		t.Fatalf("SecurityTokenReference.Id = %s; want %s", testCaseSecurityTokenReference.GetId(), testCase.id)
	}
	if testCaseSecurityTokenReference.GetUsage() != testCase.usage {
		t.Fatalf("SecurityTokenReference.Usage = %s; want %s", testCaseSecurityTokenReference.GetUsage(), testCase.usage)
	}
	if testCaseSecurityTokenReference.GetTokenType() != testCase.tokenType {
		t.Fatalf("SecurityTokenReference.TokenType = %s; want %s", testCaseSecurityTokenReference.GetTokenType(), testCase.tokenType)
	}

	testCaseContent := testCaseSecurityTokenReference.GetContent()
	if testCaseContent == nil {
		t.Fatal("SecurityTokenReference.Content = nil; want not nil")
	}
	testCaseReference, ok := testCaseContent.(Reference)
	if !ok {
		t.Fatalf("SecurityTokenReference.Content = %T; want Reference", testCaseContent)
	}
	if testCaseReference.GetUri() != "#123" {
		t.Fatalf("SecurityTokenReference.Content.Uri = %s; want #123", testCaseReference.GetUri())
	}
}

func Test_SecurityTokenReference_GetXml(t *testing.T) {
	const (
		id        = "123"
		usage     = "test"
		tokenType = "x509"
	)
	// Create test case
	testCase := struct {
		id        string
		usage     string
		tokenType string
	}{
		id:        id,
		usage:     usage,
		tokenType: tokenType,
	}

	// Create test case XML
	testCaseXml := fmt.Sprintf(
		`<wsse:SecurityTokenReference TokenType="%s" Usage="%s" wsu:Id="%s" xmlns:wsse="%s" xmlns:wsu="%s"/>`,
		testCase.tokenType,
		testCase.usage,
		testCase.id,
		WsseNamespace,
		WsuNamespace,
	)

	// Prepare the test case
	testCaseDocument := etree.NewDocument()
	testCaseContext := xml.NewContext(testCaseDocument)
	testCaseContext.SetNamespacePrefix("wsse", WsseNamespace)
	testCaseContext.SetNamespacePrefix("wsu", WsuNamespace)

	// Create test case SecurityTokenReference
	testCaseSecurityTokenReference, err := NewSecurityTokenReference(testCaseContext)
	if err != nil {
		t.Fatal(err)
	}
	testCaseSecurityTokenReference.SetId(testCase.id)
	testCaseSecurityTokenReference.SetUsage(testCase.usage)
	testCaseSecurityTokenReference.SetTokenType(testCase.tokenType)

	// Get test case SecurityTokenReference XML
	testCaseSecurityTokenReferenceElement, err := testCaseSecurityTokenReference.GetXml(testCaseContext)
	if err != nil {
		t.Fatal(err)
	}

	// Add the namespace declarations
	testCaseSecurityTokenReferenceElement.CreateAttr("xmlns:wsse", WsseNamespace)
	testCaseSecurityTokenReferenceElement.CreateAttr("xmlns:wsu", WsuNamespace)
	testCaseSecurityTokenReferenceElement.SortAttrs()

	// Get the test case XML
	testCaseDocument.SetRoot(testCaseSecurityTokenReferenceElement)
	resultXml, err := testCaseDocument.WriteToString()
	if err != nil {
		t.Fatal(err)
	}

	// Validate test case XML
	if resultXml != testCaseXml {
		t.Fatalf("SecurityTokenReference.GetXml() = %s; want %s", resultXml, testCaseXml)
	}
}

func Test_SecurityTokenReference_GetXml_WithReference(t *testing.T) {
	const (
		id        = "123"
		usage     = "test"
		tokenType = "x509"
	)
	// Create test case
	testCase := struct {
		id        string
		usage     string
		tokenType string
	}{
		id:        id,
		usage:     usage,
		tokenType: tokenType,
	}

	// Create test case XML
	testCaseXml := fmt.Sprintf(
		`<wsse:SecurityTokenReference TokenType="%s" Usage="%s" wsu:Id="%s" xmlns:wsse="%s" xmlns:wsu="%s"><wsse:Reference URI="#123"/></wsse:SecurityTokenReference>`,
		testCase.tokenType,
		testCase.usage,
		testCase.id,
		WsseNamespace,
		WsuNamespace,
	)

	// Prepare the test case
	testCaseDocument := etree.NewDocument()
	testCaseContext := xml.NewContext(testCaseDocument)
	testCaseContext.SetNamespacePrefix("wsse", WsseNamespace)
	testCaseContext.SetNamespacePrefix("wsu", WsuNamespace)

	// Create test case SecurityTokenReference
	testCaseSecurityTokenReference, err := NewSecurityTokenReference(testCaseContext)
	if err != nil {
		t.Fatal(err)
	}
	testCaseSecurityTokenReference.SetId(testCase.id)
	testCaseSecurityTokenReference.SetUsage(testCase.usage)
	testCaseSecurityTokenReference.SetTokenType(testCase.tokenType)

	// Create test case Reference
	testCaseReference, err := NewReference(testCaseContext)
	if err != nil {
		t.Fatal(err)
	}
	testCaseReference.SetUri("#123")
	testCaseSecurityTokenReference.SetContent(testCaseReference)

	// Get test case SecurityTokenReference XML
	testCaseSecurityTokenReferenceElement, err := testCaseSecurityTokenReference.GetXml(testCaseContext)
	if err != nil {
		t.Fatal(err)
	}

	// Add the namespace declarations
	testCaseSecurityTokenReferenceElement.CreateAttr("xmlns:wsse", WsseNamespace)
	testCaseSecurityTokenReferenceElement.CreateAttr("xmlns:wsu", WsuNamespace)
	testCaseSecurityTokenReferenceElement.SortAttrs()

	// Get the test case XML
	testCaseDocument.SetRoot(testCaseSecurityTokenReferenceElement)
	resultXml, err := testCaseDocument.WriteToString()
	if err != nil {
		t.Fatal(err)
	}

	// Validate test case XML
	if resultXml != testCaseXml {
		t.Fatalf("SecurityTokenReference.GetXml() = %s; want %s", resultXml, testCaseXml)
	}
}
