package xmlsecurity

import (
	"fmt"
	"testing"

	"github.com/beevik/etree"
	"github.com/deb-ict/go-xml"
)

func Test_Reference_LoadXml_InvalidElement(t *testing.T) {
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
	testCaseResolver := xml.NewXmlResolver(testCaseDocument)

	// Create test case Reference
	testCaseReference, err := NewReference(testCaseResolver)
	if err != nil {
		t.Fatal(err)
	}

	// Load test case Reference
	err = testCaseReference.LoadXml(testCaseResolver, testCaseDocument.Root())
	if err != xml.ErrInvalidElementTag {
		t.Fatal(err)
	}
}

func Test_Reference_LoadXml(t *testing.T) {
	const (
		uri       = "#123"
		valueType = "x509"
	)
	// Create test case
	testCase := struct {
		uri       string
		valueType string
	}{
		uri:       uri,
		valueType: valueType,
	}

	// Create test case XML
	testCaseXml := fmt.Sprintf(
		`<wsse:Reference URI="%s" ValueType="%s" xmlns:wsse="%s"/>`,
		testCase.uri,
		testCase.valueType,
		WsseNamespace,
	)

	// Prepare the test case
	testCaseDocument := etree.NewDocument()
	err := testCaseDocument.ReadFromString(testCaseXml)
	if err != nil {
		t.Fatal(err)
	}
	testCaseResolver := xml.NewXmlResolver(testCaseDocument)

	// Create test case Reference
	testCaseReference, err := NewReference(testCaseResolver)
	if err != nil {
		t.Fatal(err)
	}

	// Load test case Reference
	err = testCaseReference.LoadXml(testCaseResolver, testCaseDocument.Root())
	if err != nil {
		t.Fatal(err)
	}

	// Validate test case Reference
	if testCaseReference.GetUri() != testCase.uri {
		t.Fatalf("Reference.Uri = %s; want %s", testCaseReference.GetUri(), testCase.uri)
	}
	if testCaseReference.GetValueType() != testCase.valueType {
		t.Fatalf("Reference.ValueType = %s; want %s", testCaseReference.GetValueType(), testCase.valueType)
	}
}

func Test_Reference_GetXml(t *testing.T) {
	const (
		uri       = "#123"
		valueType = "x509"
	)
	// Create test case
	testCase := struct {
		uri       string
		valueType string
	}{
		uri:       uri,
		valueType: valueType,
	}

	// Create test case XML
	testCaseXml := fmt.Sprintf(
		`<wsse:Reference URI="%s" ValueType="%s" xmlns:wsse="%s"/>`,
		testCase.uri,
		testCase.valueType,
		WsseNamespace,
	)

	// Prepare the test case
	testCaseDocument := etree.NewDocument()
	testCaseResolver := xml.NewXmlResolver(testCaseDocument)
	testCaseResolver.SetNamespacePrefix("wsse", WsseNamespace)
	err := testCaseDocument.ReadFromString(testCaseXml)
	if err != nil {
		t.Fatal(err)
	}

	// Create test case Reference
	testCaseReference, err := NewReference(testCaseResolver)
	if err != nil {
		t.Fatal(err)
	}
	testCaseReference.SetUri(testCase.uri)
	testCaseReference.SetValueType(testCase.valueType)

	// Get test case Reference XML
	testCaseReferenceElement, err := testCaseReference.GetXml(testCaseResolver)
	if err != nil {
		t.Fatal(err)
	}

	// Add the namespace declarations
	testCaseReferenceElement.CreateAttr("xmlns:wsse", WsseNamespace)
	testCaseReferenceElement.SortAttrs()

	// Get the test case XML
	testCaseDocument.SetRoot(testCaseReferenceElement)
	resultXml, err := testCaseDocument.WriteToString()
	if err != nil {
		t.Fatal(err)
	}

	// Validate test case XML
	if resultXml != testCaseXml {
		t.Fatalf("Reference.GetXml() = %s; want %s", resultXml, testCaseXml)
	}
}
