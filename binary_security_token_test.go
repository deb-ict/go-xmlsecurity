package xmlsecurity

import (
	"fmt"
	"testing"

	"github.com/beevik/etree"
	"github.com/deb-ict/go-xml"
)

func Test_BinarySecurityToken_LoadXml_InvalidElement(t *testing.T) {
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

	// Create test case BinarySecurityToken
	testCaseBinarySecurityToken, err := NewBinarySecurityToken(testCaseContext)
	if err != nil {
		t.Fatal(err)
	}

	// Load test case BinarySecurityToken
	err = testCaseBinarySecurityToken.LoadXml(testCaseContext, testCaseDocument.Root())
	if err != xml.ErrInvalidElementTag {
		t.Fatal(err)
	}
}

func Test_BinarySecurityToken_LoadXml(t *testing.T) {
	const (
		id           = "123"
		valueType    = "x509"
		encodingType = "base64"
		value        = "cert_data"
	)
	// Create test case
	testCase := struct {
		id           string
		valueType    string
		encodingType string
		value        string
	}{
		id:           id,
		valueType:    valueType,
		encodingType: encodingType,
		value:        value,
	}

	// Create test case XML
	testCaseXml := fmt.Sprintf(
		`<wsse:BinarySecurityToken EncodingType="%s" ValueType="%s" wsu:Id="%s" xmlns:wsse="%s" xmlns:wsu="%s">%s</wsse:BinarySecurityToken>`,
		testCase.encodingType,
		testCase.valueType,
		testCase.id,
		WsseNamespace,
		WsuNamespace,
		testCase.value,
	)

	// Prepare the test case
	testCaseDocument := etree.NewDocument()
	err := testCaseDocument.ReadFromString(testCaseXml)
	if err != nil {
		t.Fatal(err)
	}
	testCaseContext := xml.NewContext(testCaseDocument)
	testCaseContext.SetNamespacePrefix("wsu", WsuNamespace)

	// Create test case BinarySecurityToken
	testCaseBinarySecurityToken, err := NewBinarySecurityToken(testCaseContext)
	if err != nil {
		t.Fatal(err)
	}

	// Load test case BinarySecurityToken
	err = testCaseBinarySecurityToken.LoadXml(testCaseContext, testCaseDocument.Root())
	if err != nil {
		t.Fatal(err)
	}

	// Validate test case BinarySecurityToken
	if testCaseBinarySecurityToken.GetId() != testCase.id {
		t.Fatalf("BinarySecurityToken.Id = %s; want %s", testCaseBinarySecurityToken.GetId(), testCase.id)
	}
	if testCaseBinarySecurityToken.GetValueType() != testCase.valueType {
		t.Fatalf("BinarySecurityToken.ValueType = %s; want %s", testCaseBinarySecurityToken.GetValueType(), testCase.valueType)
	}
	if testCaseBinarySecurityToken.GetEncodingType() != testCase.encodingType {
		t.Fatalf("BinarySecurityToken.EncodingType = %s; want %s", testCaseBinarySecurityToken.GetEncodingType(), testCase.encodingType)
	}
	if testCaseBinarySecurityToken.GetValue() != testCase.value {
		t.Fatalf("BinarySecurityToken.Value = %s; want %s", testCaseBinarySecurityToken.GetValue(), testCase.value)
	}
}

func Test_BinarySecurityToken_GetXml(t *testing.T) {
	const (
		id           = "123"
		valueType    = "x509"
		encodingType = "base64"
		value        = "cert_data"
	)
	// Create test case
	testCase := struct {
		id           string
		valueType    string
		encodingType string
		value        string
	}{
		id:           id,
		valueType:    valueType,
		encodingType: encodingType,
		value:        value,
	}

	// Create test case XML
	testCaseXml := fmt.Sprintf(
		`<wsse:BinarySecurityToken EncodingType="%s" ValueType="%s" wsu:Id="%s" xmlns:wsse="%s" xmlns:wsu="%s">%s</wsse:BinarySecurityToken>`,
		testCase.encodingType,
		testCase.valueType,
		testCase.id,
		WsseNamespace,
		WsuNamespace,
		testCase.value,
	)

	// Prepare the test case
	testCaseDocument := etree.NewDocument()
	testCaseContext := xml.NewContext(testCaseDocument)
	testCaseContext.SetNamespacePrefix("wsse", WsseNamespace)
	testCaseContext.SetNamespacePrefix("wsu", WsuNamespace)

	// Create test case BinarySecurityToken
	testCaseBinarySecurityToken, err := NewBinarySecurityToken(testCaseContext)
	if err != nil {
		t.Fatal(err)
	}
	testCaseBinarySecurityToken.SetId(testCase.id)
	testCaseBinarySecurityToken.SetValueType(testCase.valueType)
	testCaseBinarySecurityToken.SetEncodingType(testCase.encodingType)
	testCaseBinarySecurityToken.SetValue(testCase.value)

	// Get test case BinarySecurityToken XML
	testCaseBinarySecurityTokenElement, err := testCaseBinarySecurityToken.GetXml(testCaseContext)
	if err != nil {
		t.Fatal(err)
	}

	// Add the namespace declarations
	testCaseBinarySecurityTokenElement.CreateAttr("xmlns:wsse", WsseNamespace)
	testCaseBinarySecurityTokenElement.CreateAttr("xmlns:wsu", WsuNamespace)
	testCaseBinarySecurityTokenElement.SortAttrs()

	// Get the test case XML
	testCaseDocument.SetRoot(testCaseBinarySecurityTokenElement)
	resultXml, err := testCaseDocument.WriteToString()
	if err != nil {
		t.Fatal(err)
	}

	// Validate test case BinarySecurityToken XML
	if resultXml != testCaseXml {
		t.Fatalf("BinarySecurityToken XML = %s; want %s", resultXml, testCaseXml)
	}
}
