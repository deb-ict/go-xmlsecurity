package xmlsecurity

import (
	"testing"

	"github.com/beevik/etree"
	"github.com/deb-ict/go-xml"
)

func Test_GetWsuId(t *testing.T) {
	// Create test case
	testCase := []struct {
		xml string
		id  string
	}{
		{
			xml: `<Test xmlns:wsu="` + WsuNamespace + `" wsu:Id="123"/>`,
			id:  "123",
		},
		{
			xml: `<Test xmlns:wsu="` + WsuNamespace + `" Id="123"/>`,
			id:  "",
		},
	}

	for _, tc := range testCase {
		// Prepare the test case
		testCaseDocument := etree.NewDocument()
		err := testCaseDocument.ReadFromString(tc.xml)
		if err != nil {
			t.Fatal(err)
		}
		testCaseResolver := xml.NewXmlResolver(testCaseDocument)
		testCaseResolver.SetNamespacePrefix("wsu", WsuNamespace)

		// Get test case wsu:Id
		wsuId := GetWsuId(testCaseResolver, testCaseDocument.Root())
		if wsuId != tc.id {
			t.Fatal(wsuId)
		}
	}
}

func Test_SetWsuId(t *testing.T) {
	// Create test case
	testCase := []struct {
		newId       string
		originalXml string
		expectedXml string
	}{
		{
			newId:       "123",
			originalXml: `<Test xmlns:wsu="` + WsuNamespace + `"/>`,
			expectedXml: `<Test xmlns:wsu="` + WsuNamespace + `" wsu:Id="123"/>`,
		},
		{
			newId:       "123",
			originalXml: `<Test xmlns:wsu="` + WsuNamespace + `" wsu:Id="456"/>`,
			expectedXml: `<Test xmlns:wsu="` + WsuNamespace + `" wsu:Id="123"/>`,
		},
		{
			newId:       "123",
			originalXml: `<Test xmlns:wsu="` + WsuNamespace + `" Id="456"/>`,
			expectedXml: `<Test xmlns:wsu="` + WsuNamespace + `" Id="456" wsu:Id="123"/>`,
		},
	}

	for _, tc := range testCase {
		// Prepare the test case
		testCaseDocument := etree.NewDocument()
		err := testCaseDocument.ReadFromString(tc.originalXml)
		if err != nil {
			t.Fatal(err)
		}
		testCaseResolver := xml.NewXmlResolver(testCaseDocument)
		testCaseResolver.SetNamespacePrefix("wsu", WsuNamespace)

		// Set test case wsu:Id
		if tc.newId != "" {
			SetWsuId(testCaseResolver, testCaseDocument.Root(), tc.newId)
		}
		resultXml, err := testCaseDocument.WriteToString()
		if err != nil {
			t.Fatal(err)
		}
		if resultXml != tc.expectedXml {
			t.Fatalf("resultXml = %s; want %s", resultXml, tc.expectedXml)
		}
	}
}
