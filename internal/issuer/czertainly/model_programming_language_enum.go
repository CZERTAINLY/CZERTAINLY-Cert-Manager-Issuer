/*
CZERTAINLY Cert Manager

REST API for implementations of cert-manager issuer

API version: 2.11.0
Contact: getinfo@czertainly.com
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package czertainly

import (
	"encoding/json"
	"fmt"
)

// ProgrammingLanguageEnum Definition of programming languages used for code
type ProgrammingLanguageEnum string

// List of ProgrammingLanguageEnum
const (
	PROGRAMMINGLANGUAGEENUM_APACHECONF ProgrammingLanguageEnum = "apacheconf"
	PROGRAMMINGLANGUAGEENUM_BASH ProgrammingLanguageEnum = "bash"
	PROGRAMMINGLANGUAGEENUM_BASIC ProgrammingLanguageEnum = "basic"
	PROGRAMMINGLANGUAGEENUM_C ProgrammingLanguageEnum = "c"
	PROGRAMMINGLANGUAGEENUM_CSHARP ProgrammingLanguageEnum = "csharp"
	PROGRAMMINGLANGUAGEENUM_CPP ProgrammingLanguageEnum = "cpp"
	PROGRAMMINGLANGUAGEENUM_CSS ProgrammingLanguageEnum = "css"
	PROGRAMMINGLANGUAGEENUM_DOCKER ProgrammingLanguageEnum = "docker"
	PROGRAMMINGLANGUAGEENUM_FSHARP ProgrammingLanguageEnum = "fsharp"
	PROGRAMMINGLANGUAGEENUM_GHERKIN ProgrammingLanguageEnum = "gherkin"
	PROGRAMMINGLANGUAGEENUM_GIT ProgrammingLanguageEnum = "git"
	PROGRAMMINGLANGUAGEENUM_GO ProgrammingLanguageEnum = "go"
	PROGRAMMINGLANGUAGEENUM_GRAPHQL ProgrammingLanguageEnum = "graphql"
	PROGRAMMINGLANGUAGEENUM_HTML ProgrammingLanguageEnum = "html"
	PROGRAMMINGLANGUAGEENUM_HTTP ProgrammingLanguageEnum = "http"
	PROGRAMMINGLANGUAGEENUM_INI ProgrammingLanguageEnum = "ini"
	PROGRAMMINGLANGUAGEENUM_JAVA ProgrammingLanguageEnum = "java"
	PROGRAMMINGLANGUAGEENUM_JAVASCRIPT ProgrammingLanguageEnum = "javascript"
	PROGRAMMINGLANGUAGEENUM_JSON ProgrammingLanguageEnum = "json"
	PROGRAMMINGLANGUAGEENUM_KOTLIN ProgrammingLanguageEnum = "kotlin"
	PROGRAMMINGLANGUAGEENUM_LATEX ProgrammingLanguageEnum = "latex"
	PROGRAMMINGLANGUAGEENUM_LISP ProgrammingLanguageEnum = "lisp"
	PROGRAMMINGLANGUAGEENUM_MAKEFILE ProgrammingLanguageEnum = "makefile"
	PROGRAMMINGLANGUAGEENUM_MARKDOWN ProgrammingLanguageEnum = "markdown"
	PROGRAMMINGLANGUAGEENUM_MATLAB ProgrammingLanguageEnum = "matlab"
	PROGRAMMINGLANGUAGEENUM_NGINX ProgrammingLanguageEnum = "nginx"
	PROGRAMMINGLANGUAGEENUM_OBJECTIVEC ProgrammingLanguageEnum = "objectivec"
	PROGRAMMINGLANGUAGEENUM_PERL ProgrammingLanguageEnum = "perl"
	PROGRAMMINGLANGUAGEENUM_PHP ProgrammingLanguageEnum = "php"
	PROGRAMMINGLANGUAGEENUM_POWERSHELL ProgrammingLanguageEnum = "powershell"
	PROGRAMMINGLANGUAGEENUM_PROPERTIES ProgrammingLanguageEnum = "properties"
	PROGRAMMINGLANGUAGEENUM_PYTHON ProgrammingLanguageEnum = "python"
	PROGRAMMINGLANGUAGEENUM_RUBY ProgrammingLanguageEnum = "ruby"
	PROGRAMMINGLANGUAGEENUM_RUST ProgrammingLanguageEnum = "rust"
	PROGRAMMINGLANGUAGEENUM_SMALLTALK ProgrammingLanguageEnum = "smalltalk"
	PROGRAMMINGLANGUAGEENUM_SQL ProgrammingLanguageEnum = "sql"
	PROGRAMMINGLANGUAGEENUM_TYPESCRIPT ProgrammingLanguageEnum = "typescript"
	PROGRAMMINGLANGUAGEENUM_VBNET ProgrammingLanguageEnum = "vbnet"
	PROGRAMMINGLANGUAGEENUM_XQUERY ProgrammingLanguageEnum = "xquery"
	PROGRAMMINGLANGUAGEENUM_XML ProgrammingLanguageEnum = "xml"
	PROGRAMMINGLANGUAGEENUM_YAML ProgrammingLanguageEnum = "yaml"
)

// All allowed values of ProgrammingLanguageEnum enum
var AllowedProgrammingLanguageEnumEnumValues = []ProgrammingLanguageEnum{
	"apacheconf",
	"bash",
	"basic",
	"c",
	"csharp",
	"cpp",
	"css",
	"docker",
	"fsharp",
	"gherkin",
	"git",
	"go",
	"graphql",
	"html",
	"http",
	"ini",
	"java",
	"javascript",
	"json",
	"kotlin",
	"latex",
	"lisp",
	"makefile",
	"markdown",
	"matlab",
	"nginx",
	"objectivec",
	"perl",
	"php",
	"powershell",
	"properties",
	"python",
	"ruby",
	"rust",
	"smalltalk",
	"sql",
	"typescript",
	"vbnet",
	"xquery",
	"xml",
	"yaml",
}

func (v *ProgrammingLanguageEnum) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := ProgrammingLanguageEnum(value)
	for _, existing := range AllowedProgrammingLanguageEnumEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid ProgrammingLanguageEnum", value)
}

// NewProgrammingLanguageEnumFromValue returns a pointer to a valid ProgrammingLanguageEnum
// for the value passed as argument, or an error if the value passed is not allowed by the enum
func NewProgrammingLanguageEnumFromValue(v string) (*ProgrammingLanguageEnum, error) {
	ev := ProgrammingLanguageEnum(v)
	if ev.IsValid() {
		return &ev, nil
	} else {
		return nil, fmt.Errorf("invalid value '%v' for ProgrammingLanguageEnum: valid values are %v", v, AllowedProgrammingLanguageEnumEnumValues)
	}
}

// IsValid return true if the value is valid for the enum, false otherwise
func (v ProgrammingLanguageEnum) IsValid() bool {
	for _, existing := range AllowedProgrammingLanguageEnumEnumValues {
		if existing == v {
			return true
		}
	}
	return false
}

// Ptr returns reference to ProgrammingLanguageEnum value
func (v ProgrammingLanguageEnum) Ptr() *ProgrammingLanguageEnum {
	return &v
}

type NullableProgrammingLanguageEnum struct {
	value *ProgrammingLanguageEnum
	isSet bool
}

func (v NullableProgrammingLanguageEnum) Get() *ProgrammingLanguageEnum {
	return v.value
}

func (v *NullableProgrammingLanguageEnum) Set(val *ProgrammingLanguageEnum) {
	v.value = val
	v.isSet = true
}

func (v NullableProgrammingLanguageEnum) IsSet() bool {
	return v.isSet
}

func (v *NullableProgrammingLanguageEnum) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableProgrammingLanguageEnum(val *ProgrammingLanguageEnum) *NullableProgrammingLanguageEnum {
	return &NullableProgrammingLanguageEnum{value: val, isSet: true}
}

func (v NullableProgrammingLanguageEnum) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableProgrammingLanguageEnum) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}

