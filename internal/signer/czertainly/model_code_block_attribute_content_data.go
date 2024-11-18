/*
CZERTAINLY Cert Manager

REST API for implementations of cert-manager issuer

API version: 2.13.1
Contact: info@czertainly.com
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package czertainly

import (
	"encoding/json"
	"fmt"
)

// checks if the CodeBlockAttributeContentData type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &CodeBlockAttributeContentData{}

// CodeBlockAttributeContentData CodeBlock attribute content data
type CodeBlockAttributeContentData struct {
	Language ProgrammingLanguageEnum `json:"language"`
	// Block of the code in Base64. Formatting of the code is specified by variable language
	Code string `json:"code"`
	AdditionalProperties map[string]interface{}
}

type _CodeBlockAttributeContentData CodeBlockAttributeContentData

// NewCodeBlockAttributeContentData instantiates a new CodeBlockAttributeContentData object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCodeBlockAttributeContentData(language ProgrammingLanguageEnum, code string) *CodeBlockAttributeContentData {
	this := CodeBlockAttributeContentData{}
	this.Language = language
	this.Code = code
	return &this
}

// NewCodeBlockAttributeContentDataWithDefaults instantiates a new CodeBlockAttributeContentData object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCodeBlockAttributeContentDataWithDefaults() *CodeBlockAttributeContentData {
	this := CodeBlockAttributeContentData{}
	return &this
}

// GetLanguage returns the Language field value
func (o *CodeBlockAttributeContentData) GetLanguage() ProgrammingLanguageEnum {
	if o == nil {
		var ret ProgrammingLanguageEnum
		return ret
	}

	return o.Language
}

// GetLanguageOk returns a tuple with the Language field value
// and a boolean to check if the value has been set.
func (o *CodeBlockAttributeContentData) GetLanguageOk() (*ProgrammingLanguageEnum, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Language, true
}

// SetLanguage sets field value
func (o *CodeBlockAttributeContentData) SetLanguage(v ProgrammingLanguageEnum) {
	o.Language = v
}

// GetCode returns the Code field value
func (o *CodeBlockAttributeContentData) GetCode() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Code
}

// GetCodeOk returns a tuple with the Code field value
// and a boolean to check if the value has been set.
func (o *CodeBlockAttributeContentData) GetCodeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Code, true
}

// SetCode sets field value
func (o *CodeBlockAttributeContentData) SetCode(v string) {
	o.Code = v
}

func (o CodeBlockAttributeContentData) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o CodeBlockAttributeContentData) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["language"] = o.Language
	toSerialize["code"] = o.Code

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return toSerialize, nil
}

func (o *CodeBlockAttributeContentData) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"language",
		"code",
	}

	allProperties := make(map[string]interface{})

	err = json.Unmarshal(data, &allProperties)

	if err != nil {
		return err;
	}

	for _, requiredProperty := range(requiredProperties) {
		if _, exists := allProperties[requiredProperty]; !exists {
			return fmt.Errorf("no value given for required property %v", requiredProperty)
		}
	}

	varCodeBlockAttributeContentData := _CodeBlockAttributeContentData{}

	err = json.Unmarshal(data, &varCodeBlockAttributeContentData)

	if err != nil {
		return err
	}

	*o = CodeBlockAttributeContentData(varCodeBlockAttributeContentData)

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(data, &additionalProperties); err == nil {
		delete(additionalProperties, "language")
		delete(additionalProperties, "code")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableCodeBlockAttributeContentData struct {
	value *CodeBlockAttributeContentData
	isSet bool
}

func (v NullableCodeBlockAttributeContentData) Get() *CodeBlockAttributeContentData {
	return v.value
}

func (v *NullableCodeBlockAttributeContentData) Set(val *CodeBlockAttributeContentData) {
	v.value = val
	v.isSet = true
}

func (v NullableCodeBlockAttributeContentData) IsSet() bool {
	return v.isSet
}

func (v *NullableCodeBlockAttributeContentData) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCodeBlockAttributeContentData(val *CodeBlockAttributeContentData) *NullableCodeBlockAttributeContentData {
	return &NullableCodeBlockAttributeContentData{value: val, isSet: true}
}

func (v NullableCodeBlockAttributeContentData) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCodeBlockAttributeContentData) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


