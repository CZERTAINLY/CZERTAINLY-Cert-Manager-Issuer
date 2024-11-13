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

// checks if the StringAttributeContent type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &StringAttributeContent{}

// StringAttributeContent struct for StringAttributeContent
type StringAttributeContent struct {
	// Content Reference
	Reference *string `json:"reference,omitempty"`
	// String attribute value
	Data string `json:"data"`
	AdditionalProperties map[string]interface{}
}

type _StringAttributeContent StringAttributeContent

// NewStringAttributeContent instantiates a new StringAttributeContent object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewStringAttributeContent(data string) *StringAttributeContent {
	this := StringAttributeContent{}
	this.Data = data
	return &this
}

// NewStringAttributeContentWithDefaults instantiates a new StringAttributeContent object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewStringAttributeContentWithDefaults() *StringAttributeContent {
	this := StringAttributeContent{}
	return &this
}

// GetReference returns the Reference field value if set, zero value otherwise.
func (o *StringAttributeContent) GetReference() string {
	if o == nil || IsNil(o.Reference) {
		var ret string
		return ret
	}
	return *o.Reference
}

// GetReferenceOk returns a tuple with the Reference field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StringAttributeContent) GetReferenceOk() (*string, bool) {
	if o == nil || IsNil(o.Reference) {
		return nil, false
	}
	return o.Reference, true
}

// HasReference returns a boolean if a field has been set.
func (o *StringAttributeContent) HasReference() bool {
	if o != nil && !IsNil(o.Reference) {
		return true
	}

	return false
}

// SetReference gets a reference to the given string and assigns it to the Reference field.
func (o *StringAttributeContent) SetReference(v string) {
	o.Reference = &v
}

// GetData returns the Data field value
func (o *StringAttributeContent) GetData() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Data
}

// GetDataOk returns a tuple with the Data field value
// and a boolean to check if the value has been set.
func (o *StringAttributeContent) GetDataOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Data, true
}

// SetData sets field value
func (o *StringAttributeContent) SetData(v string) {
	o.Data = v
}

func (o StringAttributeContent) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o StringAttributeContent) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Reference) {
		toSerialize["reference"] = o.Reference
	}
	toSerialize["data"] = o.Data

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return toSerialize, nil
}

func (o *StringAttributeContent) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"data",
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

	varStringAttributeContent := _StringAttributeContent{}

	err = json.Unmarshal(data, &varStringAttributeContent)

	if err != nil {
		return err
	}

	*o = StringAttributeContent(varStringAttributeContent)

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(data, &additionalProperties); err == nil {
		delete(additionalProperties, "reference")
		delete(additionalProperties, "data")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableStringAttributeContent struct {
	value *StringAttributeContent
	isSet bool
}

func (v NullableStringAttributeContent) Get() *StringAttributeContent {
	return v.value
}

func (v *NullableStringAttributeContent) Set(val *StringAttributeContent) {
	v.value = val
	v.isSet = true
}

func (v NullableStringAttributeContent) IsSet() bool {
	return v.isSet
}

func (v *NullableStringAttributeContent) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableStringAttributeContent(val *StringAttributeContent) *NullableStringAttributeContent {
	return &NullableStringAttributeContent{value: val, isSet: true}
}

func (v NullableStringAttributeContent) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableStringAttributeContent) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


