/*
CZERTAINLY Cert Manager

REST API for implementations of cert-manager issuer

API version: 2.14.2-SNAPSHOT
Contact: info@czertainly.com
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package czertainly

import (
	"encoding/json"
	"fmt"
)

// checks if the IntegerAttributeContent type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &IntegerAttributeContent{}

// IntegerAttributeContent Integer attribute content for integer numbers
type IntegerAttributeContent struct {
	// Content Reference
	Reference *string `json:"reference,omitempty"`
	// Integer attribute value
	Data int32 `json:"data"`
	AdditionalProperties map[string]interface{}
}

type _IntegerAttributeContent IntegerAttributeContent

// NewIntegerAttributeContent instantiates a new IntegerAttributeContent object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewIntegerAttributeContent(data int32) *IntegerAttributeContent {
	this := IntegerAttributeContent{}
	this.Data = data
	return &this
}

// NewIntegerAttributeContentWithDefaults instantiates a new IntegerAttributeContent object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewIntegerAttributeContentWithDefaults() *IntegerAttributeContent {
	this := IntegerAttributeContent{}
	return &this
}

// GetReference returns the Reference field value if set, zero value otherwise.
func (o *IntegerAttributeContent) GetReference() string {
	if o == nil || IsNil(o.Reference) {
		var ret string
		return ret
	}
	return *o.Reference
}

// GetReferenceOk returns a tuple with the Reference field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *IntegerAttributeContent) GetReferenceOk() (*string, bool) {
	if o == nil || IsNil(o.Reference) {
		return nil, false
	}
	return o.Reference, true
}

// HasReference returns a boolean if a field has been set.
func (o *IntegerAttributeContent) HasReference() bool {
	if o != nil && !IsNil(o.Reference) {
		return true
	}

	return false
}

// SetReference gets a reference to the given string and assigns it to the Reference field.
func (o *IntegerAttributeContent) SetReference(v string) {
	o.Reference = &v
}

// GetData returns the Data field value
func (o *IntegerAttributeContent) GetData() int32 {
	if o == nil {
		var ret int32
		return ret
	}

	return o.Data
}

// GetDataOk returns a tuple with the Data field value
// and a boolean to check if the value has been set.
func (o *IntegerAttributeContent) GetDataOk() (*int32, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Data, true
}

// SetData sets field value
func (o *IntegerAttributeContent) SetData(v int32) {
	o.Data = v
}

func (o IntegerAttributeContent) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o IntegerAttributeContent) ToMap() (map[string]interface{}, error) {
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

func (o *IntegerAttributeContent) UnmarshalJSON(data []byte) (err error) {
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

	varIntegerAttributeContent := _IntegerAttributeContent{}

	err = json.Unmarshal(data, &varIntegerAttributeContent)

	if err != nil {
		return err
	}

	*o = IntegerAttributeContent(varIntegerAttributeContent)

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(data, &additionalProperties); err == nil {
		delete(additionalProperties, "reference")
		delete(additionalProperties, "data")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableIntegerAttributeContent struct {
	value *IntegerAttributeContent
	isSet bool
}

func (v NullableIntegerAttributeContent) Get() *IntegerAttributeContent {
	return v.value
}

func (v *NullableIntegerAttributeContent) Set(val *IntegerAttributeContent) {
	v.value = val
	v.isSet = true
}

func (v NullableIntegerAttributeContent) IsSet() bool {
	return v.isSet
}

func (v *NullableIntegerAttributeContent) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableIntegerAttributeContent(val *IntegerAttributeContent) *NullableIntegerAttributeContent {
	return &NullableIntegerAttributeContent{value: val, isSet: true}
}

func (v NullableIntegerAttributeContent) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableIntegerAttributeContent) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


