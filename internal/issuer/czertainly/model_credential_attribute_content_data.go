/*
CZERTAINLY Cert Manager

REST API for implementations of cert-manager issuer

API version: 2.13.0
Contact: info@czertainly.com
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package czertainly

import (
	"encoding/json"
	"fmt"
)

// checks if the CredentialAttributeContentData type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &CredentialAttributeContentData{}

// CredentialAttributeContentData Credential attribute content data
type CredentialAttributeContentData struct {
	// Object identifier
	Uuid string `json:"uuid"`
	// Object Name
	Name string `json:"name"`
	// Credential Kind
	Kind string `json:"kind"`
	// List of Credential Attributes
	Attributes []DataAttribute `json:"attributes"`
	AdditionalProperties map[string]interface{}
}

type _CredentialAttributeContentData CredentialAttributeContentData

// NewCredentialAttributeContentData instantiates a new CredentialAttributeContentData object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCredentialAttributeContentData(uuid string, name string, kind string, attributes []DataAttribute) *CredentialAttributeContentData {
	this := CredentialAttributeContentData{}
	this.Uuid = uuid
	this.Name = name
	this.Kind = kind
	this.Attributes = attributes
	return &this
}

// NewCredentialAttributeContentDataWithDefaults instantiates a new CredentialAttributeContentData object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCredentialAttributeContentDataWithDefaults() *CredentialAttributeContentData {
	this := CredentialAttributeContentData{}
	return &this
}

// GetUuid returns the Uuid field value
func (o *CredentialAttributeContentData) GetUuid() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Uuid
}

// GetUuidOk returns a tuple with the Uuid field value
// and a boolean to check if the value has been set.
func (o *CredentialAttributeContentData) GetUuidOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Uuid, true
}

// SetUuid sets field value
func (o *CredentialAttributeContentData) SetUuid(v string) {
	o.Uuid = v
}

// GetName returns the Name field value
func (o *CredentialAttributeContentData) GetName() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Name
}

// GetNameOk returns a tuple with the Name field value
// and a boolean to check if the value has been set.
func (o *CredentialAttributeContentData) GetNameOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Name, true
}

// SetName sets field value
func (o *CredentialAttributeContentData) SetName(v string) {
	o.Name = v
}

// GetKind returns the Kind field value
func (o *CredentialAttributeContentData) GetKind() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Kind
}

// GetKindOk returns a tuple with the Kind field value
// and a boolean to check if the value has been set.
func (o *CredentialAttributeContentData) GetKindOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Kind, true
}

// SetKind sets field value
func (o *CredentialAttributeContentData) SetKind(v string) {
	o.Kind = v
}

// GetAttributes returns the Attributes field value
func (o *CredentialAttributeContentData) GetAttributes() []DataAttribute {
	if o == nil {
		var ret []DataAttribute
		return ret
	}

	return o.Attributes
}

// GetAttributesOk returns a tuple with the Attributes field value
// and a boolean to check if the value has been set.
func (o *CredentialAttributeContentData) GetAttributesOk() ([]DataAttribute, bool) {
	if o == nil {
		return nil, false
	}
	return o.Attributes, true
}

// SetAttributes sets field value
func (o *CredentialAttributeContentData) SetAttributes(v []DataAttribute) {
	o.Attributes = v
}

func (o CredentialAttributeContentData) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o CredentialAttributeContentData) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["uuid"] = o.Uuid
	toSerialize["name"] = o.Name
	toSerialize["kind"] = o.Kind
	toSerialize["attributes"] = o.Attributes

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return toSerialize, nil
}

func (o *CredentialAttributeContentData) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"uuid",
		"name",
		"kind",
		"attributes",
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

	varCredentialAttributeContentData := _CredentialAttributeContentData{}

	err = json.Unmarshal(data, &varCredentialAttributeContentData)

	if err != nil {
		return err
	}

	*o = CredentialAttributeContentData(varCredentialAttributeContentData)

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(data, &additionalProperties); err == nil {
		delete(additionalProperties, "uuid")
		delete(additionalProperties, "name")
		delete(additionalProperties, "kind")
		delete(additionalProperties, "attributes")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableCredentialAttributeContentData struct {
	value *CredentialAttributeContentData
	isSet bool
}

func (v NullableCredentialAttributeContentData) Get() *CredentialAttributeContentData {
	return v.value
}

func (v *NullableCredentialAttributeContentData) Set(val *CredentialAttributeContentData) {
	v.value = val
	v.isSet = true
}

func (v NullableCredentialAttributeContentData) IsSet() bool {
	return v.isSet
}

func (v *NullableCredentialAttributeContentData) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCredentialAttributeContentData(val *CredentialAttributeContentData) *NullableCredentialAttributeContentData {
	return &NullableCredentialAttributeContentData{value: val, isSet: true}
}

func (v NullableCredentialAttributeContentData) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCredentialAttributeContentData) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


