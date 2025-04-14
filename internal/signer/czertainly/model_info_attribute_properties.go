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

// checks if the InfoAttributeProperties type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &InfoAttributeProperties{}

// InfoAttributeProperties struct for InfoAttributeProperties
type InfoAttributeProperties struct {
	// Friendly name of the the Attribute
	Label string `json:"label"`
	// Boolean determining if the Attribute is visible and can be displayed, otherwise it should be hidden to the user.
	Visible bool `json:"visible"`
	// Group of the Attribute, used for the logical grouping of the Attribute
	Group *string `json:"group,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _InfoAttributeProperties InfoAttributeProperties

// NewInfoAttributeProperties instantiates a new InfoAttributeProperties object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewInfoAttributeProperties(label string, visible bool) *InfoAttributeProperties {
	this := InfoAttributeProperties{}
	this.Label = label
	this.Visible = visible
	return &this
}

// NewInfoAttributePropertiesWithDefaults instantiates a new InfoAttributeProperties object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewInfoAttributePropertiesWithDefaults() *InfoAttributeProperties {
	this := InfoAttributeProperties{}
	var visible bool = true
	this.Visible = visible
	return &this
}

// GetLabel returns the Label field value
func (o *InfoAttributeProperties) GetLabel() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Label
}

// GetLabelOk returns a tuple with the Label field value
// and a boolean to check if the value has been set.
func (o *InfoAttributeProperties) GetLabelOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Label, true
}

// SetLabel sets field value
func (o *InfoAttributeProperties) SetLabel(v string) {
	o.Label = v
}

// GetVisible returns the Visible field value
func (o *InfoAttributeProperties) GetVisible() bool {
	if o == nil {
		var ret bool
		return ret
	}

	return o.Visible
}

// GetVisibleOk returns a tuple with the Visible field value
// and a boolean to check if the value has been set.
func (o *InfoAttributeProperties) GetVisibleOk() (*bool, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Visible, true
}

// SetVisible sets field value
func (o *InfoAttributeProperties) SetVisible(v bool) {
	o.Visible = v
}

// GetGroup returns the Group field value if set, zero value otherwise.
func (o *InfoAttributeProperties) GetGroup() string {
	if o == nil || IsNil(o.Group) {
		var ret string
		return ret
	}
	return *o.Group
}

// GetGroupOk returns a tuple with the Group field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *InfoAttributeProperties) GetGroupOk() (*string, bool) {
	if o == nil || IsNil(o.Group) {
		return nil, false
	}
	return o.Group, true
}

// HasGroup returns a boolean if a field has been set.
func (o *InfoAttributeProperties) HasGroup() bool {
	if o != nil && !IsNil(o.Group) {
		return true
	}

	return false
}

// SetGroup gets a reference to the given string and assigns it to the Group field.
func (o *InfoAttributeProperties) SetGroup(v string) {
	o.Group = &v
}

func (o InfoAttributeProperties) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o InfoAttributeProperties) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["label"] = o.Label
	toSerialize["visible"] = o.Visible
	if !IsNil(o.Group) {
		toSerialize["group"] = o.Group
	}

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return toSerialize, nil
}

func (o *InfoAttributeProperties) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"label",
		"visible",
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

	varInfoAttributeProperties := _InfoAttributeProperties{}

	err = json.Unmarshal(data, &varInfoAttributeProperties)

	if err != nil {
		return err
	}

	*o = InfoAttributeProperties(varInfoAttributeProperties)

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(data, &additionalProperties); err == nil {
		delete(additionalProperties, "label")
		delete(additionalProperties, "visible")
		delete(additionalProperties, "group")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableInfoAttributeProperties struct {
	value *InfoAttributeProperties
	isSet bool
}

func (v NullableInfoAttributeProperties) Get() *InfoAttributeProperties {
	return v.value
}

func (v *NullableInfoAttributeProperties) Set(val *InfoAttributeProperties) {
	v.value = val
	v.isSet = true
}

func (v NullableInfoAttributeProperties) IsSet() bool {
	return v.isSet
}

func (v *NullableInfoAttributeProperties) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableInfoAttributeProperties(val *InfoAttributeProperties) *NullableInfoAttributeProperties {
	return &NullableInfoAttributeProperties{value: val, isSet: true}
}

func (v NullableInfoAttributeProperties) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableInfoAttributeProperties) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


