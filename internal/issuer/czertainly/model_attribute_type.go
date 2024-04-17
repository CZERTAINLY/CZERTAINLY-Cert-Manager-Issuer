/*
CZERTAINLY Cert Manager

REST API for implementations of cert-manager issuer

API version: 2.11.1-SNAPSHOT
Contact: getinfo@czertainly.com
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package czertainly

import (
	"encoding/json"
	"fmt"
)

// AttributeType Type of the attribute. It is optional and must be set only if special behaviour is needed.
type AttributeType string

// List of AttributeType
const (
	ATTRIBUTETYPE_DATA AttributeType = "data"
	ATTRIBUTETYPE_GROUP AttributeType = "group"
	ATTRIBUTETYPE_INFO AttributeType = "info"
	ATTRIBUTETYPE_META AttributeType = "meta"
	ATTRIBUTETYPE_CUSTOM AttributeType = "custom"
)

// All allowed values of AttributeType enum
var AllowedAttributeTypeEnumValues = []AttributeType{
	"data",
	"group",
	"info",
	"meta",
	"custom",
}

func (v *AttributeType) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := AttributeType(value)
	for _, existing := range AllowedAttributeTypeEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid AttributeType", value)
}

// NewAttributeTypeFromValue returns a pointer to a valid AttributeType
// for the value passed as argument, or an error if the value passed is not allowed by the enum
func NewAttributeTypeFromValue(v string) (*AttributeType, error) {
	ev := AttributeType(v)
	if ev.IsValid() {
		return &ev, nil
	} else {
		return nil, fmt.Errorf("invalid value '%v' for AttributeType: valid values are %v", v, AllowedAttributeTypeEnumValues)
	}
}

// IsValid return true if the value is valid for the enum, false otherwise
func (v AttributeType) IsValid() bool {
	for _, existing := range AllowedAttributeTypeEnumValues {
		if existing == v {
			return true
		}
	}
	return false
}

// Ptr returns reference to AttributeType value
func (v AttributeType) Ptr() *AttributeType {
	return &v
}

type NullableAttributeType struct {
	value *AttributeType
	isSet bool
}

func (v NullableAttributeType) Get() *AttributeType {
	return v.value
}

func (v *NullableAttributeType) Set(val *AttributeType) {
	v.value = val
	v.isSet = true
}

func (v NullableAttributeType) IsSet() bool {
	return v.isSet
}

func (v *NullableAttributeType) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAttributeType(val *AttributeType) *NullableAttributeType {
	return &NullableAttributeType{value: val, isSet: true}
}

func (v NullableAttributeType) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAttributeType) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}

