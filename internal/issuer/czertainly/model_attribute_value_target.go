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

// AttributeValueTarget Set of targets for propagating value.
type AttributeValueTarget string

// List of AttributeValueTarget
const (
	ATTRIBUTEVALUETARGET_PATH_VARIABLE AttributeValueTarget = "pathVariable"
	ATTRIBUTEVALUETARGET_REQUEST_PARAMETER AttributeValueTarget = "requestParameter"
	ATTRIBUTEVALUETARGET_BODY AttributeValueTarget = "body"
)

// All allowed values of AttributeValueTarget enum
var AllowedAttributeValueTargetEnumValues = []AttributeValueTarget{
	"pathVariable",
	"requestParameter",
	"body",
}

func (v *AttributeValueTarget) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := AttributeValueTarget(value)
	for _, existing := range AllowedAttributeValueTargetEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid AttributeValueTarget", value)
}

// NewAttributeValueTargetFromValue returns a pointer to a valid AttributeValueTarget
// for the value passed as argument, or an error if the value passed is not allowed by the enum
func NewAttributeValueTargetFromValue(v string) (*AttributeValueTarget, error) {
	ev := AttributeValueTarget(v)
	if ev.IsValid() {
		return &ev, nil
	} else {
		return nil, fmt.Errorf("invalid value '%v' for AttributeValueTarget: valid values are %v", v, AllowedAttributeValueTargetEnumValues)
	}
}

// IsValid return true if the value is valid for the enum, false otherwise
func (v AttributeValueTarget) IsValid() bool {
	for _, existing := range AllowedAttributeValueTargetEnumValues {
		if existing == v {
			return true
		}
	}
	return false
}

// Ptr returns reference to AttributeValueTarget value
func (v AttributeValueTarget) Ptr() *AttributeValueTarget {
	return &v
}

type NullableAttributeValueTarget struct {
	value *AttributeValueTarget
	isSet bool
}

func (v NullableAttributeValueTarget) Get() *AttributeValueTarget {
	return v.value
}

func (v *NullableAttributeValueTarget) Set(val *AttributeValueTarget) {
	v.value = val
	v.isSet = true
}

func (v NullableAttributeValueTarget) IsSet() bool {
	return v.isSet
}

func (v *NullableAttributeValueTarget) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAttributeValueTarget(val *AttributeValueTarget) *NullableAttributeValueTarget {
	return &NullableAttributeValueTarget{value: val, isSet: true}
}

func (v NullableAttributeValueTarget) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAttributeValueTarget) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}

