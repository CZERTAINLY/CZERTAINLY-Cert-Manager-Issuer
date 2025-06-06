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

// KeyUsage the model 'KeyUsage'
type KeyUsage string

// List of KeyUsage
const (
	KEYUSAGE_SIGN KeyUsage = "sign"
	KEYUSAGE_VERIFY KeyUsage = "verify"
	KEYUSAGE_ENCRYPT KeyUsage = "encrypt"
	KEYUSAGE_DECRYPT KeyUsage = "decrypt"
	KEYUSAGE_WRAP KeyUsage = "wrap"
	KEYUSAGE_UNWRAP KeyUsage = "unwrap"
)

// All allowed values of KeyUsage enum
var AllowedKeyUsageEnumValues = []KeyUsage{
	"sign",
	"verify",
	"encrypt",
	"decrypt",
	"wrap",
	"unwrap",
}

func (v *KeyUsage) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := KeyUsage(value)
	for _, existing := range AllowedKeyUsageEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid KeyUsage", value)
}

// NewKeyUsageFromValue returns a pointer to a valid KeyUsage
// for the value passed as argument, or an error if the value passed is not allowed by the enum
func NewKeyUsageFromValue(v string) (*KeyUsage, error) {
	ev := KeyUsage(v)
	if ev.IsValid() {
		return &ev, nil
	} else {
		return nil, fmt.Errorf("invalid value '%v' for KeyUsage: valid values are %v", v, AllowedKeyUsageEnumValues)
	}
}

// IsValid return true if the value is valid for the enum, false otherwise
func (v KeyUsage) IsValid() bool {
	for _, existing := range AllowedKeyUsageEnumValues {
		if existing == v {
			return true
		}
	}
	return false
}

// Ptr returns reference to KeyUsage value
func (v KeyUsage) Ptr() *KeyUsage {
	return &v
}

type NullableKeyUsage struct {
	value *KeyUsage
	isSet bool
}

func (v NullableKeyUsage) Get() *KeyUsage {
	return v.value
}

func (v *NullableKeyUsage) Set(val *KeyUsage) {
	v.value = val
	v.isSet = true
}

func (v NullableKeyUsage) IsSet() bool {
	return v.isSet
}

func (v *NullableKeyUsage) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableKeyUsage(val *KeyUsage) *NullableKeyUsage {
	return &NullableKeyUsage{value: val, isSet: true}
}

func (v NullableKeyUsage) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableKeyUsage) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}

