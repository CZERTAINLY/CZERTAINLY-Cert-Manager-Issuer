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

// KeyAlgorithm Key Algorithm
type KeyAlgorithm string

// List of KeyAlgorithm
const (
	KEYALGORITHM_RSA KeyAlgorithm = "RSA"
	KEYALGORITHM_ECDSA KeyAlgorithm = "ECDSA"
	KEYALGORITHM_FALCON KeyAlgorithm = "FALCON"
	KEYALGORITHM_CRYSTALS_DILITHIUM KeyAlgorithm = "CRYSTALS-Dilithium"
	KEYALGORITHM_SPHINCS KeyAlgorithm = "SPHINCS+"
)

// All allowed values of KeyAlgorithm enum
var AllowedKeyAlgorithmEnumValues = []KeyAlgorithm{
	"RSA",
	"ECDSA",
	"FALCON",
	"CRYSTALS-Dilithium",
	"SPHINCS+",
}

func (v *KeyAlgorithm) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := KeyAlgorithm(value)
	for _, existing := range AllowedKeyAlgorithmEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid KeyAlgorithm", value)
}

// NewKeyAlgorithmFromValue returns a pointer to a valid KeyAlgorithm
// for the value passed as argument, or an error if the value passed is not allowed by the enum
func NewKeyAlgorithmFromValue(v string) (*KeyAlgorithm, error) {
	ev := KeyAlgorithm(v)
	if ev.IsValid() {
		return &ev, nil
	} else {
		return nil, fmt.Errorf("invalid value '%v' for KeyAlgorithm: valid values are %v", v, AllowedKeyAlgorithmEnumValues)
	}
}

// IsValid return true if the value is valid for the enum, false otherwise
func (v KeyAlgorithm) IsValid() bool {
	for _, existing := range AllowedKeyAlgorithmEnumValues {
		if existing == v {
			return true
		}
	}
	return false
}

// Ptr returns reference to KeyAlgorithm value
func (v KeyAlgorithm) Ptr() *KeyAlgorithm {
	return &v
}

type NullableKeyAlgorithm struct {
	value *KeyAlgorithm
	isSet bool
}

func (v NullableKeyAlgorithm) Get() *KeyAlgorithm {
	return v.value
}

func (v *NullableKeyAlgorithm) Set(val *KeyAlgorithm) {
	v.value = val
	v.isSet = true
}

func (v NullableKeyAlgorithm) IsSet() bool {
	return v.isSet
}

func (v *NullableKeyAlgorithm) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableKeyAlgorithm(val *KeyAlgorithm) *NullableKeyAlgorithm {
	return &NullableKeyAlgorithm{value: val, isSet: true}
}

func (v NullableKeyAlgorithm) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableKeyAlgorithm) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}

