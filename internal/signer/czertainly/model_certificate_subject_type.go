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

// CertificateSubjectType Certificate subject type
type CertificateSubjectType string

// List of CertificateSubjectType
const (
	CERTIFICATESUBJECTTYPE_END_ENTITY CertificateSubjectType = "endEntity"
	CERTIFICATESUBJECTTYPE_SELF_SIGNED_END_ENTITY CertificateSubjectType = "selfSignedEndEntity"
	CERTIFICATESUBJECTTYPE_INTERMEDIATE_CA CertificateSubjectType = "intermediateCa"
	CERTIFICATESUBJECTTYPE_ROOT_CA CertificateSubjectType = "rootCa"
)

// All allowed values of CertificateSubjectType enum
var AllowedCertificateSubjectTypeEnumValues = []CertificateSubjectType{
	"endEntity",
	"selfSignedEndEntity",
	"intermediateCa",
	"rootCa",
}

func (v *CertificateSubjectType) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := CertificateSubjectType(value)
	for _, existing := range AllowedCertificateSubjectTypeEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid CertificateSubjectType", value)
}

// NewCertificateSubjectTypeFromValue returns a pointer to a valid CertificateSubjectType
// for the value passed as argument, or an error if the value passed is not allowed by the enum
func NewCertificateSubjectTypeFromValue(v string) (*CertificateSubjectType, error) {
	ev := CertificateSubjectType(v)
	if ev.IsValid() {
		return &ev, nil
	} else {
		return nil, fmt.Errorf("invalid value '%v' for CertificateSubjectType: valid values are %v", v, AllowedCertificateSubjectTypeEnumValues)
	}
}

// IsValid return true if the value is valid for the enum, false otherwise
func (v CertificateSubjectType) IsValid() bool {
	for _, existing := range AllowedCertificateSubjectTypeEnumValues {
		if existing == v {
			return true
		}
	}
	return false
}

// Ptr returns reference to CertificateSubjectType value
func (v CertificateSubjectType) Ptr() *CertificateSubjectType {
	return &v
}

type NullableCertificateSubjectType struct {
	value *CertificateSubjectType
	isSet bool
}

func (v NullableCertificateSubjectType) Get() *CertificateSubjectType {
	return v.value
}

func (v *NullableCertificateSubjectType) Set(val *CertificateSubjectType) {
	v.value = val
	v.isSet = true
}

func (v NullableCertificateSubjectType) IsSet() bool {
	return v.isSet
}

func (v *NullableCertificateSubjectType) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCertificateSubjectType(val *CertificateSubjectType) *NullableCertificateSubjectType {
	return &NullableCertificateSubjectType{value: val, isSet: true}
}

func (v NullableCertificateSubjectType) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCertificateSubjectType) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}

