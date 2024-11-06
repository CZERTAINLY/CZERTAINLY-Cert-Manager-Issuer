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

// CertificateProtocol Protocol used to issue certificate
type CertificateProtocol string

// List of CertificateProtocol
const (
	CERTIFICATEPROTOCOL_ACME CertificateProtocol = "acme"
	CERTIFICATEPROTOCOL_SCEP CertificateProtocol = "scep"
	CERTIFICATEPROTOCOL_CMP CertificateProtocol = "cmp"
)

// All allowed values of CertificateProtocol enum
var AllowedCertificateProtocolEnumValues = []CertificateProtocol{
	"acme",
	"scep",
	"cmp",
}

func (v *CertificateProtocol) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := CertificateProtocol(value)
	for _, existing := range AllowedCertificateProtocolEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid CertificateProtocol", value)
}

// NewCertificateProtocolFromValue returns a pointer to a valid CertificateProtocol
// for the value passed as argument, or an error if the value passed is not allowed by the enum
func NewCertificateProtocolFromValue(v string) (*CertificateProtocol, error) {
	ev := CertificateProtocol(v)
	if ev.IsValid() {
		return &ev, nil
	} else {
		return nil, fmt.Errorf("invalid value '%v' for CertificateProtocol: valid values are %v", v, AllowedCertificateProtocolEnumValues)
	}
}

// IsValid return true if the value is valid for the enum, false otherwise
func (v CertificateProtocol) IsValid() bool {
	for _, existing := range AllowedCertificateProtocolEnumValues {
		if existing == v {
			return true
		}
	}
	return false
}

// Ptr returns reference to CertificateProtocol value
func (v CertificateProtocol) Ptr() *CertificateProtocol {
	return &v
}

type NullableCertificateProtocol struct {
	value *CertificateProtocol
	isSet bool
}

func (v NullableCertificateProtocol) Get() *CertificateProtocol {
	return v.value
}

func (v *NullableCertificateProtocol) Set(val *CertificateProtocol) {
	v.value = val
	v.isSet = true
}

func (v NullableCertificateProtocol) IsSet() bool {
	return v.isSet
}

func (v *NullableCertificateProtocol) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCertificateProtocol(val *CertificateProtocol) *NullableCertificateProtocol {
	return &NullableCertificateProtocol{value: val, isSet: true}
}

func (v NullableCertificateProtocol) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCertificateProtocol) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}

