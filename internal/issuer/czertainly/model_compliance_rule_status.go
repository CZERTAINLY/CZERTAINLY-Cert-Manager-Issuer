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

// ComplianceRuleStatus Status of the rule
type ComplianceRuleStatus string

// List of ComplianceRuleStatus
const (
	COMPLIANCERULESTATUS_OK ComplianceRuleStatus = "ok"
	COMPLIANCERULESTATUS_NOK ComplianceRuleStatus = "nok"
	COMPLIANCERULESTATUS_NA ComplianceRuleStatus = "na"
)

// All allowed values of ComplianceRuleStatus enum
var AllowedComplianceRuleStatusEnumValues = []ComplianceRuleStatus{
	"ok",
	"nok",
	"na",
}

func (v *ComplianceRuleStatus) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := ComplianceRuleStatus(value)
	for _, existing := range AllowedComplianceRuleStatusEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid ComplianceRuleStatus", value)
}

// NewComplianceRuleStatusFromValue returns a pointer to a valid ComplianceRuleStatus
// for the value passed as argument, or an error if the value passed is not allowed by the enum
func NewComplianceRuleStatusFromValue(v string) (*ComplianceRuleStatus, error) {
	ev := ComplianceRuleStatus(v)
	if ev.IsValid() {
		return &ev, nil
	} else {
		return nil, fmt.Errorf("invalid value '%v' for ComplianceRuleStatus: valid values are %v", v, AllowedComplianceRuleStatusEnumValues)
	}
}

// IsValid return true if the value is valid for the enum, false otherwise
func (v ComplianceRuleStatus) IsValid() bool {
	for _, existing := range AllowedComplianceRuleStatusEnumValues {
		if existing == v {
			return true
		}
	}
	return false
}

// Ptr returns reference to ComplianceRuleStatus value
func (v ComplianceRuleStatus) Ptr() *ComplianceRuleStatus {
	return &v
}

type NullableComplianceRuleStatus struct {
	value *ComplianceRuleStatus
	isSet bool
}

func (v NullableComplianceRuleStatus) Get() *ComplianceRuleStatus {
	return v.value
}

func (v *NullableComplianceRuleStatus) Set(val *ComplianceRuleStatus) {
	v.value = val
	v.isSet = true
}

func (v NullableComplianceRuleStatus) IsSet() bool {
	return v.isSet
}

func (v *NullableComplianceRuleStatus) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableComplianceRuleStatus(val *ComplianceRuleStatus) *NullableComplianceRuleStatus {
	return &NullableComplianceRuleStatus{value: val, isSet: true}
}

func (v NullableComplianceRuleStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableComplianceRuleStatus) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}

