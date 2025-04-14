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

// checks if the AppInfoDto type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppInfoDto{}

// AppInfoDto struct for AppInfoDto
type AppInfoDto struct {
	// CZERTAINLY Application name
	Name string `json:"name"`
	// CZERTAINLY Core version
	Version string `json:"version"`
	AdditionalProperties map[string]interface{}
}

type _AppInfoDto AppInfoDto

// NewAppInfoDto instantiates a new AppInfoDto object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppInfoDto(name string, version string) *AppInfoDto {
	this := AppInfoDto{}
	this.Name = name
	this.Version = version
	return &this
}

// NewAppInfoDtoWithDefaults instantiates a new AppInfoDto object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppInfoDtoWithDefaults() *AppInfoDto {
	this := AppInfoDto{}
	return &this
}

// GetName returns the Name field value
func (o *AppInfoDto) GetName() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Name
}

// GetNameOk returns a tuple with the Name field value
// and a boolean to check if the value has been set.
func (o *AppInfoDto) GetNameOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Name, true
}

// SetName sets field value
func (o *AppInfoDto) SetName(v string) {
	o.Name = v
}

// GetVersion returns the Version field value
func (o *AppInfoDto) GetVersion() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Version
}

// GetVersionOk returns a tuple with the Version field value
// and a boolean to check if the value has been set.
func (o *AppInfoDto) GetVersionOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Version, true
}

// SetVersion sets field value
func (o *AppInfoDto) SetVersion(v string) {
	o.Version = v
}

func (o AppInfoDto) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppInfoDto) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["name"] = o.Name
	toSerialize["version"] = o.Version

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return toSerialize, nil
}

func (o *AppInfoDto) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"name",
		"version",
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

	varAppInfoDto := _AppInfoDto{}

	err = json.Unmarshal(data, &varAppInfoDto)

	if err != nil {
		return err
	}

	*o = AppInfoDto(varAppInfoDto)

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(data, &additionalProperties); err == nil {
		delete(additionalProperties, "name")
		delete(additionalProperties, "version")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableAppInfoDto struct {
	value *AppInfoDto
	isSet bool
}

func (v NullableAppInfoDto) Get() *AppInfoDto {
	return v.value
}

func (v *NullableAppInfoDto) Set(val *AppInfoDto) {
	v.value = val
	v.isSet = true
}

func (v NullableAppInfoDto) IsSet() bool {
	return v.isSet
}

func (v *NullableAppInfoDto) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppInfoDto(val *AppInfoDto) *NullableAppInfoDto {
	return &NullableAppInfoDto{value: val, isSet: true}
}

func (v NullableAppInfoDto) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppInfoDto) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


