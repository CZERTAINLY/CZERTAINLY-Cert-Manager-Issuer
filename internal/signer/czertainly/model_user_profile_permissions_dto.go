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

// checks if the UserProfilePermissionsDto type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &UserProfilePermissionsDto{}

// UserProfilePermissionsDto struct for UserProfilePermissionsDto
type UserProfilePermissionsDto struct {
	// Allowed resource listings
	AllowedListings []Resource `json:"allowedListings"`
	AdditionalProperties map[string]interface{}
}

type _UserProfilePermissionsDto UserProfilePermissionsDto

// NewUserProfilePermissionsDto instantiates a new UserProfilePermissionsDto object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewUserProfilePermissionsDto(allowedListings []Resource) *UserProfilePermissionsDto {
	this := UserProfilePermissionsDto{}
	this.AllowedListings = allowedListings
	return &this
}

// NewUserProfilePermissionsDtoWithDefaults instantiates a new UserProfilePermissionsDto object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewUserProfilePermissionsDtoWithDefaults() *UserProfilePermissionsDto {
	this := UserProfilePermissionsDto{}
	return &this
}

// GetAllowedListings returns the AllowedListings field value
func (o *UserProfilePermissionsDto) GetAllowedListings() []Resource {
	if o == nil {
		var ret []Resource
		return ret
	}

	return o.AllowedListings
}

// GetAllowedListingsOk returns a tuple with the AllowedListings field value
// and a boolean to check if the value has been set.
func (o *UserProfilePermissionsDto) GetAllowedListingsOk() ([]Resource, bool) {
	if o == nil {
		return nil, false
	}
	return o.AllowedListings, true
}

// SetAllowedListings sets field value
func (o *UserProfilePermissionsDto) SetAllowedListings(v []Resource) {
	o.AllowedListings = v
}

func (o UserProfilePermissionsDto) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o UserProfilePermissionsDto) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["allowedListings"] = o.AllowedListings

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return toSerialize, nil
}

func (o *UserProfilePermissionsDto) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"allowedListings",
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

	varUserProfilePermissionsDto := _UserProfilePermissionsDto{}

	err = json.Unmarshal(data, &varUserProfilePermissionsDto)

	if err != nil {
		return err
	}

	*o = UserProfilePermissionsDto(varUserProfilePermissionsDto)

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(data, &additionalProperties); err == nil {
		delete(additionalProperties, "allowedListings")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableUserProfilePermissionsDto struct {
	value *UserProfilePermissionsDto
	isSet bool
}

func (v NullableUserProfilePermissionsDto) Get() *UserProfilePermissionsDto {
	return v.value
}

func (v *NullableUserProfilePermissionsDto) Set(val *UserProfilePermissionsDto) {
	v.value = val
	v.isSet = true
}

func (v NullableUserProfilePermissionsDto) IsSet() bool {
	return v.isSet
}

func (v *NullableUserProfilePermissionsDto) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableUserProfilePermissionsDto(val *UserProfilePermissionsDto) *NullableUserProfilePermissionsDto {
	return &NullableUserProfilePermissionsDto{value: val, isSet: true}
}

func (v NullableUserProfilePermissionsDto) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableUserProfilePermissionsDto) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


