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

// checks if the RoleDto type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &RoleDto{}

// RoleDto Roles for the user
type RoleDto struct {
	// Object identifier
	Uuid string `json:"uuid"`
	// Object Name
	Name string `json:"name"`
	// Description of the user
	Description *string `json:"description,omitempty"`
	// Role contact email
	Email *string `json:"email,omitempty"`
	// Is system role. True = Yes, False = No
	SystemRole bool `json:"systemRole"`
	AdditionalProperties map[string]interface{}
}

type _RoleDto RoleDto

// NewRoleDto instantiates a new RoleDto object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewRoleDto(uuid string, name string, systemRole bool) *RoleDto {
	this := RoleDto{}
	this.Uuid = uuid
	this.Name = name
	this.SystemRole = systemRole
	return &this
}

// NewRoleDtoWithDefaults instantiates a new RoleDto object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewRoleDtoWithDefaults() *RoleDto {
	this := RoleDto{}
	return &this
}

// GetUuid returns the Uuid field value
func (o *RoleDto) GetUuid() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Uuid
}

// GetUuidOk returns a tuple with the Uuid field value
// and a boolean to check if the value has been set.
func (o *RoleDto) GetUuidOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Uuid, true
}

// SetUuid sets field value
func (o *RoleDto) SetUuid(v string) {
	o.Uuid = v
}

// GetName returns the Name field value
func (o *RoleDto) GetName() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Name
}

// GetNameOk returns a tuple with the Name field value
// and a boolean to check if the value has been set.
func (o *RoleDto) GetNameOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Name, true
}

// SetName sets field value
func (o *RoleDto) SetName(v string) {
	o.Name = v
}

// GetDescription returns the Description field value if set, zero value otherwise.
func (o *RoleDto) GetDescription() string {
	if o == nil || IsNil(o.Description) {
		var ret string
		return ret
	}
	return *o.Description
}

// GetDescriptionOk returns a tuple with the Description field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *RoleDto) GetDescriptionOk() (*string, bool) {
	if o == nil || IsNil(o.Description) {
		return nil, false
	}
	return o.Description, true
}

// HasDescription returns a boolean if a field has been set.
func (o *RoleDto) HasDescription() bool {
	if o != nil && !IsNil(o.Description) {
		return true
	}

	return false
}

// SetDescription gets a reference to the given string and assigns it to the Description field.
func (o *RoleDto) SetDescription(v string) {
	o.Description = &v
}

// GetEmail returns the Email field value if set, zero value otherwise.
func (o *RoleDto) GetEmail() string {
	if o == nil || IsNil(o.Email) {
		var ret string
		return ret
	}
	return *o.Email
}

// GetEmailOk returns a tuple with the Email field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *RoleDto) GetEmailOk() (*string, bool) {
	if o == nil || IsNil(o.Email) {
		return nil, false
	}
	return o.Email, true
}

// HasEmail returns a boolean if a field has been set.
func (o *RoleDto) HasEmail() bool {
	if o != nil && !IsNil(o.Email) {
		return true
	}

	return false
}

// SetEmail gets a reference to the given string and assigns it to the Email field.
func (o *RoleDto) SetEmail(v string) {
	o.Email = &v
}

// GetSystemRole returns the SystemRole field value
func (o *RoleDto) GetSystemRole() bool {
	if o == nil {
		var ret bool
		return ret
	}

	return o.SystemRole
}

// GetSystemRoleOk returns a tuple with the SystemRole field value
// and a boolean to check if the value has been set.
func (o *RoleDto) GetSystemRoleOk() (*bool, bool) {
	if o == nil {
		return nil, false
	}
	return &o.SystemRole, true
}

// SetSystemRole sets field value
func (o *RoleDto) SetSystemRole(v bool) {
	o.SystemRole = v
}

func (o RoleDto) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o RoleDto) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["uuid"] = o.Uuid
	toSerialize["name"] = o.Name
	if !IsNil(o.Description) {
		toSerialize["description"] = o.Description
	}
	if !IsNil(o.Email) {
		toSerialize["email"] = o.Email
	}
	toSerialize["systemRole"] = o.SystemRole

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return toSerialize, nil
}

func (o *RoleDto) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"uuid",
		"name",
		"systemRole",
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

	varRoleDto := _RoleDto{}

	err = json.Unmarshal(data, &varRoleDto)

	if err != nil {
		return err
	}

	*o = RoleDto(varRoleDto)

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(data, &additionalProperties); err == nil {
		delete(additionalProperties, "uuid")
		delete(additionalProperties, "name")
		delete(additionalProperties, "description")
		delete(additionalProperties, "email")
		delete(additionalProperties, "systemRole")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableRoleDto struct {
	value *RoleDto
	isSet bool
}

func (v NullableRoleDto) Get() *RoleDto {
	return v.value
}

func (v *NullableRoleDto) Set(val *RoleDto) {
	v.value = val
	v.isSet = true
}

func (v NullableRoleDto) IsSet() bool {
	return v.isSet
}

func (v *NullableRoleDto) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableRoleDto(val *RoleDto) *NullableRoleDto {
	return &NullableRoleDto{value: val, isSet: true}
}

func (v NullableRoleDto) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableRoleDto) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


