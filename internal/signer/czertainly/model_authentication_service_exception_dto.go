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

// checks if the AuthenticationServiceExceptionDto type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AuthenticationServiceExceptionDto{}

// AuthenticationServiceExceptionDto struct for AuthenticationServiceExceptionDto
type AuthenticationServiceExceptionDto struct {
	// Status code of the HTTP Request
	StatusCode int32 `json:"statusCode"`
	// Code of the result
	Code string `json:"code"`
	// Exception message
	Message string `json:"message"`
	AdditionalProperties map[string]interface{}
}

type _AuthenticationServiceExceptionDto AuthenticationServiceExceptionDto

// NewAuthenticationServiceExceptionDto instantiates a new AuthenticationServiceExceptionDto object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAuthenticationServiceExceptionDto(statusCode int32, code string, message string) *AuthenticationServiceExceptionDto {
	this := AuthenticationServiceExceptionDto{}
	this.StatusCode = statusCode
	this.Code = code
	this.Message = message
	return &this
}

// NewAuthenticationServiceExceptionDtoWithDefaults instantiates a new AuthenticationServiceExceptionDto object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAuthenticationServiceExceptionDtoWithDefaults() *AuthenticationServiceExceptionDto {
	this := AuthenticationServiceExceptionDto{}
	return &this
}

// GetStatusCode returns the StatusCode field value
func (o *AuthenticationServiceExceptionDto) GetStatusCode() int32 {
	if o == nil {
		var ret int32
		return ret
	}

	return o.StatusCode
}

// GetStatusCodeOk returns a tuple with the StatusCode field value
// and a boolean to check if the value has been set.
func (o *AuthenticationServiceExceptionDto) GetStatusCodeOk() (*int32, bool) {
	if o == nil {
		return nil, false
	}
	return &o.StatusCode, true
}

// SetStatusCode sets field value
func (o *AuthenticationServiceExceptionDto) SetStatusCode(v int32) {
	o.StatusCode = v
}

// GetCode returns the Code field value
func (o *AuthenticationServiceExceptionDto) GetCode() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Code
}

// GetCodeOk returns a tuple with the Code field value
// and a boolean to check if the value has been set.
func (o *AuthenticationServiceExceptionDto) GetCodeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Code, true
}

// SetCode sets field value
func (o *AuthenticationServiceExceptionDto) SetCode(v string) {
	o.Code = v
}

// GetMessage returns the Message field value
func (o *AuthenticationServiceExceptionDto) GetMessage() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Message
}

// GetMessageOk returns a tuple with the Message field value
// and a boolean to check if the value has been set.
func (o *AuthenticationServiceExceptionDto) GetMessageOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Message, true
}

// SetMessage sets field value
func (o *AuthenticationServiceExceptionDto) SetMessage(v string) {
	o.Message = v
}

func (o AuthenticationServiceExceptionDto) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AuthenticationServiceExceptionDto) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["statusCode"] = o.StatusCode
	toSerialize["code"] = o.Code
	toSerialize["message"] = o.Message

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return toSerialize, nil
}

func (o *AuthenticationServiceExceptionDto) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"statusCode",
		"code",
		"message",
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

	varAuthenticationServiceExceptionDto := _AuthenticationServiceExceptionDto{}

	err = json.Unmarshal(data, &varAuthenticationServiceExceptionDto)

	if err != nil {
		return err
	}

	*o = AuthenticationServiceExceptionDto(varAuthenticationServiceExceptionDto)

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(data, &additionalProperties); err == nil {
		delete(additionalProperties, "statusCode")
		delete(additionalProperties, "code")
		delete(additionalProperties, "message")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableAuthenticationServiceExceptionDto struct {
	value *AuthenticationServiceExceptionDto
	isSet bool
}

func (v NullableAuthenticationServiceExceptionDto) Get() *AuthenticationServiceExceptionDto {
	return v.value
}

func (v *NullableAuthenticationServiceExceptionDto) Set(val *AuthenticationServiceExceptionDto) {
	v.value = val
	v.isSet = true
}

func (v NullableAuthenticationServiceExceptionDto) IsSet() bool {
	return v.isSet
}

func (v *NullableAuthenticationServiceExceptionDto) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAuthenticationServiceExceptionDto(val *AuthenticationServiceExceptionDto) *NullableAuthenticationServiceExceptionDto {
	return &NullableAuthenticationServiceExceptionDto{value: val, isSet: true}
}

func (v NullableAuthenticationServiceExceptionDto) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAuthenticationServiceExceptionDto) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


