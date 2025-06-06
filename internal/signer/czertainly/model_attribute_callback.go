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

// checks if the AttributeCallback type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AttributeCallback{}

// AttributeCallback struct for AttributeCallback
type AttributeCallback struct {
	// Context part of callback URL
	CallbackContext string `json:"callbackContext"`
	// HTTP method of the callback
	CallbackMethod string `json:"callbackMethod"`
	// Mappings for the callback method
	Mappings []AttributeCallbackMapping `json:"mappings"`
	AdditionalProperties map[string]interface{}
}

type _AttributeCallback AttributeCallback

// NewAttributeCallback instantiates a new AttributeCallback object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAttributeCallback(callbackContext string, callbackMethod string, mappings []AttributeCallbackMapping) *AttributeCallback {
	this := AttributeCallback{}
	this.CallbackContext = callbackContext
	this.CallbackMethod = callbackMethod
	this.Mappings = mappings
	return &this
}

// NewAttributeCallbackWithDefaults instantiates a new AttributeCallback object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAttributeCallbackWithDefaults() *AttributeCallback {
	this := AttributeCallback{}
	return &this
}

// GetCallbackContext returns the CallbackContext field value
func (o *AttributeCallback) GetCallbackContext() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.CallbackContext
}

// GetCallbackContextOk returns a tuple with the CallbackContext field value
// and a boolean to check if the value has been set.
func (o *AttributeCallback) GetCallbackContextOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.CallbackContext, true
}

// SetCallbackContext sets field value
func (o *AttributeCallback) SetCallbackContext(v string) {
	o.CallbackContext = v
}

// GetCallbackMethod returns the CallbackMethod field value
func (o *AttributeCallback) GetCallbackMethod() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.CallbackMethod
}

// GetCallbackMethodOk returns a tuple with the CallbackMethod field value
// and a boolean to check if the value has been set.
func (o *AttributeCallback) GetCallbackMethodOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.CallbackMethod, true
}

// SetCallbackMethod sets field value
func (o *AttributeCallback) SetCallbackMethod(v string) {
	o.CallbackMethod = v
}

// GetMappings returns the Mappings field value
func (o *AttributeCallback) GetMappings() []AttributeCallbackMapping {
	if o == nil {
		var ret []AttributeCallbackMapping
		return ret
	}

	return o.Mappings
}

// GetMappingsOk returns a tuple with the Mappings field value
// and a boolean to check if the value has been set.
func (o *AttributeCallback) GetMappingsOk() ([]AttributeCallbackMapping, bool) {
	if o == nil {
		return nil, false
	}
	return o.Mappings, true
}

// SetMappings sets field value
func (o *AttributeCallback) SetMappings(v []AttributeCallbackMapping) {
	o.Mappings = v
}

func (o AttributeCallback) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AttributeCallback) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["callbackContext"] = o.CallbackContext
	toSerialize["callbackMethod"] = o.CallbackMethod
	toSerialize["mappings"] = o.Mappings

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return toSerialize, nil
}

func (o *AttributeCallback) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"callbackContext",
		"callbackMethod",
		"mappings",
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

	varAttributeCallback := _AttributeCallback{}

	err = json.Unmarshal(data, &varAttributeCallback)

	if err != nil {
		return err
	}

	*o = AttributeCallback(varAttributeCallback)

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(data, &additionalProperties); err == nil {
		delete(additionalProperties, "callbackContext")
		delete(additionalProperties, "callbackMethod")
		delete(additionalProperties, "mappings")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableAttributeCallback struct {
	value *AttributeCallback
	isSet bool
}

func (v NullableAttributeCallback) Get() *AttributeCallback {
	return v.value
}

func (v *NullableAttributeCallback) Set(val *AttributeCallback) {
	v.value = val
	v.isSet = true
}

func (v NullableAttributeCallback) IsSet() bool {
	return v.isSet
}

func (v *NullableAttributeCallback) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAttributeCallback(val *AttributeCallback) *NullableAttributeCallback {
	return &NullableAttributeCallback{value: val, isSet: true}
}

func (v NullableAttributeCallback) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAttributeCallback) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


