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

// checks if the AttributeCallbackMapping type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AttributeCallbackMapping{}

// AttributeCallbackMapping Mappings for the callback method
type AttributeCallbackMapping struct {
	// Name of the attribute whose value is to be used as value of path variable or request param or body field.It is optional and must be set only if value is not set.
	From *string `json:"from,omitempty"`
	AttributeType *AttributeType `json:"attributeType,omitempty"`
	AttributeContentType *AttributeContentType `json:"attributeContentType,omitempty"`
	// Name of the path variable or request param or body field which is to be used to assign value of attribute
	To string `json:"to"`
	// Set of targets for propagating value.
	Targets []AttributeValueTarget `json:"targets"`
	// Static value to be propagated to targets. It is optional and is set only if the value is known at attribute creation time.
	Value map[string]interface{} `json:"value,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _AttributeCallbackMapping AttributeCallbackMapping

// NewAttributeCallbackMapping instantiates a new AttributeCallbackMapping object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAttributeCallbackMapping(to string, targets []AttributeValueTarget) *AttributeCallbackMapping {
	this := AttributeCallbackMapping{}
	this.To = to
	this.Targets = targets
	return &this
}

// NewAttributeCallbackMappingWithDefaults instantiates a new AttributeCallbackMapping object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAttributeCallbackMappingWithDefaults() *AttributeCallbackMapping {
	this := AttributeCallbackMapping{}
	return &this
}

// GetFrom returns the From field value if set, zero value otherwise.
func (o *AttributeCallbackMapping) GetFrom() string {
	if o == nil || IsNil(o.From) {
		var ret string
		return ret
	}
	return *o.From
}

// GetFromOk returns a tuple with the From field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AttributeCallbackMapping) GetFromOk() (*string, bool) {
	if o == nil || IsNil(o.From) {
		return nil, false
	}
	return o.From, true
}

// HasFrom returns a boolean if a field has been set.
func (o *AttributeCallbackMapping) HasFrom() bool {
	if o != nil && !IsNil(o.From) {
		return true
	}

	return false
}

// SetFrom gets a reference to the given string and assigns it to the From field.
func (o *AttributeCallbackMapping) SetFrom(v string) {
	o.From = &v
}

// GetAttributeType returns the AttributeType field value if set, zero value otherwise.
func (o *AttributeCallbackMapping) GetAttributeType() AttributeType {
	if o == nil || IsNil(o.AttributeType) {
		var ret AttributeType
		return ret
	}
	return *o.AttributeType
}

// GetAttributeTypeOk returns a tuple with the AttributeType field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AttributeCallbackMapping) GetAttributeTypeOk() (*AttributeType, bool) {
	if o == nil || IsNil(o.AttributeType) {
		return nil, false
	}
	return o.AttributeType, true
}

// HasAttributeType returns a boolean if a field has been set.
func (o *AttributeCallbackMapping) HasAttributeType() bool {
	if o != nil && !IsNil(o.AttributeType) {
		return true
	}

	return false
}

// SetAttributeType gets a reference to the given AttributeType and assigns it to the AttributeType field.
func (o *AttributeCallbackMapping) SetAttributeType(v AttributeType) {
	o.AttributeType = &v
}

// GetAttributeContentType returns the AttributeContentType field value if set, zero value otherwise.
func (o *AttributeCallbackMapping) GetAttributeContentType() AttributeContentType {
	if o == nil || IsNil(o.AttributeContentType) {
		var ret AttributeContentType
		return ret
	}
	return *o.AttributeContentType
}

// GetAttributeContentTypeOk returns a tuple with the AttributeContentType field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AttributeCallbackMapping) GetAttributeContentTypeOk() (*AttributeContentType, bool) {
	if o == nil || IsNil(o.AttributeContentType) {
		return nil, false
	}
	return o.AttributeContentType, true
}

// HasAttributeContentType returns a boolean if a field has been set.
func (o *AttributeCallbackMapping) HasAttributeContentType() bool {
	if o != nil && !IsNil(o.AttributeContentType) {
		return true
	}

	return false
}

// SetAttributeContentType gets a reference to the given AttributeContentType and assigns it to the AttributeContentType field.
func (o *AttributeCallbackMapping) SetAttributeContentType(v AttributeContentType) {
	o.AttributeContentType = &v
}

// GetTo returns the To field value
func (o *AttributeCallbackMapping) GetTo() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.To
}

// GetToOk returns a tuple with the To field value
// and a boolean to check if the value has been set.
func (o *AttributeCallbackMapping) GetToOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.To, true
}

// SetTo sets field value
func (o *AttributeCallbackMapping) SetTo(v string) {
	o.To = v
}

// GetTargets returns the Targets field value
func (o *AttributeCallbackMapping) GetTargets() []AttributeValueTarget {
	if o == nil {
		var ret []AttributeValueTarget
		return ret
	}

	return o.Targets
}

// GetTargetsOk returns a tuple with the Targets field value
// and a boolean to check if the value has been set.
func (o *AttributeCallbackMapping) GetTargetsOk() ([]AttributeValueTarget, bool) {
	if o == nil {
		return nil, false
	}
	return o.Targets, true
}

// SetTargets sets field value
func (o *AttributeCallbackMapping) SetTargets(v []AttributeValueTarget) {
	o.Targets = v
}

// GetValue returns the Value field value if set, zero value otherwise.
func (o *AttributeCallbackMapping) GetValue() map[string]interface{} {
	if o == nil || IsNil(o.Value) {
		var ret map[string]interface{}
		return ret
	}
	return o.Value
}

// GetValueOk returns a tuple with the Value field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AttributeCallbackMapping) GetValueOk() (map[string]interface{}, bool) {
	if o == nil || IsNil(o.Value) {
		return map[string]interface{}{}, false
	}
	return o.Value, true
}

// HasValue returns a boolean if a field has been set.
func (o *AttributeCallbackMapping) HasValue() bool {
	if o != nil && !IsNil(o.Value) {
		return true
	}

	return false
}

// SetValue gets a reference to the given map[string]interface{} and assigns it to the Value field.
func (o *AttributeCallbackMapping) SetValue(v map[string]interface{}) {
	o.Value = v
}

func (o AttributeCallbackMapping) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AttributeCallbackMapping) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.From) {
		toSerialize["from"] = o.From
	}
	if !IsNil(o.AttributeType) {
		toSerialize["attributeType"] = o.AttributeType
	}
	if !IsNil(o.AttributeContentType) {
		toSerialize["attributeContentType"] = o.AttributeContentType
	}
	toSerialize["to"] = o.To
	toSerialize["targets"] = o.Targets
	if !IsNil(o.Value) {
		toSerialize["value"] = o.Value
	}

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return toSerialize, nil
}

func (o *AttributeCallbackMapping) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"to",
		"targets",
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

	varAttributeCallbackMapping := _AttributeCallbackMapping{}

	err = json.Unmarshal(data, &varAttributeCallbackMapping)

	if err != nil {
		return err
	}

	*o = AttributeCallbackMapping(varAttributeCallbackMapping)

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(data, &additionalProperties); err == nil {
		delete(additionalProperties, "from")
		delete(additionalProperties, "attributeType")
		delete(additionalProperties, "attributeContentType")
		delete(additionalProperties, "to")
		delete(additionalProperties, "targets")
		delete(additionalProperties, "value")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableAttributeCallbackMapping struct {
	value *AttributeCallbackMapping
	isSet bool
}

func (v NullableAttributeCallbackMapping) Get() *AttributeCallbackMapping {
	return v.value
}

func (v *NullableAttributeCallbackMapping) Set(val *AttributeCallbackMapping) {
	v.value = val
	v.isSet = true
}

func (v NullableAttributeCallbackMapping) IsSet() bool {
	return v.isSet
}

func (v *NullableAttributeCallbackMapping) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAttributeCallbackMapping(val *AttributeCallbackMapping) *NullableAttributeCallbackMapping {
	return &NullableAttributeCallbackMapping{value: val, isSet: true}
}

func (v NullableAttributeCallbackMapping) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAttributeCallbackMapping) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


