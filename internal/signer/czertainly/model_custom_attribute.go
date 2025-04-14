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

// checks if the CustomAttribute type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &CustomAttribute{}

// CustomAttribute Custom attribute allows to store and transfer dynamic data. Its content can be edited and send in requests to store.
type CustomAttribute struct {
	// Version of the Attribute
	Version *int32 `json:"version,omitempty"`
	// UUID of the Attribute for unique identification
	Uuid string `json:"uuid"`
	// Name of the Attribute that is used for identification
	Name string `json:"name"`
	// Optional description of the Attribute, should contain helper text on what is expected
	Description *string `json:"description,omitempty"`
	// Content of the Attribute
	Content []BaseAttributeContentDto `json:"content,omitempty"`
	// Type of the Attribute
	Type AttributeType `json:"type"`
	// Type of the Content
	ContentType AttributeContentType `json:"contentType"`
	// Properties of the Attributes
	Properties CustomAttributeProperties `json:"properties"`
	AdditionalProperties map[string]interface{}
}

type _CustomAttribute CustomAttribute

// NewCustomAttribute instantiates a new CustomAttribute object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCustomAttribute(uuid string, name string, type_ AttributeType, contentType AttributeContentType, properties CustomAttributeProperties) *CustomAttribute {
	this := CustomAttribute{}
	var version int32 = 2
	this.Version = &version
	this.Uuid = uuid
	this.Name = name
	this.Type = type_
	this.ContentType = contentType
	this.Properties = properties
	return &this
}

// NewCustomAttributeWithDefaults instantiates a new CustomAttribute object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCustomAttributeWithDefaults() *CustomAttribute {
	this := CustomAttribute{}
	var version int32 = 2
	this.Version = &version
	return &this
}

// GetVersion returns the Version field value if set, zero value otherwise.
func (o *CustomAttribute) GetVersion() int32 {
	if o == nil || IsNil(o.Version) {
		var ret int32
		return ret
	}
	return *o.Version
}

// GetVersionOk returns a tuple with the Version field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustomAttribute) GetVersionOk() (*int32, bool) {
	if o == nil || IsNil(o.Version) {
		return nil, false
	}
	return o.Version, true
}

// HasVersion returns a boolean if a field has been set.
func (o *CustomAttribute) HasVersion() bool {
	if o != nil && !IsNil(o.Version) {
		return true
	}

	return false
}

// SetVersion gets a reference to the given int32 and assigns it to the Version field.
func (o *CustomAttribute) SetVersion(v int32) {
	o.Version = &v
}

// GetUuid returns the Uuid field value
func (o *CustomAttribute) GetUuid() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Uuid
}

// GetUuidOk returns a tuple with the Uuid field value
// and a boolean to check if the value has been set.
func (o *CustomAttribute) GetUuidOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Uuid, true
}

// SetUuid sets field value
func (o *CustomAttribute) SetUuid(v string) {
	o.Uuid = v
}

// GetName returns the Name field value
func (o *CustomAttribute) GetName() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Name
}

// GetNameOk returns a tuple with the Name field value
// and a boolean to check if the value has been set.
func (o *CustomAttribute) GetNameOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Name, true
}

// SetName sets field value
func (o *CustomAttribute) SetName(v string) {
	o.Name = v
}

// GetDescription returns the Description field value if set, zero value otherwise.
func (o *CustomAttribute) GetDescription() string {
	if o == nil || IsNil(o.Description) {
		var ret string
		return ret
	}
	return *o.Description
}

// GetDescriptionOk returns a tuple with the Description field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustomAttribute) GetDescriptionOk() (*string, bool) {
	if o == nil || IsNil(o.Description) {
		return nil, false
	}
	return o.Description, true
}

// HasDescription returns a boolean if a field has been set.
func (o *CustomAttribute) HasDescription() bool {
	if o != nil && !IsNil(o.Description) {
		return true
	}

	return false
}

// SetDescription gets a reference to the given string and assigns it to the Description field.
func (o *CustomAttribute) SetDescription(v string) {
	o.Description = &v
}

// GetContent returns the Content field value if set, zero value otherwise.
func (o *CustomAttribute) GetContent() []BaseAttributeContentDto {
	if o == nil || IsNil(o.Content) {
		var ret []BaseAttributeContentDto
		return ret
	}
	return o.Content
}

// GetContentOk returns a tuple with the Content field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustomAttribute) GetContentOk() ([]BaseAttributeContentDto, bool) {
	if o == nil || IsNil(o.Content) {
		return nil, false
	}
	return o.Content, true
}

// HasContent returns a boolean if a field has been set.
func (o *CustomAttribute) HasContent() bool {
	if o != nil && !IsNil(o.Content) {
		return true
	}

	return false
}

// SetContent gets a reference to the given []BaseAttributeContentDto and assigns it to the Content field.
func (o *CustomAttribute) SetContent(v []BaseAttributeContentDto) {
	o.Content = v
}

// GetType returns the Type field value
func (o *CustomAttribute) GetType() AttributeType {
	if o == nil {
		var ret AttributeType
		return ret
	}

	return o.Type
}

// GetTypeOk returns a tuple with the Type field value
// and a boolean to check if the value has been set.
func (o *CustomAttribute) GetTypeOk() (*AttributeType, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Type, true
}

// SetType sets field value
func (o *CustomAttribute) SetType(v AttributeType) {
	o.Type = v
}

// GetContentType returns the ContentType field value
func (o *CustomAttribute) GetContentType() AttributeContentType {
	if o == nil {
		var ret AttributeContentType
		return ret
	}

	return o.ContentType
}

// GetContentTypeOk returns a tuple with the ContentType field value
// and a boolean to check if the value has been set.
func (o *CustomAttribute) GetContentTypeOk() (*AttributeContentType, bool) {
	if o == nil {
		return nil, false
	}
	return &o.ContentType, true
}

// SetContentType sets field value
func (o *CustomAttribute) SetContentType(v AttributeContentType) {
	o.ContentType = v
}

// GetProperties returns the Properties field value
func (o *CustomAttribute) GetProperties() CustomAttributeProperties {
	if o == nil {
		var ret CustomAttributeProperties
		return ret
	}

	return o.Properties
}

// GetPropertiesOk returns a tuple with the Properties field value
// and a boolean to check if the value has been set.
func (o *CustomAttribute) GetPropertiesOk() (*CustomAttributeProperties, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Properties, true
}

// SetProperties sets field value
func (o *CustomAttribute) SetProperties(v CustomAttributeProperties) {
	o.Properties = v
}

func (o CustomAttribute) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o CustomAttribute) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Version) {
		toSerialize["version"] = o.Version
	}
	toSerialize["uuid"] = o.Uuid
	toSerialize["name"] = o.Name
	if !IsNil(o.Description) {
		toSerialize["description"] = o.Description
	}
	if !IsNil(o.Content) {
		toSerialize["content"] = o.Content
	}
	toSerialize["type"] = o.Type
	toSerialize["contentType"] = o.ContentType
	toSerialize["properties"] = o.Properties

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return toSerialize, nil
}

func (o *CustomAttribute) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"uuid",
		"name",
		"type",
		"contentType",
		"properties",
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

	varCustomAttribute := _CustomAttribute{}

	err = json.Unmarshal(data, &varCustomAttribute)

	if err != nil {
		return err
	}

	*o = CustomAttribute(varCustomAttribute)

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(data, &additionalProperties); err == nil {
		delete(additionalProperties, "version")
		delete(additionalProperties, "uuid")
		delete(additionalProperties, "name")
		delete(additionalProperties, "description")
		delete(additionalProperties, "content")
		delete(additionalProperties, "type")
		delete(additionalProperties, "contentType")
		delete(additionalProperties, "properties")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableCustomAttribute struct {
	value *CustomAttribute
	isSet bool
}

func (v NullableCustomAttribute) Get() *CustomAttribute {
	return v.value
}

func (v *NullableCustomAttribute) Set(val *CustomAttribute) {
	v.value = val
	v.isSet = true
}

func (v NullableCustomAttribute) IsSet() bool {
	return v.isSet
}

func (v *NullableCustomAttribute) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCustomAttribute(val *CustomAttribute) *NullableCustomAttribute {
	return &NullableCustomAttribute{value: val, isSet: true}
}

func (v NullableCustomAttribute) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCustomAttribute) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


