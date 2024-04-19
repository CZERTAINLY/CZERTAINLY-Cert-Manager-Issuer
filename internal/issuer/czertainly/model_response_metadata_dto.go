/*
CZERTAINLY Cert Manager

REST API for implementations of cert-manager issuer

API version: 2.11.0
Contact: getinfo@czertainly.com
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package czertainly

import (
	"encoding/json"
	"fmt"
)

// checks if the ResponseMetadataDto type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &ResponseMetadataDto{}

// ResponseMetadataDto Response metadata attribute instance with content
type ResponseMetadataDto struct {
	// UUID of the Attribute
	Uuid *string `json:"uuid,omitempty"`
	// Name of the Attribute
	Name string `json:"name"`
	// Label of the the Attribute
	Label string `json:"label"`
	Type AttributeType `json:"type"`
	ContentType AttributeContentType `json:"contentType"`
	// Content of the Attribute
	Content []BaseAttributeContentDto `json:"content,omitempty"`
	// Source Object Type
	SourceObjectType *string `json:"sourceObjectType,omitempty"`
	// Source Objects
	SourceObjects []NameAndUuidDto `json:"sourceObjects,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _ResponseMetadataDto ResponseMetadataDto

// NewResponseMetadataDto instantiates a new ResponseMetadataDto object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewResponseMetadataDto(name string, label string, type_ AttributeType, contentType AttributeContentType) *ResponseMetadataDto {
	this := ResponseMetadataDto{}
	this.Name = name
	this.Label = label
	this.Type = type_
	this.ContentType = contentType
	return &this
}

// NewResponseMetadataDtoWithDefaults instantiates a new ResponseMetadataDto object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewResponseMetadataDtoWithDefaults() *ResponseMetadataDto {
	this := ResponseMetadataDto{}
	return &this
}

// GetUuid returns the Uuid field value if set, zero value otherwise.
func (o *ResponseMetadataDto) GetUuid() string {
	if o == nil || IsNil(o.Uuid) {
		var ret string
		return ret
	}
	return *o.Uuid
}

// GetUuidOk returns a tuple with the Uuid field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ResponseMetadataDto) GetUuidOk() (*string, bool) {
	if o == nil || IsNil(o.Uuid) {
		return nil, false
	}
	return o.Uuid, true
}

// HasUuid returns a boolean if a field has been set.
func (o *ResponseMetadataDto) HasUuid() bool {
	if o != nil && !IsNil(o.Uuid) {
		return true
	}

	return false
}

// SetUuid gets a reference to the given string and assigns it to the Uuid field.
func (o *ResponseMetadataDto) SetUuid(v string) {
	o.Uuid = &v
}

// GetName returns the Name field value
func (o *ResponseMetadataDto) GetName() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Name
}

// GetNameOk returns a tuple with the Name field value
// and a boolean to check if the value has been set.
func (o *ResponseMetadataDto) GetNameOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Name, true
}

// SetName sets field value
func (o *ResponseMetadataDto) SetName(v string) {
	o.Name = v
}

// GetLabel returns the Label field value
func (o *ResponseMetadataDto) GetLabel() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Label
}

// GetLabelOk returns a tuple with the Label field value
// and a boolean to check if the value has been set.
func (o *ResponseMetadataDto) GetLabelOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Label, true
}

// SetLabel sets field value
func (o *ResponseMetadataDto) SetLabel(v string) {
	o.Label = v
}

// GetType returns the Type field value
func (o *ResponseMetadataDto) GetType() AttributeType {
	if o == nil {
		var ret AttributeType
		return ret
	}

	return o.Type
}

// GetTypeOk returns a tuple with the Type field value
// and a boolean to check if the value has been set.
func (o *ResponseMetadataDto) GetTypeOk() (*AttributeType, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Type, true
}

// SetType sets field value
func (o *ResponseMetadataDto) SetType(v AttributeType) {
	o.Type = v
}

// GetContentType returns the ContentType field value
func (o *ResponseMetadataDto) GetContentType() AttributeContentType {
	if o == nil {
		var ret AttributeContentType
		return ret
	}

	return o.ContentType
}

// GetContentTypeOk returns a tuple with the ContentType field value
// and a boolean to check if the value has been set.
func (o *ResponseMetadataDto) GetContentTypeOk() (*AttributeContentType, bool) {
	if o == nil {
		return nil, false
	}
	return &o.ContentType, true
}

// SetContentType sets field value
func (o *ResponseMetadataDto) SetContentType(v AttributeContentType) {
	o.ContentType = v
}

// GetContent returns the Content field value if set, zero value otherwise.
func (o *ResponseMetadataDto) GetContent() []BaseAttributeContentDto {
	if o == nil || IsNil(o.Content) {
		var ret []BaseAttributeContentDto
		return ret
	}
	return o.Content
}

// GetContentOk returns a tuple with the Content field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ResponseMetadataDto) GetContentOk() ([]BaseAttributeContentDto, bool) {
	if o == nil || IsNil(o.Content) {
		return nil, false
	}
	return o.Content, true
}

// HasContent returns a boolean if a field has been set.
func (o *ResponseMetadataDto) HasContent() bool {
	if o != nil && !IsNil(o.Content) {
		return true
	}

	return false
}

// SetContent gets a reference to the given []BaseAttributeContentDto and assigns it to the Content field.
func (o *ResponseMetadataDto) SetContent(v []BaseAttributeContentDto) {
	o.Content = v
}

// GetSourceObjectType returns the SourceObjectType field value if set, zero value otherwise.
func (o *ResponseMetadataDto) GetSourceObjectType() string {
	if o == nil || IsNil(o.SourceObjectType) {
		var ret string
		return ret
	}
	return *o.SourceObjectType
}

// GetSourceObjectTypeOk returns a tuple with the SourceObjectType field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ResponseMetadataDto) GetSourceObjectTypeOk() (*string, bool) {
	if o == nil || IsNil(o.SourceObjectType) {
		return nil, false
	}
	return o.SourceObjectType, true
}

// HasSourceObjectType returns a boolean if a field has been set.
func (o *ResponseMetadataDto) HasSourceObjectType() bool {
	if o != nil && !IsNil(o.SourceObjectType) {
		return true
	}

	return false
}

// SetSourceObjectType gets a reference to the given string and assigns it to the SourceObjectType field.
func (o *ResponseMetadataDto) SetSourceObjectType(v string) {
	o.SourceObjectType = &v
}

// GetSourceObjects returns the SourceObjects field value if set, zero value otherwise.
func (o *ResponseMetadataDto) GetSourceObjects() []NameAndUuidDto {
	if o == nil || IsNil(o.SourceObjects) {
		var ret []NameAndUuidDto
		return ret
	}
	return o.SourceObjects
}

// GetSourceObjectsOk returns a tuple with the SourceObjects field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ResponseMetadataDto) GetSourceObjectsOk() ([]NameAndUuidDto, bool) {
	if o == nil || IsNil(o.SourceObjects) {
		return nil, false
	}
	return o.SourceObjects, true
}

// HasSourceObjects returns a boolean if a field has been set.
func (o *ResponseMetadataDto) HasSourceObjects() bool {
	if o != nil && !IsNil(o.SourceObjects) {
		return true
	}

	return false
}

// SetSourceObjects gets a reference to the given []NameAndUuidDto and assigns it to the SourceObjects field.
func (o *ResponseMetadataDto) SetSourceObjects(v []NameAndUuidDto) {
	o.SourceObjects = v
}

func (o ResponseMetadataDto) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o ResponseMetadataDto) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Uuid) {
		toSerialize["uuid"] = o.Uuid
	}
	toSerialize["name"] = o.Name
	toSerialize["label"] = o.Label
	toSerialize["type"] = o.Type
	toSerialize["contentType"] = o.ContentType
	if !IsNil(o.Content) {
		toSerialize["content"] = o.Content
	}
	if !IsNil(o.SourceObjectType) {
		toSerialize["sourceObjectType"] = o.SourceObjectType
	}
	if !IsNil(o.SourceObjects) {
		toSerialize["sourceObjects"] = o.SourceObjects
	}

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return toSerialize, nil
}

func (o *ResponseMetadataDto) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"name",
		"label",
		"type",
		"contentType",
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

	varResponseMetadataDto := _ResponseMetadataDto{}

	err = json.Unmarshal(data, &varResponseMetadataDto)

	if err != nil {
		return err
	}

	*o = ResponseMetadataDto(varResponseMetadataDto)

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(data, &additionalProperties); err == nil {
		delete(additionalProperties, "uuid")
		delete(additionalProperties, "name")
		delete(additionalProperties, "label")
		delete(additionalProperties, "type")
		delete(additionalProperties, "contentType")
		delete(additionalProperties, "content")
		delete(additionalProperties, "sourceObjectType")
		delete(additionalProperties, "sourceObjects")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableResponseMetadataDto struct {
	value *ResponseMetadataDto
	isSet bool
}

func (v NullableResponseMetadataDto) Get() *ResponseMetadataDto {
	return v.value
}

func (v *NullableResponseMetadataDto) Set(val *ResponseMetadataDto) {
	v.value = val
	v.isSet = true
}

func (v NullableResponseMetadataDto) IsSet() bool {
	return v.isSet
}

func (v *NullableResponseMetadataDto) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableResponseMetadataDto(val *ResponseMetadataDto) *NullableResponseMetadataDto {
	return &NullableResponseMetadataDto{value: val, isSet: true}
}

func (v NullableResponseMetadataDto) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableResponseMetadataDto) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


