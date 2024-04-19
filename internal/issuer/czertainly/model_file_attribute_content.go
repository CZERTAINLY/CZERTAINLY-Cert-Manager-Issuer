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

// checks if the FileAttributeContent type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &FileAttributeContent{}

// FileAttributeContent struct for FileAttributeContent
type FileAttributeContent struct {
	// Content Reference
	Reference *string `json:"reference,omitempty"`
	Data FileAttributeContentData `json:"data"`
	AdditionalProperties map[string]interface{}
}

type _FileAttributeContent FileAttributeContent

// NewFileAttributeContent instantiates a new FileAttributeContent object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewFileAttributeContent(data FileAttributeContentData) *FileAttributeContent {
	this := FileAttributeContent{}
	this.Data = data
	return &this
}

// NewFileAttributeContentWithDefaults instantiates a new FileAttributeContent object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewFileAttributeContentWithDefaults() *FileAttributeContent {
	this := FileAttributeContent{}
	return &this
}

// GetReference returns the Reference field value if set, zero value otherwise.
func (o *FileAttributeContent) GetReference() string {
	if o == nil || IsNil(o.Reference) {
		var ret string
		return ret
	}
	return *o.Reference
}

// GetReferenceOk returns a tuple with the Reference field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FileAttributeContent) GetReferenceOk() (*string, bool) {
	if o == nil || IsNil(o.Reference) {
		return nil, false
	}
	return o.Reference, true
}

// HasReference returns a boolean if a field has been set.
func (o *FileAttributeContent) HasReference() bool {
	if o != nil && !IsNil(o.Reference) {
		return true
	}

	return false
}

// SetReference gets a reference to the given string and assigns it to the Reference field.
func (o *FileAttributeContent) SetReference(v string) {
	o.Reference = &v
}

// GetData returns the Data field value
func (o *FileAttributeContent) GetData() FileAttributeContentData {
	if o == nil {
		var ret FileAttributeContentData
		return ret
	}

	return o.Data
}

// GetDataOk returns a tuple with the Data field value
// and a boolean to check if the value has been set.
func (o *FileAttributeContent) GetDataOk() (*FileAttributeContentData, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Data, true
}

// SetData sets field value
func (o *FileAttributeContent) SetData(v FileAttributeContentData) {
	o.Data = v
}

func (o FileAttributeContent) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o FileAttributeContent) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Reference) {
		toSerialize["reference"] = o.Reference
	}
	toSerialize["data"] = o.Data

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return toSerialize, nil
}

func (o *FileAttributeContent) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"data",
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

	varFileAttributeContent := _FileAttributeContent{}

	err = json.Unmarshal(data, &varFileAttributeContent)

	if err != nil {
		return err
	}

	*o = FileAttributeContent(varFileAttributeContent)

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(data, &additionalProperties); err == nil {
		delete(additionalProperties, "reference")
		delete(additionalProperties, "data")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableFileAttributeContent struct {
	value *FileAttributeContent
	isSet bool
}

func (v NullableFileAttributeContent) Get() *FileAttributeContent {
	return v.value
}

func (v *NullableFileAttributeContent) Set(val *FileAttributeContent) {
	v.value = val
	v.isSet = true
}

func (v NullableFileAttributeContent) IsSet() bool {
	return v.isSet
}

func (v *NullableFileAttributeContent) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableFileAttributeContent(val *FileAttributeContent) *NullableFileAttributeContent {
	return &NullableFileAttributeContent{value: val, isSet: true}
}

func (v NullableFileAttributeContent) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableFileAttributeContent) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


