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

// checks if the MetadataResponseDto type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &MetadataResponseDto{}

// MetadataResponseDto Metadata response attributes with their source connector
type MetadataResponseDto struct {
	// UUID of the Connector
	ConnectorUuid *string `json:"connectorUuid,omitempty"`
	// Name of the Connector
	ConnectorName *string `json:"connectorName,omitempty"`
	// Source Object Type
	SourceObjectType *Resource `json:"sourceObjectType,omitempty"`
	// List of Metadata
	Items []ResponseMetadataDto `json:"items"`
	AdditionalProperties map[string]interface{}
}

type _MetadataResponseDto MetadataResponseDto

// NewMetadataResponseDto instantiates a new MetadataResponseDto object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewMetadataResponseDto(items []ResponseMetadataDto) *MetadataResponseDto {
	this := MetadataResponseDto{}
	this.Items = items
	return &this
}

// NewMetadataResponseDtoWithDefaults instantiates a new MetadataResponseDto object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewMetadataResponseDtoWithDefaults() *MetadataResponseDto {
	this := MetadataResponseDto{}
	return &this
}

// GetConnectorUuid returns the ConnectorUuid field value if set, zero value otherwise.
func (o *MetadataResponseDto) GetConnectorUuid() string {
	if o == nil || IsNil(o.ConnectorUuid) {
		var ret string
		return ret
	}
	return *o.ConnectorUuid
}

// GetConnectorUuidOk returns a tuple with the ConnectorUuid field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *MetadataResponseDto) GetConnectorUuidOk() (*string, bool) {
	if o == nil || IsNil(o.ConnectorUuid) {
		return nil, false
	}
	return o.ConnectorUuid, true
}

// HasConnectorUuid returns a boolean if a field has been set.
func (o *MetadataResponseDto) HasConnectorUuid() bool {
	if o != nil && !IsNil(o.ConnectorUuid) {
		return true
	}

	return false
}

// SetConnectorUuid gets a reference to the given string and assigns it to the ConnectorUuid field.
func (o *MetadataResponseDto) SetConnectorUuid(v string) {
	o.ConnectorUuid = &v
}

// GetConnectorName returns the ConnectorName field value if set, zero value otherwise.
func (o *MetadataResponseDto) GetConnectorName() string {
	if o == nil || IsNil(o.ConnectorName) {
		var ret string
		return ret
	}
	return *o.ConnectorName
}

// GetConnectorNameOk returns a tuple with the ConnectorName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *MetadataResponseDto) GetConnectorNameOk() (*string, bool) {
	if o == nil || IsNil(o.ConnectorName) {
		return nil, false
	}
	return o.ConnectorName, true
}

// HasConnectorName returns a boolean if a field has been set.
func (o *MetadataResponseDto) HasConnectorName() bool {
	if o != nil && !IsNil(o.ConnectorName) {
		return true
	}

	return false
}

// SetConnectorName gets a reference to the given string and assigns it to the ConnectorName field.
func (o *MetadataResponseDto) SetConnectorName(v string) {
	o.ConnectorName = &v
}

// GetSourceObjectType returns the SourceObjectType field value if set, zero value otherwise.
func (o *MetadataResponseDto) GetSourceObjectType() Resource {
	if o == nil || IsNil(o.SourceObjectType) {
		var ret Resource
		return ret
	}
	return *o.SourceObjectType
}

// GetSourceObjectTypeOk returns a tuple with the SourceObjectType field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *MetadataResponseDto) GetSourceObjectTypeOk() (*Resource, bool) {
	if o == nil || IsNil(o.SourceObjectType) {
		return nil, false
	}
	return o.SourceObjectType, true
}

// HasSourceObjectType returns a boolean if a field has been set.
func (o *MetadataResponseDto) HasSourceObjectType() bool {
	if o != nil && !IsNil(o.SourceObjectType) {
		return true
	}

	return false
}

// SetSourceObjectType gets a reference to the given Resource and assigns it to the SourceObjectType field.
func (o *MetadataResponseDto) SetSourceObjectType(v Resource) {
	o.SourceObjectType = &v
}

// GetItems returns the Items field value
func (o *MetadataResponseDto) GetItems() []ResponseMetadataDto {
	if o == nil {
		var ret []ResponseMetadataDto
		return ret
	}

	return o.Items
}

// GetItemsOk returns a tuple with the Items field value
// and a boolean to check if the value has been set.
func (o *MetadataResponseDto) GetItemsOk() ([]ResponseMetadataDto, bool) {
	if o == nil {
		return nil, false
	}
	return o.Items, true
}

// SetItems sets field value
func (o *MetadataResponseDto) SetItems(v []ResponseMetadataDto) {
	o.Items = v
}

func (o MetadataResponseDto) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o MetadataResponseDto) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.ConnectorUuid) {
		toSerialize["connectorUuid"] = o.ConnectorUuid
	}
	if !IsNil(o.ConnectorName) {
		toSerialize["connectorName"] = o.ConnectorName
	}
	if !IsNil(o.SourceObjectType) {
		toSerialize["sourceObjectType"] = o.SourceObjectType
	}
	toSerialize["items"] = o.Items

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return toSerialize, nil
}

func (o *MetadataResponseDto) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"items",
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

	varMetadataResponseDto := _MetadataResponseDto{}

	err = json.Unmarshal(data, &varMetadataResponseDto)

	if err != nil {
		return err
	}

	*o = MetadataResponseDto(varMetadataResponseDto)

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(data, &additionalProperties); err == nil {
		delete(additionalProperties, "connectorUuid")
		delete(additionalProperties, "connectorName")
		delete(additionalProperties, "sourceObjectType")
		delete(additionalProperties, "items")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableMetadataResponseDto struct {
	value *MetadataResponseDto
	isSet bool
}

func (v NullableMetadataResponseDto) Get() *MetadataResponseDto {
	return v.value
}

func (v *NullableMetadataResponseDto) Set(val *MetadataResponseDto) {
	v.value = val
	v.isSet = true
}

func (v NullableMetadataResponseDto) IsSet() bool {
	return v.isSet
}

func (v *NullableMetadataResponseDto) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableMetadataResponseDto(val *MetadataResponseDto) *NullableMetadataResponseDto {
	return &NullableMetadataResponseDto{value: val, isSet: true}
}

func (v NullableMetadataResponseDto) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableMetadataResponseDto) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


