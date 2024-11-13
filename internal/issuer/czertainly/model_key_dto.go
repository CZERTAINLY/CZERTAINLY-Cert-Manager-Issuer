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
	"time"
	"fmt"
)

// checks if the KeyDto type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &KeyDto{}

// KeyDto Key Pair of the certificate
type KeyDto struct {
	// Object identifier
	Uuid string `json:"uuid"`
	// Object Name
	Name string `json:"name"`
	// Description of the Key
	Description string `json:"description"`
	// Creation time of the Key. If the key is discovered from the connector, then it will be returned
	CreationTime time.Time `json:"creationTime"`
	// UUID of the Token Profile
	TokenProfileUuid *string `json:"tokenProfileUuid,omitempty"`
	// Name of the Token Profile
	TokenProfileName *string `json:"tokenProfileName,omitempty"`
	// Token Instance UUID
	TokenInstanceUuid string `json:"tokenInstanceUuid"`
	// Token Instance Name
	TokenInstanceName string `json:"tokenInstanceName"`
	// Owner of the Key
	Owner *string `json:"owner,omitempty"`
	// UUID of the owner of the Key
	OwnerUuid *string `json:"ownerUuid,omitempty"`
	// Groups associated to the key
	Groups []GroupDto `json:"groups,omitempty"`
	// Key Items
	Items []KeyItemDto `json:"items"`
	// Number of associated objects
	Associations *int32 `json:"associations,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _KeyDto KeyDto

// NewKeyDto instantiates a new KeyDto object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewKeyDto(uuid string, name string, description string, creationTime time.Time, tokenInstanceUuid string, tokenInstanceName string, items []KeyItemDto) *KeyDto {
	this := KeyDto{}
	this.Uuid = uuid
	this.Name = name
	this.Description = description
	this.CreationTime = creationTime
	this.TokenInstanceUuid = tokenInstanceUuid
	this.TokenInstanceName = tokenInstanceName
	this.Items = items
	return &this
}

// NewKeyDtoWithDefaults instantiates a new KeyDto object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewKeyDtoWithDefaults() *KeyDto {
	this := KeyDto{}
	return &this
}

// GetUuid returns the Uuid field value
func (o *KeyDto) GetUuid() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Uuid
}

// GetUuidOk returns a tuple with the Uuid field value
// and a boolean to check if the value has been set.
func (o *KeyDto) GetUuidOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Uuid, true
}

// SetUuid sets field value
func (o *KeyDto) SetUuid(v string) {
	o.Uuid = v
}

// GetName returns the Name field value
func (o *KeyDto) GetName() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Name
}

// GetNameOk returns a tuple with the Name field value
// and a boolean to check if the value has been set.
func (o *KeyDto) GetNameOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Name, true
}

// SetName sets field value
func (o *KeyDto) SetName(v string) {
	o.Name = v
}

// GetDescription returns the Description field value
func (o *KeyDto) GetDescription() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Description
}

// GetDescriptionOk returns a tuple with the Description field value
// and a boolean to check if the value has been set.
func (o *KeyDto) GetDescriptionOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Description, true
}

// SetDescription sets field value
func (o *KeyDto) SetDescription(v string) {
	o.Description = v
}

// GetCreationTime returns the CreationTime field value
func (o *KeyDto) GetCreationTime() time.Time {
	if o == nil {
		var ret time.Time
		return ret
	}

	return o.CreationTime
}

// GetCreationTimeOk returns a tuple with the CreationTime field value
// and a boolean to check if the value has been set.
func (o *KeyDto) GetCreationTimeOk() (*time.Time, bool) {
	if o == nil {
		return nil, false
	}
	return &o.CreationTime, true
}

// SetCreationTime sets field value
func (o *KeyDto) SetCreationTime(v time.Time) {
	o.CreationTime = v
}

// GetTokenProfileUuid returns the TokenProfileUuid field value if set, zero value otherwise.
func (o *KeyDto) GetTokenProfileUuid() string {
	if o == nil || IsNil(o.TokenProfileUuid) {
		var ret string
		return ret
	}
	return *o.TokenProfileUuid
}

// GetTokenProfileUuidOk returns a tuple with the TokenProfileUuid field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KeyDto) GetTokenProfileUuidOk() (*string, bool) {
	if o == nil || IsNil(o.TokenProfileUuid) {
		return nil, false
	}
	return o.TokenProfileUuid, true
}

// HasTokenProfileUuid returns a boolean if a field has been set.
func (o *KeyDto) HasTokenProfileUuid() bool {
	if o != nil && !IsNil(o.TokenProfileUuid) {
		return true
	}

	return false
}

// SetTokenProfileUuid gets a reference to the given string and assigns it to the TokenProfileUuid field.
func (o *KeyDto) SetTokenProfileUuid(v string) {
	o.TokenProfileUuid = &v
}

// GetTokenProfileName returns the TokenProfileName field value if set, zero value otherwise.
func (o *KeyDto) GetTokenProfileName() string {
	if o == nil || IsNil(o.TokenProfileName) {
		var ret string
		return ret
	}
	return *o.TokenProfileName
}

// GetTokenProfileNameOk returns a tuple with the TokenProfileName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KeyDto) GetTokenProfileNameOk() (*string, bool) {
	if o == nil || IsNil(o.TokenProfileName) {
		return nil, false
	}
	return o.TokenProfileName, true
}

// HasTokenProfileName returns a boolean if a field has been set.
func (o *KeyDto) HasTokenProfileName() bool {
	if o != nil && !IsNil(o.TokenProfileName) {
		return true
	}

	return false
}

// SetTokenProfileName gets a reference to the given string and assigns it to the TokenProfileName field.
func (o *KeyDto) SetTokenProfileName(v string) {
	o.TokenProfileName = &v
}

// GetTokenInstanceUuid returns the TokenInstanceUuid field value
func (o *KeyDto) GetTokenInstanceUuid() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.TokenInstanceUuid
}

// GetTokenInstanceUuidOk returns a tuple with the TokenInstanceUuid field value
// and a boolean to check if the value has been set.
func (o *KeyDto) GetTokenInstanceUuidOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.TokenInstanceUuid, true
}

// SetTokenInstanceUuid sets field value
func (o *KeyDto) SetTokenInstanceUuid(v string) {
	o.TokenInstanceUuid = v
}

// GetTokenInstanceName returns the TokenInstanceName field value
func (o *KeyDto) GetTokenInstanceName() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.TokenInstanceName
}

// GetTokenInstanceNameOk returns a tuple with the TokenInstanceName field value
// and a boolean to check if the value has been set.
func (o *KeyDto) GetTokenInstanceNameOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.TokenInstanceName, true
}

// SetTokenInstanceName sets field value
func (o *KeyDto) SetTokenInstanceName(v string) {
	o.TokenInstanceName = v
}

// GetOwner returns the Owner field value if set, zero value otherwise.
func (o *KeyDto) GetOwner() string {
	if o == nil || IsNil(o.Owner) {
		var ret string
		return ret
	}
	return *o.Owner
}

// GetOwnerOk returns a tuple with the Owner field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KeyDto) GetOwnerOk() (*string, bool) {
	if o == nil || IsNil(o.Owner) {
		return nil, false
	}
	return o.Owner, true
}

// HasOwner returns a boolean if a field has been set.
func (o *KeyDto) HasOwner() bool {
	if o != nil && !IsNil(o.Owner) {
		return true
	}

	return false
}

// SetOwner gets a reference to the given string and assigns it to the Owner field.
func (o *KeyDto) SetOwner(v string) {
	o.Owner = &v
}

// GetOwnerUuid returns the OwnerUuid field value if set, zero value otherwise.
func (o *KeyDto) GetOwnerUuid() string {
	if o == nil || IsNil(o.OwnerUuid) {
		var ret string
		return ret
	}
	return *o.OwnerUuid
}

// GetOwnerUuidOk returns a tuple with the OwnerUuid field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KeyDto) GetOwnerUuidOk() (*string, bool) {
	if o == nil || IsNil(o.OwnerUuid) {
		return nil, false
	}
	return o.OwnerUuid, true
}

// HasOwnerUuid returns a boolean if a field has been set.
func (o *KeyDto) HasOwnerUuid() bool {
	if o != nil && !IsNil(o.OwnerUuid) {
		return true
	}

	return false
}

// SetOwnerUuid gets a reference to the given string and assigns it to the OwnerUuid field.
func (o *KeyDto) SetOwnerUuid(v string) {
	o.OwnerUuid = &v
}

// GetGroups returns the Groups field value if set, zero value otherwise.
func (o *KeyDto) GetGroups() []GroupDto {
	if o == nil || IsNil(o.Groups) {
		var ret []GroupDto
		return ret
	}
	return o.Groups
}

// GetGroupsOk returns a tuple with the Groups field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KeyDto) GetGroupsOk() ([]GroupDto, bool) {
	if o == nil || IsNil(o.Groups) {
		return nil, false
	}
	return o.Groups, true
}

// HasGroups returns a boolean if a field has been set.
func (o *KeyDto) HasGroups() bool {
	if o != nil && !IsNil(o.Groups) {
		return true
	}

	return false
}

// SetGroups gets a reference to the given []GroupDto and assigns it to the Groups field.
func (o *KeyDto) SetGroups(v []GroupDto) {
	o.Groups = v
}

// GetItems returns the Items field value
func (o *KeyDto) GetItems() []KeyItemDto {
	if o == nil {
		var ret []KeyItemDto
		return ret
	}

	return o.Items
}

// GetItemsOk returns a tuple with the Items field value
// and a boolean to check if the value has been set.
func (o *KeyDto) GetItemsOk() ([]KeyItemDto, bool) {
	if o == nil {
		return nil, false
	}
	return o.Items, true
}

// SetItems sets field value
func (o *KeyDto) SetItems(v []KeyItemDto) {
	o.Items = v
}

// GetAssociations returns the Associations field value if set, zero value otherwise.
func (o *KeyDto) GetAssociations() int32 {
	if o == nil || IsNil(o.Associations) {
		var ret int32
		return ret
	}
	return *o.Associations
}

// GetAssociationsOk returns a tuple with the Associations field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KeyDto) GetAssociationsOk() (*int32, bool) {
	if o == nil || IsNil(o.Associations) {
		return nil, false
	}
	return o.Associations, true
}

// HasAssociations returns a boolean if a field has been set.
func (o *KeyDto) HasAssociations() bool {
	if o != nil && !IsNil(o.Associations) {
		return true
	}

	return false
}

// SetAssociations gets a reference to the given int32 and assigns it to the Associations field.
func (o *KeyDto) SetAssociations(v int32) {
	o.Associations = &v
}

func (o KeyDto) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o KeyDto) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["uuid"] = o.Uuid
	toSerialize["name"] = o.Name
	toSerialize["description"] = o.Description
	toSerialize["creationTime"] = o.CreationTime
	if !IsNil(o.TokenProfileUuid) {
		toSerialize["tokenProfileUuid"] = o.TokenProfileUuid
	}
	if !IsNil(o.TokenProfileName) {
		toSerialize["tokenProfileName"] = o.TokenProfileName
	}
	toSerialize["tokenInstanceUuid"] = o.TokenInstanceUuid
	toSerialize["tokenInstanceName"] = o.TokenInstanceName
	if !IsNil(o.Owner) {
		toSerialize["owner"] = o.Owner
	}
	if !IsNil(o.OwnerUuid) {
		toSerialize["ownerUuid"] = o.OwnerUuid
	}
	if !IsNil(o.Groups) {
		toSerialize["groups"] = o.Groups
	}
	toSerialize["items"] = o.Items
	if !IsNil(o.Associations) {
		toSerialize["associations"] = o.Associations
	}

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return toSerialize, nil
}

func (o *KeyDto) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"uuid",
		"name",
		"description",
		"creationTime",
		"tokenInstanceUuid",
		"tokenInstanceName",
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

	varKeyDto := _KeyDto{}

	err = json.Unmarshal(data, &varKeyDto)

	if err != nil {
		return err
	}

	*o = KeyDto(varKeyDto)

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(data, &additionalProperties); err == nil {
		delete(additionalProperties, "uuid")
		delete(additionalProperties, "name")
		delete(additionalProperties, "description")
		delete(additionalProperties, "creationTime")
		delete(additionalProperties, "tokenProfileUuid")
		delete(additionalProperties, "tokenProfileName")
		delete(additionalProperties, "tokenInstanceUuid")
		delete(additionalProperties, "tokenInstanceName")
		delete(additionalProperties, "owner")
		delete(additionalProperties, "ownerUuid")
		delete(additionalProperties, "groups")
		delete(additionalProperties, "items")
		delete(additionalProperties, "associations")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableKeyDto struct {
	value *KeyDto
	isSet bool
}

func (v NullableKeyDto) Get() *KeyDto {
	return v.value
}

func (v *NullableKeyDto) Set(val *KeyDto) {
	v.value = val
	v.isSet = true
}

func (v NullableKeyDto) IsSet() bool {
	return v.isSet
}

func (v *NullableKeyDto) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableKeyDto(val *KeyDto) *NullableKeyDto {
	return &NullableKeyDto{value: val, isSet: true}
}

func (v NullableKeyDto) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableKeyDto) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


