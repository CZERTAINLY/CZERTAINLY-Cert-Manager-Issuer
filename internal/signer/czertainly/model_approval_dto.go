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
	"time"
	"fmt"
)

// checks if the ApprovalDto type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &ApprovalDto{}

// ApprovalDto struct for ApprovalDto
type ApprovalDto struct {
	// UUID of the Approval
	ApprovalUuid string `json:"approvalUuid"`
	// UUID of the user that requested approval
	CreatorUuid string `json:"creatorUuid"`
	// Username of the user that requested approval
	CreatorUsername *string `json:"creatorUsername,omitempty"`
	// Version of the Approval profile
	Version int32 `json:"version"`
	// Creation date of the Approval
	CreatedAt time.Time `json:"createdAt"`
	// Expiry date of the Approval
	ExpiryAt time.Time `json:"expiryAt"`
	// Date of resolution of the Approval
	ClosedAt *time.Time `json:"closedAt,omitempty"`
	// Status of the Approval
	Status string `json:"status"`
	// Resource of the Approval
	Resource Resource `json:"resource"`
	// Resource action of the Approval
	ResourceAction string `json:"resourceAction"`
	// UUID of the target object of the Approval
	ObjectUuid string `json:"objectUuid"`
	// Name of the Approval profile
	ApprovalProfileName string `json:"approvalProfileName"`
	// UUID of the Approval profile
	ApprovalProfileUuid string `json:"approvalProfileUuid"`
	AdditionalProperties map[string]interface{}
}

type _ApprovalDto ApprovalDto

// NewApprovalDto instantiates a new ApprovalDto object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewApprovalDto(approvalUuid string, creatorUuid string, version int32, createdAt time.Time, expiryAt time.Time, status string, resource Resource, resourceAction string, objectUuid string, approvalProfileName string, approvalProfileUuid string) *ApprovalDto {
	this := ApprovalDto{}
	this.ApprovalUuid = approvalUuid
	this.CreatorUuid = creatorUuid
	this.Version = version
	this.CreatedAt = createdAt
	this.ExpiryAt = expiryAt
	this.Status = status
	this.Resource = resource
	this.ResourceAction = resourceAction
	this.ObjectUuid = objectUuid
	this.ApprovalProfileName = approvalProfileName
	this.ApprovalProfileUuid = approvalProfileUuid
	return &this
}

// NewApprovalDtoWithDefaults instantiates a new ApprovalDto object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewApprovalDtoWithDefaults() *ApprovalDto {
	this := ApprovalDto{}
	return &this
}

// GetApprovalUuid returns the ApprovalUuid field value
func (o *ApprovalDto) GetApprovalUuid() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.ApprovalUuid
}

// GetApprovalUuidOk returns a tuple with the ApprovalUuid field value
// and a boolean to check if the value has been set.
func (o *ApprovalDto) GetApprovalUuidOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.ApprovalUuid, true
}

// SetApprovalUuid sets field value
func (o *ApprovalDto) SetApprovalUuid(v string) {
	o.ApprovalUuid = v
}

// GetCreatorUuid returns the CreatorUuid field value
func (o *ApprovalDto) GetCreatorUuid() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.CreatorUuid
}

// GetCreatorUuidOk returns a tuple with the CreatorUuid field value
// and a boolean to check if the value has been set.
func (o *ApprovalDto) GetCreatorUuidOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.CreatorUuid, true
}

// SetCreatorUuid sets field value
func (o *ApprovalDto) SetCreatorUuid(v string) {
	o.CreatorUuid = v
}

// GetCreatorUsername returns the CreatorUsername field value if set, zero value otherwise.
func (o *ApprovalDto) GetCreatorUsername() string {
	if o == nil || IsNil(o.CreatorUsername) {
		var ret string
		return ret
	}
	return *o.CreatorUsername
}

// GetCreatorUsernameOk returns a tuple with the CreatorUsername field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ApprovalDto) GetCreatorUsernameOk() (*string, bool) {
	if o == nil || IsNil(o.CreatorUsername) {
		return nil, false
	}
	return o.CreatorUsername, true
}

// HasCreatorUsername returns a boolean if a field has been set.
func (o *ApprovalDto) HasCreatorUsername() bool {
	if o != nil && !IsNil(o.CreatorUsername) {
		return true
	}

	return false
}

// SetCreatorUsername gets a reference to the given string and assigns it to the CreatorUsername field.
func (o *ApprovalDto) SetCreatorUsername(v string) {
	o.CreatorUsername = &v
}

// GetVersion returns the Version field value
func (o *ApprovalDto) GetVersion() int32 {
	if o == nil {
		var ret int32
		return ret
	}

	return o.Version
}

// GetVersionOk returns a tuple with the Version field value
// and a boolean to check if the value has been set.
func (o *ApprovalDto) GetVersionOk() (*int32, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Version, true
}

// SetVersion sets field value
func (o *ApprovalDto) SetVersion(v int32) {
	o.Version = v
}

// GetCreatedAt returns the CreatedAt field value
func (o *ApprovalDto) GetCreatedAt() time.Time {
	if o == nil {
		var ret time.Time
		return ret
	}

	return o.CreatedAt
}

// GetCreatedAtOk returns a tuple with the CreatedAt field value
// and a boolean to check if the value has been set.
func (o *ApprovalDto) GetCreatedAtOk() (*time.Time, bool) {
	if o == nil {
		return nil, false
	}
	return &o.CreatedAt, true
}

// SetCreatedAt sets field value
func (o *ApprovalDto) SetCreatedAt(v time.Time) {
	o.CreatedAt = v
}

// GetExpiryAt returns the ExpiryAt field value
func (o *ApprovalDto) GetExpiryAt() time.Time {
	if o == nil {
		var ret time.Time
		return ret
	}

	return o.ExpiryAt
}

// GetExpiryAtOk returns a tuple with the ExpiryAt field value
// and a boolean to check if the value has been set.
func (o *ApprovalDto) GetExpiryAtOk() (*time.Time, bool) {
	if o == nil {
		return nil, false
	}
	return &o.ExpiryAt, true
}

// SetExpiryAt sets field value
func (o *ApprovalDto) SetExpiryAt(v time.Time) {
	o.ExpiryAt = v
}

// GetClosedAt returns the ClosedAt field value if set, zero value otherwise.
func (o *ApprovalDto) GetClosedAt() time.Time {
	if o == nil || IsNil(o.ClosedAt) {
		var ret time.Time
		return ret
	}
	return *o.ClosedAt
}

// GetClosedAtOk returns a tuple with the ClosedAt field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ApprovalDto) GetClosedAtOk() (*time.Time, bool) {
	if o == nil || IsNil(o.ClosedAt) {
		return nil, false
	}
	return o.ClosedAt, true
}

// HasClosedAt returns a boolean if a field has been set.
func (o *ApprovalDto) HasClosedAt() bool {
	if o != nil && !IsNil(o.ClosedAt) {
		return true
	}

	return false
}

// SetClosedAt gets a reference to the given time.Time and assigns it to the ClosedAt field.
func (o *ApprovalDto) SetClosedAt(v time.Time) {
	o.ClosedAt = &v
}

// GetStatus returns the Status field value
func (o *ApprovalDto) GetStatus() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Status
}

// GetStatusOk returns a tuple with the Status field value
// and a boolean to check if the value has been set.
func (o *ApprovalDto) GetStatusOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Status, true
}

// SetStatus sets field value
func (o *ApprovalDto) SetStatus(v string) {
	o.Status = v
}

// GetResource returns the Resource field value
func (o *ApprovalDto) GetResource() Resource {
	if o == nil {
		var ret Resource
		return ret
	}

	return o.Resource
}

// GetResourceOk returns a tuple with the Resource field value
// and a boolean to check if the value has been set.
func (o *ApprovalDto) GetResourceOk() (*Resource, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Resource, true
}

// SetResource sets field value
func (o *ApprovalDto) SetResource(v Resource) {
	o.Resource = v
}

// GetResourceAction returns the ResourceAction field value
func (o *ApprovalDto) GetResourceAction() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.ResourceAction
}

// GetResourceActionOk returns a tuple with the ResourceAction field value
// and a boolean to check if the value has been set.
func (o *ApprovalDto) GetResourceActionOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.ResourceAction, true
}

// SetResourceAction sets field value
func (o *ApprovalDto) SetResourceAction(v string) {
	o.ResourceAction = v
}

// GetObjectUuid returns the ObjectUuid field value
func (o *ApprovalDto) GetObjectUuid() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.ObjectUuid
}

// GetObjectUuidOk returns a tuple with the ObjectUuid field value
// and a boolean to check if the value has been set.
func (o *ApprovalDto) GetObjectUuidOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.ObjectUuid, true
}

// SetObjectUuid sets field value
func (o *ApprovalDto) SetObjectUuid(v string) {
	o.ObjectUuid = v
}

// GetApprovalProfileName returns the ApprovalProfileName field value
func (o *ApprovalDto) GetApprovalProfileName() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.ApprovalProfileName
}

// GetApprovalProfileNameOk returns a tuple with the ApprovalProfileName field value
// and a boolean to check if the value has been set.
func (o *ApprovalDto) GetApprovalProfileNameOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.ApprovalProfileName, true
}

// SetApprovalProfileName sets field value
func (o *ApprovalDto) SetApprovalProfileName(v string) {
	o.ApprovalProfileName = v
}

// GetApprovalProfileUuid returns the ApprovalProfileUuid field value
func (o *ApprovalDto) GetApprovalProfileUuid() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.ApprovalProfileUuid
}

// GetApprovalProfileUuidOk returns a tuple with the ApprovalProfileUuid field value
// and a boolean to check if the value has been set.
func (o *ApprovalDto) GetApprovalProfileUuidOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.ApprovalProfileUuid, true
}

// SetApprovalProfileUuid sets field value
func (o *ApprovalDto) SetApprovalProfileUuid(v string) {
	o.ApprovalProfileUuid = v
}

func (o ApprovalDto) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o ApprovalDto) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["approvalUuid"] = o.ApprovalUuid
	toSerialize["creatorUuid"] = o.CreatorUuid
	if !IsNil(o.CreatorUsername) {
		toSerialize["creatorUsername"] = o.CreatorUsername
	}
	toSerialize["version"] = o.Version
	toSerialize["createdAt"] = o.CreatedAt
	toSerialize["expiryAt"] = o.ExpiryAt
	if !IsNil(o.ClosedAt) {
		toSerialize["closedAt"] = o.ClosedAt
	}
	toSerialize["status"] = o.Status
	toSerialize["resource"] = o.Resource
	toSerialize["resourceAction"] = o.ResourceAction
	toSerialize["objectUuid"] = o.ObjectUuid
	toSerialize["approvalProfileName"] = o.ApprovalProfileName
	toSerialize["approvalProfileUuid"] = o.ApprovalProfileUuid

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return toSerialize, nil
}

func (o *ApprovalDto) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"approvalUuid",
		"creatorUuid",
		"version",
		"createdAt",
		"expiryAt",
		"status",
		"resource",
		"resourceAction",
		"objectUuid",
		"approvalProfileName",
		"approvalProfileUuid",
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

	varApprovalDto := _ApprovalDto{}

	err = json.Unmarshal(data, &varApprovalDto)

	if err != nil {
		return err
	}

	*o = ApprovalDto(varApprovalDto)

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(data, &additionalProperties); err == nil {
		delete(additionalProperties, "approvalUuid")
		delete(additionalProperties, "creatorUuid")
		delete(additionalProperties, "creatorUsername")
		delete(additionalProperties, "version")
		delete(additionalProperties, "createdAt")
		delete(additionalProperties, "expiryAt")
		delete(additionalProperties, "closedAt")
		delete(additionalProperties, "status")
		delete(additionalProperties, "resource")
		delete(additionalProperties, "resourceAction")
		delete(additionalProperties, "objectUuid")
		delete(additionalProperties, "approvalProfileName")
		delete(additionalProperties, "approvalProfileUuid")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableApprovalDto struct {
	value *ApprovalDto
	isSet bool
}

func (v NullableApprovalDto) Get() *ApprovalDto {
	return v.value
}

func (v *NullableApprovalDto) Set(val *ApprovalDto) {
	v.value = val
	v.isSet = true
}

func (v NullableApprovalDto) IsSet() bool {
	return v.isSet
}

func (v *NullableApprovalDto) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableApprovalDto(val *ApprovalDto) *NullableApprovalDto {
	return &NullableApprovalDto{value: val, isSet: true}
}

func (v NullableApprovalDto) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableApprovalDto) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


