package util

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	czertainlyissuerapi "github.com/CZERTAINLY/CZERTAINLY-Cert-Manager-Issuer/api/v1alpha1"
)

func GetSpecAndStatus(issuer client.Object) (*czertainlyissuerapi.IssuerSpec, *czertainlyissuerapi.IssuerStatus, error) {
	switch t := issuer.(type) {
	case *czertainlyissuerapi.Issuer:
		return &t.Spec, &t.Status, nil
	case *czertainlyissuerapi.ClusterIssuer:
		return &t.Spec, &t.Status, nil
	default:
		return nil, nil, fmt.Errorf("not an issuer type: %t", t)
	}
}

func SetReadyCondition(status *czertainlyissuerapi.IssuerStatus, conditionStatus czertainlyissuerapi.ConditionStatus, reason, message string) {
	ready := GetReadyCondition(status)
	if ready == nil {
		ready = &czertainlyissuerapi.IssuerCondition{
			Type: czertainlyissuerapi.IssuerConditionReady,
		}
		status.Conditions = append(status.Conditions, *ready)
	}
	if ready.Status != conditionStatus {
		ready.Status = conditionStatus
		now := metav1.Now()
		ready.LastTransitionTime = &now
	}
	ready.Reason = reason
	ready.Message = message

	for i, c := range status.Conditions {
		if c.Type == czertainlyissuerapi.IssuerConditionReady {
			status.Conditions[i] = *ready
			return
		}
	}
}

func GetReadyCondition(status *czertainlyissuerapi.IssuerStatus) *czertainlyissuerapi.IssuerCondition {
	for _, c := range status.Conditions {
		if c.Type == czertainlyissuerapi.IssuerConditionReady {
			return &c
		}
	}
	return nil
}

func IsReady(status *czertainlyissuerapi.IssuerStatus) bool {
	if c := GetReadyCondition(status); c != nil {
		return c.Status == czertainlyissuerapi.ConditionTrue
	}
	return false
}
