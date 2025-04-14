package signer

import "time"

const (
	czertainlyAnnotationPrefix = "czertainly-issuer.czertainly.com/"
	certificateUuidAnnotation  = czertainlyAnnotationPrefix + "certificate-uuid"

	waitForNextRequeueTime = 10 * time.Second
)
