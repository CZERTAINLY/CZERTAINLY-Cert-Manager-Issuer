package signer

import "time"

const (
	czertainlyAnnotationPrefix = "czertainly-issuer.czertainly.com/"
	certificateUuidAnnotation  = czertainlyAnnotationPrefix + "certificate-uuid"

	waitForNextRequeueTime = 10 * time.Second

	// HTTP Transport defaults
	defaultDialTimeout           = 5 * time.Second
	defaultDialKeepAlive         = 30 * time.Second
	defaultTLSHandshakeTimeout   = 5 * time.Second
	defaultResponseHeaderTimeout = 20 * time.Second
	defaultExpectContinueTimeout = 1 * time.Second
	defaultIdleConnTimeout       = 90 * time.Second
	defaultMaxIdleConns          = 200
	defaultMaxIdleConnsPerHost   = 20
	defaultClientTimeout         = 30 * time.Second
)
