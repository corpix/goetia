package http

import (
	"net/http"
)

const ( // go doc -all net/http | rg '^\t+Status.+=' | awk '{print $1 " = http." $1}' | sort
	StatusAccepted                      = http.StatusAccepted
	StatusAlreadyReported               = http.StatusAlreadyReported
	StatusBadGateway                    = http.StatusBadGateway
	StatusBadRequest                    = http.StatusBadRequest
	StatusConflict                      = http.StatusConflict
	StatusContinue                      = http.StatusContinue
	StatusCreated                       = http.StatusCreated
	StatusEarlyHints                    = http.StatusEarlyHints
	StatusExpectationFailed             = http.StatusExpectationFailed
	StatusFailedDependency              = http.StatusFailedDependency
	StatusForbidden                     = http.StatusForbidden
	StatusFound                         = http.StatusFound
	StatusGatewayTimeout                = http.StatusGatewayTimeout
	StatusGone                          = http.StatusGone
	StatusHTTPVersionNotSupported       = http.StatusHTTPVersionNotSupported
	StatusIMUsed                        = http.StatusIMUsed
	StatusInsufficientStorage           = http.StatusInsufficientStorage
	StatusInternalServerError           = http.StatusInternalServerError
	StatusLengthRequired                = http.StatusLengthRequired
	StatusLocked                        = http.StatusLocked
	StatusLoopDetected                  = http.StatusLoopDetected
	StatusMethodNotAllowed              = http.StatusMethodNotAllowed
	StatusMisdirectedRequest            = http.StatusMisdirectedRequest
	StatusMovedPermanently              = http.StatusMovedPermanently
	StatusMultipleChoices               = http.StatusMultipleChoices
	StatusMultiStatus                   = http.StatusMultiStatus
	StatusNetworkAuthenticationRequired = http.StatusNetworkAuthenticationRequired
	StatusNoContent                     = http.StatusNoContent
	StatusNonAuthoritativeInfo          = http.StatusNonAuthoritativeInfo
	StatusNotAcceptable                 = http.StatusNotAcceptable
	StatusNotExtended                   = http.StatusNotExtended
	StatusNotFound                      = http.StatusNotFound
	StatusNotImplemented                = http.StatusNotImplemented
	StatusNotModified                   = http.StatusNotModified
	StatusOK                            = http.StatusOK
	StatusPartialContent                = http.StatusPartialContent
	StatusPaymentRequired               = http.StatusPaymentRequired
	StatusPermanentRedirect             = http.StatusPermanentRedirect
	StatusPreconditionFailed            = http.StatusPreconditionFailed
	StatusPreconditionRequired          = http.StatusPreconditionRequired
	StatusProcessing                    = http.StatusProcessing
	StatusProxyAuthRequired             = http.StatusProxyAuthRequired
	StatusRequestedRangeNotSatisfiable  = http.StatusRequestedRangeNotSatisfiable
	StatusRequestEntityTooLarge         = http.StatusRequestEntityTooLarge
	StatusRequestHeaderFieldsTooLarge   = http.StatusRequestHeaderFieldsTooLarge
	StatusRequestTimeout                = http.StatusRequestTimeout
	StatusRequestURITooLong             = http.StatusRequestURITooLong
	StatusResetContent                  = http.StatusResetContent
	StatusSeeOther                      = http.StatusSeeOther
	StatusServiceUnavailable            = http.StatusServiceUnavailable
	StatusSwitchingProtocols            = http.StatusSwitchingProtocols
	StatusTeapot                        = http.StatusTeapot
	StatusTemporaryRedirect             = http.StatusTemporaryRedirect
	StatusTooEarly                      = http.StatusTooEarly
	StatusTooManyRequests               = http.StatusTooManyRequests
	StatusUnauthorized                  = http.StatusUnauthorized
	StatusUnavailableForLegalReasons    = http.StatusUnavailableForLegalReasons
	StatusCanceled                      = 499
	StatusUnprocessableEntity           = http.StatusUnprocessableEntity
	StatusUnsupportedMediaType          = http.StatusUnsupportedMediaType
	StatusUpgradeRequired               = http.StatusUpgradeRequired
	StatusUseProxy                      = http.StatusUseProxy
	StatusVariantAlsoNegotiates         = http.StatusVariantAlsoNegotiates
)
