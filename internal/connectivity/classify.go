package connectivity

import (
	"context"
	"errors"

	"github.com/luizosorio/nostmesh/internal/observability"
)

// classifyGatherFailure maps a discovery failure to a reason code.
//
// Most of these are ordinary rather than wrong: a node with no PCP router and no
// configured observer fails those methods every time it runs. The code is what
// lets an operator tell that apart from a node whose discovery is broken.
func classifyGatherFailure(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrObserverUnreachable):
		return observability.ReasonObserverUnreachable
	case errors.Is(err, ErrObserverResponse):
		return observability.ReasonObserverUnreachable
	case errors.Is(err, ErrUnsafeAddress):
		return observability.ReasonPolicyRefused
	case errors.Is(err, ErrTooManyCandidates):
		return observability.ReasonOversized
	case errors.Is(err, context.Canceled):
		return observability.ReasonCancelled
	case errors.Is(err, context.DeadlineExceeded):
		return observability.ReasonTimeout
	}
	return observability.ReasonNoCandidates
}

// classifyProbeFailure maps a connectivity check failure to a reason code.
func classifyProbeFailure(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrUnverified):
		return observability.ReasonProbeUnauthenticated
	case errors.Is(err, ErrUnsafeAddress):
		return observability.ReasonPolicyRefused
	case errors.Is(err, ErrTransportClosed):
		return observability.ReasonIOFailed
	case errors.Is(err, ErrDatagramTooLarge):
		return observability.ReasonOversized
	case errors.Is(err, ErrNoValidPath):
		return observability.ReasonNoPath
	case errors.Is(err, context.Canceled):
		return observability.ReasonCancelled
	case errors.Is(err, context.DeadlineExceeded):
		return observability.ReasonProbeTimeout
	}
	return observability.ReasonProbeTimeout
}
