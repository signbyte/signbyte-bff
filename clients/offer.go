package clients

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// offerCallTimeout bounds the read of what the signing service offers: it answers
// from its own configuration, so a slow answer is an unhealthy one.
const offerCallTimeout = 5 * time.Second

// scopeSignerRead is the scope the offer read requests toward the signing service.
const scopeSignerRead = "signatures:read"

// Offer reads which signing flows the signing service runs, with this service's
// OWN identity: the answer belongs to the deployment, not to a user.
type Offer struct {
	doer     ServiceDoer
	baseURL  string
	audience string
}

// NewOffer builds an offer client over the given service-identity doer.
func NewOffer(d ServiceDoer, baseURL, audience string) *Offer {
	return &Offer{doer: d, baseURL: strings.TrimRight(baseURL, "/"), audience: audience}
}

// Flows returns the names of the signing flows the signing service runs.
func (c *Offer) Flows(ctx context.Context) ([]string, error) {
	resp, err := c.doer.DoServiceWithTimeout(ctx, offerCallTimeout, c.audience, scopeSignerRead,
		http.MethodGet, c.baseURL+"/api/v1/info", http.Header{}, nil)
	if err != nil {
		return nil, fmt.Errorf("signer: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPError{Service: "signer", StatusCode: resp.StatusCode, Body: string(resp.Body)}
	}
	var out struct {
		Flows []struct {
			Name string `json:"name"`
		} `json:"flows"`
	}
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return nil, fmt.Errorf("signer: decode info: %w", err)
	}
	flows := make([]string, 0, len(out.Flows))
	for _, f := range out.Flows {
		flows = append(flows, f.Name)
	}

	return flows, nil
}

// ErrOfferStale marks an answer that is the last one known: the signing service
// could not be asked again.
var ErrOfferStale = errors.New("signer: the offered flows could not be refreshed; the last answer is used")

// FlowSource is what OfferedFlows asks; *Offer satisfies it.
type FlowSource interface {
	Flows(ctx context.Context) ([]string, error)
}

// OfferedFlows remembers the signing service's answer — and a failure to get one —
// for ttl, so a page load does not cost a call to it and an unreachable signing
// service costs one timeout per ttl, not one per page load.
type OfferedFlows struct {
	src FlowSource
	ttl time.Duration
	now func() time.Time

	mu    sync.Mutex
	asked bool
	at    time.Time
	flows []string // the last answer; nil until the first one
	err   error    // why the last attempt failed; nil when it did not
}

// NewOfferedFlows remembers src's answer for ttl.
func NewOfferedFlows(src FlowSource, ttl time.Duration) *OfferedFlows {
	return &OfferedFlows{src: src, ttl: ttl, now: time.Now}
}

// Get returns the flows the signing service runs, asking it at most once per ttl.
// When the last attempt failed, the last answer is returned with an error wrapping
// ErrOfferStale; with no answer ever, it returns nil and the error.
func (o *OfferedFlows) Get(ctx context.Context) ([]string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.asked && o.now().Sub(o.at) < o.ttl {
		return o.flows, o.err
	}
	flows, err := o.src.Flows(ctx)
	o.asked, o.at = true, o.now()
	if err != nil {
		o.err = err
		if o.flows != nil {
			o.err = fmt.Errorf("%w: %w", ErrOfferStale, err)
		}

		return o.flows, o.err
	}
	o.flows, o.err = flows, nil

	return flows, nil
}
