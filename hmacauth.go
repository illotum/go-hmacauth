package hmacauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"sort"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

const (
	// common parameters
	authorizationHeader = "Authorization"
	apiKeyParam         = "APIKey"
	signatureParam      = "Signature"
	timestampParam      = "Timestamp"

	// timestamp validation
	maxNegativeTimeOffset time.Duration = -5 * time.Minute

	// parsing bits
	empty   = ""
	comma   = ","
	space   = " "
	eqSign  = "="
	newline = "\n"
)

type (
	KeyLocator func(string) string
)

type Options struct {
	SignedHeaders      []string
	SecretKey          KeyLocator
	SignatureExpiresIn time.Duration
	HashLib            func() hash.Hash
}

type authBits struct {
	APIKey          string
	Signature       string
	TimestampString string
	Timestamp       time.Time
}

func (ab *authBits) IsValid() bool {
	return ab.APIKey != empty &&
		ab.Signature != empty &&
		!ab.Timestamp.IsZero()
}

func (ab *authBits) SetTimestamp(isoTime string) (err error) {
	ab.Timestamp, err = time.Parse(time.RFC3339, isoTime)
	if err == nil {
		ab.TimestampString = isoTime
	}
	return
}

func AuthenticateFHTTP(options *Options, ctx *fasthttp.RequestCtx) error {
	var err error
	var ab *authBits

	if ab, err = parseAuthHeader(string(ctx.Request.Header.Peek(authorizationHeader))); err == nil {
		if err = validateTimestamp(ab.Timestamp, options); err == nil {
			var sts string

			if sts, err = stringToSignFHTTP(ctx, options, ab.TimestampString); err == nil {
				if sk := options.SecretKey(ab.APIKey); sk != empty {
					if ab.Signature != signString(sts, sk, options) {
						err = HMACAuthError{invalidSignature}
					}
				} else {
					err = HMACAuthError{invalidAPIKey}
				}
			}
		}
	}

	return err
}

func signString(str string, secret string, options *Options) string {
	var hashlib hash.Hash

	if options.HashLib == nil {
		hashlib = hmac.New(sha256.New, []byte(secret))
	} else {
		hashlib = hmac.New(options.HashLib, []byte(secret))
	}

	hashlib.Write([]byte(str))
	return base64.StdEncoding.EncodeToString(hashlib.Sum(nil))
}

func stringToSignFHTTP(ctx *fasthttp.RequestCtx, options *Options, timestamp string) (string, error) {
	var buffer bytes.Buffer

	// Standard
	buffer.Write(ctx.Request.Header.Method())
	buffer.WriteString(newline)
	buffer.Write(ctx.Request.Header.Host())
	buffer.WriteString(newline)
	buffer.Write(ctx.Request.URI().RequestURI())
	buffer.WriteString(newline)
	buffer.WriteString(timestamp)
	buffer.WriteString(newline)

	// Headers
	sort.Strings(options.SignedHeaders)
	for _, header := range options.SignedHeaders {
		val := ctx.Request.Header.Peek(header)
		if len(val) == 0 {
			return empty, HeaderMissingError{header}
		}
		buffer.Write(val)
		buffer.WriteString(newline)
	}

	return buffer.String(), nil
}

func parseAuthHeader(header string) (*authBits, error) {
	if header == empty {
		return nil, HeaderMissingError{authorizationHeader}
	}

	ab := new(authBits)
	parts := strings.Split(header, comma)
	for _, part := range parts {
		kv := strings.SplitN(strings.Trim(part, space), eqSign, 2)
		if kv[0] == apiKeyParam {
			if ab.APIKey != empty {
				return nil, RepeatedParameterError{kv[0]}
			}
			ab.APIKey = kv[1]
		} else if kv[0] == signatureParam {
			if ab.Signature != empty {
				return nil, RepeatedParameterError{kv[0]}
			}
			ab.Signature = kv[1]
		} else if kv[0] == timestampParam {
			if !ab.Timestamp.IsZero() {
				return nil, RepeatedParameterError{kv[0]}
			}
			if ab.SetTimestamp(kv[1]) != nil {
				return nil, HMACAuthError{invalidTimestamp}
			}
		} else {
			return nil, HMACAuthError{invalidParameter}
		}
	}

	if !ab.IsValid() {
		return nil, HMACAuthError{missingParameter}
	}

	return ab, nil
}

func validateTimestamp(ts time.Time, options *Options) error {
	reqAge := time.Since(ts)

	// Allow for about `maxNegativeTimeOffset` of difference, some servers are
	// ahead and some are behind
	if reqAge < maxNegativeTimeOffset {
		return HMACAuthError{tsOutOfRange}
	}

	if options.SignatureExpiresIn != 0 {
		if reqAge > options.SignatureExpiresIn {
			return HMACAuthError{signatureExpired}
		}
	}

	return nil
}
