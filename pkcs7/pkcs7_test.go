// Copyright 2025 Block, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pkcs7

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
)

var testBlock, _ = base64.StdEncoding.DecodeString(`
MIICXAYJKoZIhvcNAQcCoIICTTCCAkkCAQExADALBgkqhkiG9w0BBwGgggIvMIIC
KzCCAZQCCQDHlr/u+lfb8jANBgkqhkiG9w0BAQsFADBaMQswCQYDVQQGEwJVUzEL
MAkGA1UECBMCQ0ExEDAOBgNVBAoTB2NlcnRpZ28xEDAOBgNVBAsTB2V4YW1wbGUx
GjAYBgNVBAMTEWV4YW1wbGUtc21hbGwta2V5MB4XDTE2MDYxMDIyMTQxMloXDTIz
MDQxNTIyMTQxMlowWjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRAwDgYDVQQK
EwdjZXJ0aWdvMRAwDgYDVQQLEwdleGFtcGxlMRowGAYDVQQDExFleGFtcGxlLXNt
YWxsLWtleTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAlzyCIeP1T87k1rHV
MtbaGXIWpK/VQuvuXwig+e3ct1ajA4bw0BAInXZ37FEGGSCUix0k/CjH2NltGREt
wbahE0k5oTkVbA5XS4xkNs0M0poAFN5OiFKEAqZ014hqhvKnEUQ2oTe9SVORWw49
mLNg36AIEE2Fu2KQb/VT90cwwD0CAwEAATANBgkqhkiG9w0BAQsFAAOBgQBVsJ4V
b2L1ywLVeAxNqY0PZqS7a8Q2GLhNr5V+3hOoWn7bwqQ7L06UJGSrcLOPZeIHIWM2
0aOFHSTWbocd4f+m6s3llyXwBBlK2BPZbWv0OeAHgjN9AVav4flAZ4oD2GxAaJkG
AXmR9QzZNJLai5mv3L/B/p/NxeU3UGfaySxVv6EAMQA=`)

func TestExtract(t *testing.T) {
	certs, err := ExtractCertificates(testBlock)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 certs, but found %d", len(certs))
	}
}

func TestParseSignedDataStrictSingle(t *testing.T) {
	envelopes, err := ParseSignedDataStrict(testBlock)
	if err != nil {
		t.Fatalf("strict parse failed: %v", err)
	}
	if len(envelopes) != 1 {
		t.Fatalf("expected 1 envelope, but found %d", len(envelopes))
	}
}

func TestParseSignedDataStrictConcatenated(t *testing.T) {
	// Two valid envelopes concatenated must both be reported, with all
	// bytes consumed.
	data := bytes.Repeat(testBlock, 2)
	envelopes, err := ParseSignedDataStrict(data)
	if err != nil {
		t.Fatalf("strict parse failed: %v", err)
	}
	if len(envelopes) != 2 {
		t.Fatalf("expected 2 envelopes, but found %d", len(envelopes))
	}
}

func TestParseSignedDataStrictTrailingData(t *testing.T) {
	// A valid envelope followed by garbage must not look like success.
	data := append(append([]byte{}, testBlock...), 0x00, 0x01, 0x02)
	envelopes, err := ParseSignedDataStrict(data)
	if !errors.Is(err, ErrTruncatedSignedData) {
		t.Fatalf("expected ErrTruncatedSignedData, got %v", err)
	}
	if len(envelopes) != 1 {
		t.Fatalf("expected the valid prefix envelope to be returned, got %d", len(envelopes))
	}
}

func TestParseSignedDataStrictEmpty(t *testing.T) {
	if _, err := ParseSignedDataStrict(nil); err == nil {
		t.Fatal("expected error for empty input, got nil")
	}
	if envelopes, err := ParseSignedDataStrict([]byte{0x30, 0x00}); err == nil {
		t.Fatalf("expected error for non-signed-data envelope, got %d envelopes", len(envelopes))
	}
}

func TestParseSignedDataStrictGarbageOnly(t *testing.T) {
	// Garbage without a valid prefix is a plain parse error, not a
	// truncation of a valid envelope prefix.
	_, err := ParseSignedDataStrict([]byte{0x00, 0x01, 0x02, 0x03})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if errors.Is(err, ErrTruncatedSignedData) {
		t.Fatalf("plain garbage must not be classified as truncated signed data: %v", err)
	}
}
