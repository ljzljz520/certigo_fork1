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

package lib

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/square/certigo/pkcs7"
)

type testCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
	pem  []byte
}

var certSerialCounter int64

func generateCert(t *testing.T, cn string, parent *testCert, exts ...pkix.Extension) *testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	certSerialCounter++
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(certSerialCounter),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  parent == nil,
		ExtraExtensions:       exts,
	}

	issuer := tmpl
	var issuerKey crypto.Signer = key
	if parent != nil {
		issuer = parent.cert
		issuerKey = parent.key
	}
	raw, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, key.Public(), issuerKey)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(raw)
	require.NoError(t, err)

	return &testCert{
		cert: parsed,
		key:  key,
		der:  raw,
		pem:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}),
	}
}

// buildPKCS7 builds a DER SignedData envelope containing the given
// certificates, and cross-checks that strict parsing accepts it.
func buildPKCS7(t *testing.T, rawCerts ...[]byte) []byte {
	t.Helper()

	dataOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	contentInfoDER, err := asn1.Marshal(struct {
		OID asn1.ObjectIdentifier
	}{dataOID})
	require.NoError(t, err)
	var contentInfo asn1.RawValue
	_, err = asn1.Unmarshal(contentInfoDER, &contentInfo)
	require.NoError(t, err)

	certs := make([]asn1.RawValue, len(rawCerts))
	for i, raw := range rawCerts {
		_, err = asn1.Unmarshal(raw, &certs[i])
		require.NoError(t, err)
	}

	env := pkcs7.SignedDataEnvelope{
		Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2},
		SignedData: pkcs7.SignedData{
			Version:          1,
			DigestAlgorithms: []asn1.RawValue{},
			ContentInfo:      contentInfo,
			Certificates:     certs,
			SignerInfos:      []asn1.RawValue{},
		},
	}
	der, err := asn1.Marshal(env)
	require.NoError(t, err)

	envelopes, err := pkcs7.ParseSignedDataStrict(der)
	require.NoError(t, err, "home-built PKCS#7 envelope must parse strictly")
	require.Len(t, envelopes, 1)
	extracted, err := pkcs7.ExtractCertificates(der)
	require.NoError(t, err)
	require.Len(t, extracted, len(rawCerts))
	return der
}

func noPassword(string) string { return "" }

type collectedCert struct {
	cert *x509.Certificate
	src  Source
	err  error
}

func collectX509(t *testing.T, inputs []Input) ([]collectedCert, *ParseResult, error) {
	t.Helper()
	var got []collectedCert
	pr, err := ReadX509Inputs(inputs, "", noPassword, func(cert *x509.Certificate, src Source, parseErr error) error {
		got = append(got, collectedCert{cert: cert, src: src, err: parseErr})
		return nil
	})
	require.NotNil(t, pr)
	return got, pr, err
}

func pemInput(name string, blocks ...[]byte) Input {
	return Input{Name: name, Reader: strings.NewReader(strings.Join(byteSlicesToStrings(blocks), ""))}
}

func byteSlicesToStrings(blocks [][]byte) []string {
	out := make([]string, len(blocks))
	for i, b := range blocks {
		out[i] = string(b)
	}
	return out
}

func TestReadMultiCertificatePEM(t *testing.T) {
	c1 := generateCert(t, "leaf-1", nil)
	c2 := generateCert(t, "leaf-2", nil)
	c3 := generateCert(t, "leaf-3", nil)

	got, pr, err := collectX509(t, []Input{pemInput("chain.pem", c1.pem, c2.pem, c3.pem)})
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.True(t, pr.Complete())
	require.NoError(t, pr.Error())
	require.Len(t, pr.Inputs, 1)

	in := pr.Inputs[0]
	assert.Equal(t, "chain.pem", in.Name)
	assert.Equal(t, "PEM", in.Format)
	assert.Equal(t, StatusComplete, in.Status)
	require.Len(t, in.Certificates, 3)

	for i, c := range got {
		require.NotNil(t, c.cert)
		assert.Equal(t, "PEM", c.src.Format)
		assert.Equal(t, i+1, c.src.Block)
		assert.Equal(t, i+1, in.Certificates[i].Block)
		assert.Equal(t, in.Certificates[i].Offset, c.src.Offset)
	}
	// Offsets locate the BEGIN marker of every block.
	raw := string(c1.pem) + string(c2.pem) + string(c3.pem)
	assert.Equal(t, int64(0), got[0].src.Offset)
	assert.Equal(t, int64(len(c1.pem)), got[1].src.Offset)
	assert.Equal(t, int64(len(c1.pem)+len(c2.pem)), got[2].src.Offset)
	assert.Equal(t, "-----BEGIN CERTIFICATE-----", raw[got[2].src.Offset:got[2].src.Offset+27])
}

func TestPKCS7ExpandsEveryCertificateDER(t *testing.T) {
	c1 := generateCert(t, "p7-leaf", nil)
	c2 := generateCert(t, "p7-root", nil)
	p7 := buildPKCS7(t, c1.der, c2.der)

	got, pr, err := collectX509(t, []Input{{Name: "bundle.der", Reader: bytes.NewReader(p7)}})
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.True(t, pr.Complete())
	require.Len(t, pr.Inputs[0].Certificates, 2)

	assert.Equal(t, CertPosition{Block: 1, Envelope: 1, Index: 1}, pr.Inputs[0].Certificates[0])
	assert.Equal(t, CertPosition{Block: 1, Envelope: 1, Index: 2}, pr.Inputs[0].Certificates[1])
	for i, c := range got {
		assert.Equal(t, "DER", c.src.Format)
		assert.Equal(t, 1, c.src.Block)
		assert.Equal(t, 1, c.src.Envelope)
		assert.Equal(t, i+1, c.src.Index)
	}
	assert.Equal(t, c1.cert.SerialNumber, got[0].cert.SerialNumber)
	assert.Equal(t, c2.cert.SerialNumber, got[1].cert.SerialNumber)
}

func TestPKCS7ExpandsEveryCertificatePEM(t *testing.T) {
	c1 := generateCert(t, "p7-leaf", nil)
	c2 := generateCert(t, "p7-mid", nil)
	p7 := buildPKCS7(t, c1.der, c2.der)
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: p7})

	got, pr, err := collectX509(t, []Input{{Name: "bundle.p7b", Reader: strings.NewReader(string(pemBlock))}})
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.True(t, pr.Complete())
	assert.Equal(t, "PEM", pr.Inputs[0].Format)
	assert.Equal(t, CertPosition{Block: 1, Envelope: 1, Index: 1}, pr.Inputs[0].Certificates[0])
	assert.Equal(t, CertPosition{Block: 1, Envelope: 1, Index: 2}, pr.Inputs[0].Certificates[1])
	for i, c := range got {
		assert.Equal(t, "PEM", c.src.Format)
		assert.Equal(t, 1, c.src.Block)
		assert.Equal(t, 1, c.src.Envelope)
		assert.Equal(t, i+1, c.src.Index)
	}
}

func TestMixedMultiFileInputs(t *testing.T) {
	c1 := generateCert(t, "a1", nil)
	c2 := generateCert(t, "a2", nil)
	c3 := generateCert(t, "b1", nil)
	c4 := generateCert(t, "b2", nil)
	p7 := buildPKCS7(t, c3.der, c4.der)

	inputs := []Input{
		{Name: "first.pem", Reader: strings.NewReader(string(c1.pem) + string(c2.pem))},
		{Name: "second.der", Reader: bytes.NewReader(p7)},
	}
	got, pr, err := collectX509(t, inputs)
	require.NoError(t, err)
	require.Len(t, got, 4)
	assert.True(t, pr.Complete())
	require.Len(t, pr.Inputs, 2)

	assert.Equal(t, "first.pem", pr.Inputs[0].Name)
	assert.Equal(t, "PEM", pr.Inputs[0].Format)
	assert.Equal(t, []CertPosition{{Block: 1}, {Block: 2, Offset: int64(len(c1.pem))}}, pr.Inputs[0].Certificates)

	assert.Equal(t, "second.der", pr.Inputs[1].Name)
	assert.Equal(t, "DER", pr.Inputs[1].Format)
	assert.Equal(t, CertPosition{Block: 1, Envelope: 1, Index: 1}, pr.Inputs[1].Certificates[0])
	assert.Equal(t, CertPosition{Block: 1, Envelope: 1, Index: 2}, pr.Inputs[1].Certificates[1])

	// Block ordinals restart per input.
	assert.Equal(t, 1, got[2].src.Block)
}

func TestTruncatedPEMBlockAfterValidCerts(t *testing.T) {
	c1 := generateCert(t, "ok-1", nil)
	c2 := generateCert(t, "ok-2", nil)
	truncated := []byte("\n-----BEGIN CERTIFICATE-----\nMIIBjTCCbroken-no-end-line\n")

	content := append(append([]byte{}, c1.pem...), c2.pem...)
	content = append(content, truncated...)
	got, pr, readErr := collectX509(t, []Input{
		{Name: "truncated.pem", Reader: bytes.NewReader(content)},
	})
	require.NoError(t, readErr)
	require.Len(t, got, 2, "valid prefix certificates remain available as a partial result")
	assert.False(t, pr.Complete())
	require.Error(t, pr.Error())
	assert.Contains(t, pr.Error().Error(), "truncated.pem")
	assert.Contains(t, pr.Error().Error(), "block 3")

	in := pr.Inputs[0]
	assert.Equal(t, StatusIncomplete, in.Status)
	require.Len(t, in.Diagnostics, 1)
	d := in.Diagnostics[0]
	assert.Equal(t, DiagMalformedBlock, d.Kind)
	assert.Equal(t, 3, d.Source.Block)
	assert.Equal(t, "truncated.pem", d.Source.Name)
	assert.True(t, d.Source.Offset >= int64(len(c1.pem)+len(c2.pem)))
}

func TestMalformedPEMBlockWithEndLineIsSkippedAndFatal(t *testing.T) {
	c1 := generateCert(t, "ok", nil)
	bad := []byte("-----BEGIN CERTIFICATE-----\nthis is not base64 !!\n-----END CERTIFICATE-----\n")

	got, pr, readErr := collectX509(t, []Input{
		{Name: "bad.pem", Reader: strings.NewReader(string(c1.pem) + string(bad))},
	})
	require.NoError(t, readErr)
	require.Len(t, got, 1)
	assert.False(t, pr.Complete())
	assert.Equal(t, StatusIncomplete, pr.Inputs[0].Status)
	require.Len(t, pr.Inputs[0].Diagnostics, 1)
	assert.Equal(t, DiagMalformedBlock, pr.Inputs[0].Diagnostics[0].Kind)
	assert.Equal(t, 2, pr.Inputs[0].Diagnostics[0].Source.Block)
}

func TestMalformedPEMBlockBeforeValidBlockIsNotProse(t *testing.T) {
	c1 := generateCert(t, "ok", nil)
	// stdlib pem.Decode silently skips this region and returns the valid
	// block that follows it; the strict reader must flag it instead.
	bad := []byte("-----BEGIN CERTIFICATE-----\nnot base64 at all\n-----END CERTIFICATE-----\n")

	got, pr, readErr := collectX509(t, []Input{
		{Name: "badfirst.pem", Reader: strings.NewReader(string(bad) + string(c1.pem))},
	})
	require.NoError(t, readErr)
	require.Len(t, got, 1, "the valid certificate after the bad block is still delivered")
	assert.Equal(t, 2, got[0].src.Block, "the valid certificate keeps block ordinal 2")
	assert.False(t, pr.Complete())
	in := pr.Inputs[0]
	assert.Equal(t, StatusIncomplete, in.Status)
	require.Len(t, in.Diagnostics, 1)
	d := in.Diagnostics[0]
	assert.Equal(t, DiagMalformedBlock, d.Kind)
	assert.Equal(t, 1, d.Source.Block)
	assert.Equal(t, int64(0), d.Source.Offset)
	// The delivered certificate's offset must point at ITS BEGIN marker,
	// not at the discarded bad block.
	assert.Equal(t, int64(len(bad)), got[0].src.Offset)
}

func TestProseOutsidePEMBlocksIsAllowed(t *testing.T) {
	c1 := generateCert(t, "ok", nil)
	content := "leading explanatory prose\n\n" + string(c1.pem) + "# trailing comment\n"
	var got []collectedCert
	pr, readErr := ReadX509Inputs([]Input{{Reader: strings.NewReader(content)}}, "PEM", noPassword,
		func(cert *x509.Certificate, src Source, parseErr error) error {
			got = append(got, collectedCert{cert: cert, src: src, err: parseErr})
			return nil
		})
	require.NoError(t, readErr)
	require.Len(t, got, 1)
	assert.True(t, pr.Complete())
	assert.Empty(t, pr.Inputs[0].Diagnostics)
}

func TestNonCertificateBlocksAreSkippedNotFatal(t *testing.T) {
	c1 := generateCert(t, "ok", nil)
	keyDER, err := x509.MarshalPKCS8PrivateKey(c1.key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	got, pr, readErr := collectX509(t, []Input{
		{Name: "mixed.pem", Reader: strings.NewReader(string(keyPEM) + string(c1.pem))},
	})
	require.NoError(t, readErr)
	require.Len(t, got, 1)
	assert.True(t, pr.Complete(), "skipped non-certificate blocks must not make the input incomplete: %v", pr.Error())
	require.Len(t, pr.Inputs[0].Diagnostics, 1)
	assert.Equal(t, DiagSkippedBlock, pr.Inputs[0].Diagnostics[0].Kind)
}

func TestCallbackTerminationIsDistinguishable(t *testing.T) {
	c1 := generateCert(t, "c1", nil)
	c2 := generateCert(t, "c2", nil)
	c3 := generateCert(t, "c3", nil)
	boom := errors.New("caller said stop")

	delivered := 0
	pr, err := ReadX509Inputs([]Input{pemInput("", c1.pem, c2.pem, c3.pem)}, "", noPassword,
		func(cert *x509.Certificate, src Source, parseErr error) error {
			delivered++
			if delivered == 2 {
				return boom
			}
			return nil
		})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCallbackTerminated))
	assert.True(t, errors.Is(err, boom))
	assert.Equal(t, 2, delivered)
	assert.False(t, pr.Complete())
	assert.Equal(t, StatusTerminated, pr.Inputs[0].Status)
	assert.True(t, pr.Inputs[0].hasKind(DiagCallbackTerminated))
}

func TestDERConcatenatedCertificates(t *testing.T) {
	c1 := generateCert(t, "der-1", nil)
	c2 := generateCert(t, "der-2", nil)
	data := append(append([]byte{}, c1.der...), c2.der...)

	got, pr, err := collectX509(t, []Input{{Name: "certs.der", Reader: bytes.NewReader(data)}})
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.True(t, pr.Complete())
	assert.Equal(t, []CertPosition{{Block: 1}, {Block: 2}}, pr.Inputs[0].Certificates)
}

func TestDERTrailingGarbageIsIncomplete(t *testing.T) {
	c1 := generateCert(t, "der-ok", nil)
	data := append(append([]byte{}, c1.der...), 0x00, 0x01, 0x02, 0x03)

	got, pr, err := collectX509(t, []Input{{Name: "tail.der", Reader: bytes.NewReader(data)}})
	require.NoError(t, err)
	// The standard library rejects the whole DER blob on trailing bytes;
	// the input must nevertheless be reported as incomplete rather than
	// silently succeeding.
	assert.Empty(t, got)
	assert.False(t, pr.Complete())
	require.Len(t, pr.Inputs[0].Diagnostics, 1)
	assert.Equal(t, DiagMalformedBlock, pr.Inputs[0].Diagnostics[0].Kind)
}

func TestDERPKCS7TrailingGarbageIsPartialResult(t *testing.T) {
	c1 := generateCert(t, "p7-1", nil)
	c2 := generateCert(t, "p7-2", nil)
	p7 := buildPKCS7(t, c1.der, c2.der)
	data := append(append([]byte{}, p7...), 0x00, 0x01, 0x02)

	got, pr, err := collectX509(t, []Input{{Name: "p7-tail.der", Reader: bytes.NewReader(data)}})
	require.NoError(t, err)
	require.Len(t, got, 2, "envelope certificates are delivered before the truncation error")
	assert.False(t, pr.Complete())
	require.Len(t, pr.Inputs[0].Diagnostics, 1)
	assert.Equal(t, DiagMalformedBlock, pr.Inputs[0].Diagnostics[0].Kind)
	assert.Equal(t, 2, pr.Inputs[0].Diagnostics[0].Source.Block)
}

func TestEmptyDERIsMalformed(t *testing.T) {
	_, pr, err := collectX509(t, []Input{{Name: "empty.der", Reader: strings.NewReader("")}})
	require.NoError(t, err)
	assert.False(t, pr.Complete())
	assert.Equal(t, DiagMalformedBlock, pr.Inputs[0].Diagnostics[0].Kind)
}

func TestLargePEMBlockBeyondScannerDefault(t *testing.T) {
	// A certificate whose DER is ~60 KiB produces a PEM block well above
	// bufio.Scanner's 64 KiB default token ceiling.
	bigExt := pkix.Extension{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7}, Value: make([]byte, 60_000)}
	c1 := generateCert(t, "big", nil, bigExt)
	require.Greater(t, len(c1.pem), 70_000)

	got, pr, err := collectX509(t, []Input{{Name: "big.pem", Reader: strings.NewReader(string(c1.pem))}})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.True(t, pr.Complete())
}

func saveLimits(t *testing.T) {
	t.Helper()
	oldBlock := maxPEMBlockBytes
	oldBlocks := maxBlocksPerInput
	oldCerts := maxContainerCerts
	oldBytes := maxContainerBytes
	t.Cleanup(func() {
		maxPEMBlockBytes = oldBlock
		maxBlocksPerInput = oldBlocks
		maxContainerCerts = oldCerts
		maxContainerBytes = oldBytes
	})
}

func TestResourceLimitTooManyPEMBlocks(t *testing.T) {
	saveLimits(t)
	maxBlocksPerInput = 2
	c1 := generateCert(t, "c1", nil)
	c2 := generateCert(t, "c2", nil)
	c3 := generateCert(t, "c3", nil)

	got, pr, err := collectX509(t, []Input{pemInput("many.pem", c1.pem, c2.pem, c3.pem)})
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.False(t, pr.Complete())
	assert.Equal(t, DiagResourceLimit, pr.Inputs[0].Diagnostics[0].Kind)
}

func TestResourceLimitTooManyContainerCerts(t *testing.T) {
	saveLimits(t)
	maxContainerCerts = 1
	c1 := generateCert(t, "p7-1", nil)
	c2 := generateCert(t, "p7-2", nil)
	p7 := buildPKCS7(t, c1.der, c2.der)

	got, pr, err := collectX509(t, []Input{{Name: "p7.der", Reader: bytes.NewReader(p7)}})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.False(t, pr.Complete())
	require.Len(t, pr.Inputs[0].Diagnostics, 1)
	assert.Equal(t, DiagResourceLimit, pr.Inputs[0].Diagnostics[0].Kind)
}

func TestResourceLimitPEMBlockTooLarge(t *testing.T) {
	saveLimits(t)
	maxPEMBlockBytes = 16 * 1024
	bigExt := pkix.Extension{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7}, Value: make([]byte, 60_000)}
	c1 := generateCert(t, "big", nil, bigExt)

	got, pr, err := collectX509(t, []Input{pemInput("big.pem", c1.pem)})
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.False(t, pr.Complete())
	require.Len(t, pr.Inputs[0].Diagnostics, 1)
	assert.Equal(t, DiagResourceLimit, pr.Inputs[0].Diagnostics[0].Kind)
}

func TestResourceLimitContainerBytes(t *testing.T) {
	saveLimits(t)
	maxContainerBytes = 8
	c1 := generateCert(t, "der", nil)

	got, pr, err := collectX509(t, []Input{{Name: "big.der", Reader: bytes.NewReader(c1.der)}})
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.False(t, pr.Complete())
	require.Len(t, pr.Inputs[0].Diagnostics, 1)
	assert.Equal(t, DiagResourceLimit, pr.Inputs[0].Diagnostics[0].Kind)
}

func TestDeprecatedReadAsX509ExpandsPKCS7(t *testing.T) {
	c1 := generateCert(t, "p7-1", nil)
	c2 := generateCert(t, "p7-2", nil)
	p7 := buildPKCS7(t, c1.der, c2.der)

	var delivered int
	err := ReadAsX509([]io.Reader{bytes.NewReader(p7)}, "DER", noPassword,
		func(cert *x509.Certificate, format string, parseErr error) error {
			assert.Equal(t, "DER", format)
			assert.NoError(t, parseErr)
			delivered++
			return nil
		})
	require.NoError(t, err)
	assert.Equal(t, 2, delivered)
}

func TestDeprecatedReadAsPEMPreservesBlocks(t *testing.T) {
	c1 := generateCert(t, "ok", nil)
	p7 := buildPKCS7(t, c1.der)
	pemPKCS7 := pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: p7})

	var types []string
	err := ReadAsPEM([]io.Reader{strings.NewReader(string(pemPKCS7))}, "PEM", noPassword,
		func(block *pem.Block, format string) error {
			assert.Equal(t, "PEM", format)
			types = append(types, block.Type)
			return nil
		})
	require.NoError(t, err)
	assert.Equal(t, []string{"PKCS7"}, types)
}
