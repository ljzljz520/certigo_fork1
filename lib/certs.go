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
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/square/certigo/jceks"
	"github.com/square/certigo/pkcs7"
)

const (
	// nameHeader is the PEM header field for the friendly name/alias of the key in the key store.
	nameHeader = "friendlyName"

	// fileHeader is the origin file where the key came from (as in file on disk).
	fileHeader = "originFile"

	// defaultMaxPEMBlockBytes bounds the size of a single PEM block. It is
	// deliberately larger than bufio.Scanner's 64 KiB default token limit so
	// legitimate large certificates parse, while still giving a clear error
	// instead of silently truncating pathological input.
	defaultMaxPEMBlockBytes = 1 << 20 // 1 MiB

	// defaultMaxBlocksPerInput bounds the number of PEM/keystore blocks that a
	// single input can emit.
	defaultMaxBlocksPerInput = 100_000

	// defaultMaxContainerCerts bounds how many certificates a single
	// container (notably a PKCS#7 envelope) is expanded into.
	defaultMaxContainerCerts = 100_000

	// defaultMaxContainerBytes bounds how many bytes are buffered for binary
	// container formats (DER, PKCS#12, JCEKS) that must be read in full.
	defaultMaxContainerBytes = 100 << 20 // 100 MiB
)

// Resource limits are variables (not constants) so tests can lower them.
var (
	maxPEMBlockBytes  = defaultMaxPEMBlockBytes
	maxBlocksPerInput = defaultMaxBlocksPerInput
	maxContainerCerts = defaultMaxContainerCerts
	maxContainerBytes = int64(defaultMaxContainerBytes)
)

var fileExtToFormat = map[string]string{
	".pem":   "PEM",
	".crt":   "PEM",
	".p7b":   "PEM",
	".p7c":   "PEM",
	".p12":   "PKCS12",
	".pfx":   "PKCS12",
	".jceks": "JCEKS",
	".jks":   "JCEKS", // Only partially supported
	".der":   "DER",
}

var badSignatureAlgorithms = [...]x509.SignatureAlgorithm{
	x509.MD2WithRSA,
	x509.MD5WithRSA,
	x509.SHA1WithRSA,
	x509.DSAWithSHA1,
	x509.ECDSAWithSHA1,
}

// Parse statuses reported per input.
const (
	// StatusComplete means the input was consumed to EOF and every block was
	// parsed or explicitly skipped.
	StatusComplete = "complete"
	// StatusIncomplete means parsing stopped because of malformed data, an
	// exceeded resource limit, or a read error; emitted certificates may be a
	// partial result.
	StatusIncomplete = "incomplete"
	// StatusTerminated means parsing stopped because the caller's callback
	// returned an error.
	StatusTerminated = "terminated"
)

// Diagnostic kinds. SkippedBlock is informational; all other kinds make the
// owning input incomplete.
const (
	DiagSkippedBlock       = "skipped_block"
	DiagMalformedBlock     = "malformed_block"
	DiagResourceLimit      = "resource_limit"
	DiagReadError          = "read_error"
	DiagUnknownFormat      = "unknown_format"
	DiagCallbackTerminated = "callback_terminated"
)

var (
	// ErrCallbackTerminated wraps the error returned by a caller-supplied
	// callback, so that caller-initiated termination can be distinguished from
	// malformed input with errors.Is.
	ErrCallbackTerminated = errors.New("processing terminated by callback")

	errUnclosedPEM   = errors.New("unclosed PEM block at end of input")
	errInputTooLarge = errors.New("input exceeds maximum allowed size")
	errTooManyBlocks = errors.New("input contains more blocks than allowed")
	errTooManyCerts  = errors.New("container expands to more certificates than allowed")
)

var (
	pemBeginMarker = []byte("-----BEGIN ")
	pemEndMarker   = []byte("\n-----END ")
)

// Source identifies where a certificate, block, or diagnostic came from.
type Source struct {
	// Name is the file name, or "" for stdin / an unnamed stream.
	Name string `json:"name,omitempty"`
	// Format is the container format (PEM, DER, PKCS12, JCEKS).
	Format string `json:"format"`
	// Block is the 1-based ordinal of the block within the input.
	Block int `json:"block"`
	// Envelope is the 1-based ordinal of the PKCS#7 signed-data envelope the
	// certificate was expanded from. It is 0 for ordinary CERTIFICATE blocks.
	Envelope int `json:"envelope,omitempty"`
	// Index is the 1-based position of the certificate inside its PKCS#7
	// envelope. It is 0 for certificates that were not container-expanded.
	Index int `json:"index,omitempty"`
	// Offset is the byte offset of the block start within the input stream.
	Offset int64 `json:"offset,omitempty"`
}

// Diagnostic describes a non-fatal skip or a fatal parse problem.
type Diagnostic struct {
	// Kind is one of the Diag* constants.
	Kind string `json:"kind"`
	// Message is a human-readable description.
	Message string `json:"message"`
	// BlockType is the PEM block type involved, when applicable.
	BlockType string `json:"block_type,omitempty"`
	// Source identifies the input location.
	Source Source `json:"source"`
}

// CertPosition records where a delivered certificate came from. Entries are
// appended in callback/delivery order.
type CertPosition struct {
	Block    int   `json:"block"`
	Envelope int   `json:"envelope,omitempty"`
	Index    int   `json:"index,omitempty"`
	Offset   int64 `json:"offset,omitempty"`
}

// InputParseResult is the parse outcome for one file or stream.
type InputParseResult struct {
	Name         string         `json:"name,omitempty"`
	Format       string         `json:"format"`
	Status       string         `json:"status"`
	Certificates []CertPosition `json:"certificates"`
	Diagnostics  []Diagnostic   `json:"diagnostics,omitempty"`
}

// ParseResult is the aggregate parse outcome for all inputs.
type ParseResult struct {
	Inputs []InputParseResult `json:"inputs"`
}

// Complete reports whether every input reached EOF without any fatal
// diagnostic. Only when Complete is true is it safe to make trust decisions
// about the emitted certificates.
func (r *ParseResult) Complete() bool {
	if r == nil {
		return false
	}
	for i := range r.Inputs {
		if r.Inputs[i].Status != StatusComplete {
			return false
		}
	}
	return true
}

// Error aggregates the fatal diagnostics of all incomplete inputs.
func (r *ParseResult) Error() error {
	if r == nil {
		return nil
	}
	var msgs []string
	for i := range r.Inputs {
		if msg := r.Inputs[i].failureMessage(); msg != "" {
			msgs = append(msgs, msg)
		}
	}
	if len(msgs) == 0 {
		return nil
	}
	if len(msgs) == 1 {
		return errors.New(msgs[0])
	}
	return errors.New("encountered multiple errors:\n* " + strings.Join(msgs, "\n* "))
}

// Error aggregates the fatal diagnostics of an incomplete input.
func (in *InputParseResult) Error() error {
	msg := in.failureMessage()
	if msg == "" {
		return nil
	}
	return errors.New(msg)
}

func (in *InputParseResult) failureMessage() string {
	if in.Status == StatusComplete {
		return ""
	}
	var msgs []string
	for i := range in.Diagnostics {
		d := &in.Diagnostics[i]
		if d.Kind == DiagSkippedBlock {
			continue
		}
		msgs = append(msgs, d.String())
	}
	if in.Status == StatusTerminated && !in.hasKind(DiagCallbackTerminated) {
		msgs = append(msgs, in.prefix()+": callback terminated input processing")
	}
	switch len(msgs) {
	case 0:
		return ""
	case 1:
		return msgs[0]
	default:
		return "encountered multiple errors:\n* " + strings.Join(msgs, "\n* ")
	}
}

func (in *InputParseResult) hasKind(kind string) bool {
	for i := range in.Diagnostics {
		if in.Diagnostics[i].Kind == kind {
			return true
		}
	}
	return false
}

func (in *InputParseResult) prefix() string {
	if in.Name != "" {
		return fmt.Sprintf("file %s", in.Name)
	}
	return "input stream"
}

// String renders a diagnostic with its source location.
func (d Diagnostic) String() string {
	loc := d.Source
	at := ""
	switch {
	case loc.Envelope > 0 && loc.Index > 0:
		at = fmt.Sprintf(" block %d, PKCS#7 envelope %d, certificate %d", loc.Block, loc.Envelope, loc.Index)
	case loc.Block > 0:
		at = fmt.Sprintf(" block %d", loc.Block)
	}
	where := ""
	if loc.Name != "" {
		where = fmt.Sprintf("file %s%s", loc.Name, at)
	} else if at != "" {
		where = strings.TrimSpace(at)
		where = strings.TrimPrefix(where, " ")
	}
	if loc.Offset > 0 {
		where += fmt.Sprintf(" (byte offset %d)", loc.Offset)
	}
	if where == "" {
		where = "input stream"
	}
	return fmt.Sprintf("%s: %s", where, d.Message)
}

func (in *InputParseResult) addDiagnostic(kind, blockType, message string, src Source) {
	if src.Name == "" {
		src.Name = in.Name
	}
	if src.Format == "" {
		src.Format = in.Format
	}
	in.Diagnostics = append(in.Diagnostics, Diagnostic{
		Kind:      kind,
		Message:   message,
		BlockType: blockType,
		Source:    src,
	})
	if kind != DiagSkippedBlock {
		in.Status = StatusIncomplete
	}
}

func (in *InputParseResult) malformed(src Source, blockType string, err error) {
	in.addDiagnostic(DiagMalformedBlock, blockType, strings.TrimSuffix(err.Error(), "\n"), src)
}

func (in *InputParseResult) skip(src Source, blockType, message string) {
	in.addDiagnostic(DiagSkippedBlock, blockType, message, src)
}

func (in *InputParseResult) noteCertificate(src Source) bool {
	if len(in.Certificates) >= maxContainerCerts {
		return false
	}
	in.Certificates = append(in.Certificates, CertPosition{
		Block:    src.Block,
		Envelope: src.Envelope,
		Index:    src.Index,
		Offset:   src.Offset,
	})
	return true
}

// emit invokes the callback and classifies its error: resource-limit
// sentinels leave the input incomplete as-is, any other error is caller
// termination and is wrapped with ErrCallbackTerminated.
func (in *InputParseResult) emit(callback blockFunc, block *pem.Block, src Source) error {
	err := callback(block, src)
	if err == nil {
		return nil
	}
	if errors.Is(err, errTooManyBlocks) || errors.Is(err, errTooManyCerts) {
		return err
	}
	in.addDiagnostic(DiagCallbackTerminated, block.Type, "input processing was stopped by the callback", src)
	in.Status = StatusTerminated
	return fmt.Errorf("%w: %w", ErrCallbackTerminated, err)
}

// Input is a named stream to read certificates or PEM blocks from. A nil Name
// denotes stdin / an unnamed stream.
type Input struct {
	Name   string
	Reader io.Reader
}

// X509SourceFunc receives every X.509 certificate in input order. A parse
// failure for a certificate-bearing block is delivered as a nil certificate
// and non-nil err (and is also recorded as a diagnostic); returning an error
// terminates the whole read.
type X509SourceFunc func(cert *x509.Certificate, src Source, err error) error

// PEMSourceFunc receives every decoded PEM block (including private keys) in
// input order. Returning an error terminates the whole read.
type PEMSourceFunc func(block *pem.Block, src Source) error

type blockFunc func(block *pem.Block, src Source) error

// ReadX509Inputs converts all given inputs to X.509 certificates (private keys
// and other non-certificate blocks are skipped) and passes them to the
// callback. PKCS#7 containers are fully expanded: every certificate of every
// envelope reaches the callback. The returned ParseResult is always populated,
// including when an error is returned; a non-nil error only denotes
// caller-initiated termination.
func ReadX509Inputs(inputs []Input, format string, password func(string) string, callback X509SourceFunc) (*ParseResult, error) {
	return readInputs(inputs, format, password, func(in *InputParseResult) blockFunc {
		return x509BlockCallback(callback, in)
	})
}

// ReadPEMInputs converts all given inputs to PEM blocks and passes them to the
// callback. See ReadX509Inputs for result/error semantics.
func ReadPEMInputs(inputs []Input, format string, password func(string) string, callback PEMSourceFunc) (*ParseResult, error) {
	return readInputs(inputs, format, password, func(in *InputParseResult) blockFunc {
		return func(block *pem.Block, src Source) error {
			return callback(block, src)
		}
	})
}

func readInputs(inputs []Input, format string, password func(string) string, makeCallback func(in *InputParseResult) blockFunc) (*ParseResult, error) {
	result := &ParseResult{Inputs: []InputParseResult{}}
	for _, in := range inputs {
		ir := &InputParseResult{
			Name:         in.Name,
			Certificates: []CertPosition{},
			Status:       StatusComplete,
		}
		err := readOneInput(in, format, password, makeCallback(ir), ir)
		result.Inputs = append(result.Inputs, *ir)
		if err != nil {
			return result, err
		}
	}
	return result, nil
}

// ReadAsPEMFromFiles will read PEM blocks from the given set of inputs. Input
// data may be in plain-text PEM files, DER-encoded certificates or PKCS7
// envelopes, or PKCS12/JCEKS keystores. All inputs will be converted to PEM
// blocks and passed to the callback.
//
// Deprecated: use ReadPEMInputs, which reports a structured, per-input
// completion status and block provenance.
func ReadAsPEMFromFiles(files []*os.File, format string, password func(string) string, callback func(*pem.Block, string) error) error {
	var errs []error
	for _, file := range files {
		reader := bufio.NewReaderSize(file, 4)
		guessed, err := formatForFile(reader, file.Name(), format)
		if err != nil {
			return fmt.Errorf("unable to guess file type for file %s", file.Name())
		}

		ir := &InputParseResult{Name: file.Name(), Format: guessed, Certificates: []CertPosition{}, Status: StatusComplete}
		err = readOneInput(Input{Name: file.Name(), Reader: reader}, guessed, password,
			func(block *pem.Block, _ Source) error { return callback(block, guessed) },
			ir)
		if err != nil {
			errs = append(errs, err)
		} else if e := ir.Error(); e != nil {
			errs = append(errs, e)
		}
	}
	return errorFromErrors(errs)
}

// ReadAsPEM will read PEM blocks from the given set of inputs. Input data may
// be in plain-text PEM files, DER-encoded certificates or PKCS7 envelopes, or
// PKCS12/JCEKS keystores. All inputs will be converted to PEM blocks and
// passed to the callback.
//
// Deprecated: use ReadPEMInputs, which reports a structured, per-input
// completion status and block provenance.
func ReadAsPEM(readers []io.Reader, format string, password func(string) string, callback func(*pem.Block, string) error) error {
	var errs []error
	for _, r := range readers {
		reader := bufio.NewReaderSize(r, 4)
		guessed, err := formatForFile(reader, "", format)
		if err != nil {
			return fmt.Errorf("unable to guess format for input stream")
		}

		ir := &InputParseResult{Format: guessed, Certificates: []CertPosition{}, Status: StatusComplete}
		err = readOneInput(Input{Reader: reader}, guessed, password,
			func(block *pem.Block, _ Source) error { return callback(block, guessed) }, ir)
		if err != nil {
			errs = append(errs, err)
		} else if e := ir.Error(); e != nil {
			errs = append(errs, e)
		}
	}
	return errorFromErrors(errs)
}

// ReadAsX509FromFiles will read X.509 certificates from the given set of
// inputs. Input data may be in plain-text PEM files, DER-encoded certificates
// or PKCS7 envelopes, or PKCS12/JCEKS keystores. All inputs will be converted
// to X.509 certificates (private keys are skipped) and passed to the callback.
//
// Deprecated: use ReadX509Inputs, which reports a structured, per-input
// completion status, expands every PKCS#7 certificate, and tracks provenance.
func ReadAsX509FromFiles(files []*os.File, format string, password func(string) string, callback func(*x509.Certificate, string, error) error) error {
	var errs []error
	for _, file := range files {
		reader := bufio.NewReaderSize(file, 4)
		guessed, err := formatForFile(reader, file.Name(), format)
		if err != nil {
			return fmt.Errorf("unable to guess file type for file %s, try adding --format flag", file.Name())
		}

		ir := &InputParseResult{Name: file.Name(), Format: guessed, Certificates: []CertPosition{}, Status: StatusComplete}
		err = readOneInput(Input{Name: file.Name(), Reader: reader}, guessed, password,
			x509BlockCallback(func(cert *x509.Certificate, src Source, parseErr error) error {
				return callback(cert, src.Format, parseErr)
			}, ir), ir)
		if err != nil {
			errs = append(errs, err)
		} else if e := ir.Error(); e != nil {
			errs = append(errs, e)
		}
	}
	return errorFromErrors(errs)
}

// ReadAsX509 will read X.509 certificates from the given set of inputs. Input
// data may be in plain-text PEM files, DER-encoded certificates or PKCS7
// envelopes, or PKCS12/JCEKS keystores. All inputs will be converted to X.509
// certificates (private keys are skipped) and passed to the callback.
//
// Deprecated: use ReadX509Inputs, which reports a structured, per-input
// completion status, expands every PKCS#7 certificate, and tracks provenance.
func ReadAsX509(readers []io.Reader, format string, password func(string) string, callback func(*x509.Certificate, string, error) error) error {
	var errs []error
	for _, r := range readers {
		reader := bufio.NewReaderSize(r, 4)
		guessed, err := formatForFile(reader, "", format)
		if err != nil {
			return fmt.Errorf("unable to guess format for input stream")
		}

		ir := &InputParseResult{Format: guessed, Certificates: []CertPosition{}, Status: StatusComplete}
		err = readOneInput(Input{Reader: reader}, guessed, password,
			x509BlockCallback(func(cert *x509.Certificate, src Source, parseErr error) error {
				return callback(cert, src.Format, parseErr)
			}, ir), ir)
		if err != nil {
			errs = append(errs, err)
		} else if e := ir.Error(); e != nil {
			errs = append(errs, e)
		}
	}
	return errorFromErrors(errs)
}

// x509BlockCallback expands the unified block stream into X.509 certificate
// callbacks. Every certificate inside every PKCS#7 envelope is delivered,
// with envelope/index provenance.
func x509BlockCallback(callback X509SourceFunc, in *InputParseResult) blockFunc {
	return func(block *pem.Block, src Source) error {
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				in.malformed(src, "CERTIFICATE", err)
				return callback(nil, src, err)
			}
			if !in.noteCertificate(src) {
				in.addDiagnostic(DiagResourceLimit, "CERTIFICATE",
					fmt.Sprintf("input expands to more than the allowed %d certificates", maxContainerCerts), src)
				return errTooManyCerts
			}
			return callback(cert, src, nil)
		case "PKCS7":
			envelopes, err := pkcs7.ParseSignedDataStrict(block.Bytes)
			if err != nil {
				in.malformed(src, "PKCS7", err)
				return callback(nil, src, err)
			}
			for envelopeOrdinal, envelope := range envelopes {
				p7src := src
				if src.Format == "DER" {
					// DER input is emitted as one PKCS#7 block per envelope,
					// so the block ordinal already identifies the envelope.
					p7src.Envelope = src.Block + envelopeOrdinal
				} else {
					// A PEM PKCS#7 block may bundle several envelopes.
					p7src.Envelope = envelopeOrdinal + 1
				}
				if len(envelope.SignedData.Certificates) == 0 {
					in.skip(p7src, "PKCS7", "PKCS#7 envelope contains no certificates")
					continue
				}
				for certOrdinal, raw := range envelope.SignedData.Certificates {
					certSrc := p7src
					certSrc.Index = certOrdinal + 1
					cert, parseErr := x509.ParseCertificate(raw.FullBytes)
					if parseErr != nil {
						in.malformed(certSrc, "CERTIFICATE", parseErr)
						if err := callback(nil, certSrc, parseErr); err != nil {
							return err
						}
						continue
					}
					if !in.noteCertificate(certSrc) {
						in.addDiagnostic(DiagResourceLimit, "PKCS7",
							fmt.Sprintf("container expands to more than the allowed %d certificates", maxContainerCerts), certSrc)
						return errTooManyCerts
					}
					if err := callback(cert, certSrc, nil); err != nil {
						return err
					}
				}
			}
			return nil
		case "CERTIFICATE REQUEST":
			// Preserve the historical warning emitted to standard output.
			fmt.Println(red.SprintfFunc()("warning: certificate requests are not supported"))
		}
		in.skip(src, block.Type, fmt.Sprintf("skipping non-certificate PEM block of type %q", block.Type))
		return nil
	}
}

// readOneInput takes some input and converts it to PEM blocks. Parse problems
// are recorded on ir; a non-nil return error only occurs when the callback
// terminates processing. Resource-limit aborts are recorded on ir and
// reported as incomplete, not as returned errors.
func readOneInput(in Input, format string, password func(string) string, callback blockFunc, ir *InputParseResult) error {
	headers := map[string]string{}
	if in.Name != "" && in.Name != os.Stdin.Name() {
		headers[fileHeader] = in.Name
	}

	reader := bufio.NewReaderSize(in.Reader, 4)
	guessed, err := formatForFile(reader, in.Name, format)
	if err != nil {
		ir.Format = ""
		ir.addDiagnostic(DiagUnknownFormat, "", "unable to determine input format: "+strings.TrimSuffix(err.Error(), "\n"),
			Source{Name: in.Name})
		return nil
	}
	ir.Format = guessed

	var readErr error
	switch guessed {
	case "PEM":
		readErr = readPEMBlocks(reader, ir, headers, callback)
	case "DER":
		readErr = readDERBlocks(reader, ir, headers, callback)
	case "PKCS12":
		readErr = readPKCS12Blocks(reader, ir, password, headers, callback)
	case "JCEKS":
		readErr = readJCEKSBlocks(reader, ir, password, headers, callback)
	default:
		ir.addDiagnostic(DiagUnknownFormat, "", fmt.Sprintf("unknown file type %q", guessed), Source{Name: in.Name, Format: guessed})
		return nil
	}

	// Resource limits were already recorded as diagnostics; the input is
	// incomplete rather than callback-terminated.
	if readErr != nil && !errors.Is(readErr, errTooManyBlocks) && !errors.Is(readErr, errTooManyCerts) {
		return readErr
	}
	return nil
}

// pemScanState drives the strict PEM splitter: it tracks absolute byte
// offsets and block ordinals across split invocations and records malformed
// regions so that trailing/unconsumed data can never be reported as success.
type pemScanState struct {
	in           *InputParseResult
	consumed     int64
	blockOrdinal int
	lastOffset   int64
}

func (s *pemScanState) split(data []byte, atEOF bool) (int, []byte, error) {
	block, rest := pem.Decode(data)
	if block != nil {
		size := len(data) - len(rest)
		region := data[:size]
		// pem.Decode silently discards malformed BEGIN..END regions that
		// precede the block it returns. Enumerate every line-leading BEGIN
		// marker in the consumed region: the last one starts the decoded
		// block, every earlier one is a malformed block that must not be
		// mistaken for prose.
		var markers []int
		for off := 0; ; {
			idx := bytes.Index(region[off:], pemBeginMarker)
			if idx < 0 {
				break
			}
			pos := off + idx
			if pos == 0 || region[pos-1] == '\n' {
				markers = append(markers, pos)
			}
			off = pos + len(pemBeginMarker)
		}
		realBegin := 0
		if len(markers) > 0 {
			realBegin = markers[len(markers)-1]
			for _, pos := range markers[:len(markers)-1] {
				s.blockOrdinal++
				s.in.addDiagnostic(DiagMalformedBlock, "", "malformed PEM block could not be decoded",
					Source{Name: s.in.Name, Format: "PEM", Block: s.blockOrdinal, Offset: s.consumed + int64(pos)})
			}
		}
		s.consumed += int64(size)
		s.blockOrdinal++
		s.lastOffset = s.consumed - int64(size) + int64(realBegin)
		return size, data[:size], nil
	}

	begin := bytes.Index(data, pemBeginMarker)
	if begin < 0 {
		// No block start in the buffer. Hold back a suffix that could be a
		// partial "-----BEGIN " marker; everything else is explanatory text.
		if !atEOF {
			keep := len(pemBeginMarker) - 1
			if len(data) > keep {
				advance := len(data) - keep
				s.consumed += int64(advance)
				return advance, nil, nil
			}
			return 0, nil, nil
		}
		s.consumed += int64(len(data))
		return len(data), nil, nil
	}

	if begin > 0 {
		// Consume the prose preceding the dangling marker and re-enter.
		s.consumed += int64(begin)
		return begin, nil, nil
	}

	// The buffer starts with "-----BEGIN " but pem.Decode cannot produce a
	// block. If the matching END line is already present the block is
	// malformed; otherwise we are still waiting for more input.
	if end := pemEndLineEnd(data, atEOF); end > 0 {
		s.blockOrdinal++
		s.in.addDiagnostic(DiagMalformedBlock, "", "malformed PEM block could not be decoded",
			Source{Name: s.in.Name, Format: "PEM", Block: s.blockOrdinal, Offset: s.consumed})
		s.consumed += int64(end)
		return end, nil, nil
	}
	if atEOF {
		s.blockOrdinal++
		s.in.addDiagnostic(DiagMalformedBlock, "", "unclosed PEM block at end of input; input is truncated",
			Source{Name: s.in.Name, Format: "PEM", Block: s.blockOrdinal, Offset: s.consumed})
		return 0, nil, errUnclosedPEM
	}
	return 0, nil, nil
}

// pemEndLineEnd returns the offset just past the END line of a block, or -1 if
// no complete END line is visible.
func pemEndLineEnd(data []byte, atEOF bool) int {
	idx := bytes.Index(data, pemEndMarker)
	if idx < 0 {
		return -1
	}
	newline := bytes.IndexByte(data[idx+1:], '\n')
	if newline >= 0 {
		return idx + 1 + newline + 1
	}
	if atEOF {
		return len(data)
	}
	return -1
}

func readPEMBlocks(reader io.Reader, ir *InputParseResult, headers map[string]string, callback blockFunc) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), maxPEMBlockBytes)
	state := &pemScanState{in: ir}
	scanner.Split(state.split)

	for scanner.Scan() {
		// Clone the token: scanner reuses its buffer, but parsed certificates
		// keep referencing the underlying bytes.
		token := bytes.Clone(scanner.Bytes())
		block, _ := pem.Decode(token)
		if block == nil {
			// Defensive: the splitter only emits decodable blocks.
			continue
		}
		src := Source{Name: ir.Name, Format: "PEM", Block: state.blockOrdinal, Offset: state.lastOffset}
		if state.blockOrdinal > maxBlocksPerInput {
			ir.addDiagnostic(DiagResourceLimit, block.Type,
				fmt.Sprintf("input contains more than the allowed %d PEM blocks", maxBlocksPerInput), src)
			return errTooManyBlocks
		}
		block.Headers = mergeHeaders(block.Headers, headers)
		if err := ir.emit(callback, block, src); err != nil {
			return err
		}
	}

	switch err := scanner.Err(); {
	case err == nil:
		return nil
	case errors.Is(err, bufio.ErrTooLong):
		ir.addDiagnostic(DiagResourceLimit, "",
			fmt.Sprintf("PEM block exceeds maximum allowed size of %d bytes", maxPEMBlockBytes),
			Source{Name: ir.Name, Format: "PEM", Block: state.blockOrdinal + 1})
		return nil
	case errors.Is(err, errUnclosedPEM):
		// The splitter already recorded the diagnostic.
		return nil
	default:
		ir.addDiagnostic(DiagReadError, "", "error reading input: "+err.Error(),
			Source{Name: ir.Name, Format: "PEM", Block: state.blockOrdinal + 1})
		return nil
	}
}

func readDERBlocks(reader io.Reader, ir *InputParseResult, headers map[string]string, callback blockFunc) error {
	data, err := readAllLimited(reader)
	if err != nil {
		recordContainerReadError(ir, "DER", err)
		return nil
	}

	// X.509 path: ParseCertificates returns every fully parsed certificate
	// before the failure point. Valid certificates are delivered as a
	// partial result; trailing data that prevented full consumption makes
	// the input incomplete.
	x509Certs, x509Err := x509.ParseCertificates(data)
	if len(x509Certs) > 0 {
		for i, cert := range x509Certs {
			src := Source{Name: ir.Name, Format: "DER", Block: i + 1}
			if i+1 > maxBlocksPerInput {
				ir.addDiagnostic(DiagResourceLimit, "CERTIFICATE",
					fmt.Sprintf("input contains more than the allowed %d certificates", maxBlocksPerInput), src)
				return errTooManyBlocks
			}
			if cbErr := ir.emit(callback, EncodeX509ToPEM(cert, headers), src); cbErr != nil {
				return cbErr
			}
		}
		if x509Err != nil {
			ir.addDiagnostic(DiagMalformedBlock, "CERTIFICATE",
				"trailing data after DER certificate(s) could not be parsed: "+strings.TrimSuffix(x509Err.Error(), "\n"),
				Source{Name: ir.Name, Format: "DER", Block: len(x509Certs) + 1})
		}
		return nil
	}

	// PKCS#7 path: strict parsing requires every byte to be consumed, but
	// envelopes parsed before trailing garbage are still delivered.
	p7bBlocks, p7Err := pkcs7.ParseSignedDataStrict(data)
	if len(p7bBlocks) > 0 {
		for i, block := range p7bBlocks {
			src := Source{Name: ir.Name, Format: "DER", Block: i + 1}
			if i+1 > maxBlocksPerInput {
				ir.addDiagnostic(DiagResourceLimit, "PKCS7",
					fmt.Sprintf("input contains more than the allowed %d containers", maxBlocksPerInput), src)
				return errTooManyBlocks
			}
			if cbErr := ir.emit(callback, pkcs7ToPem(block, headers), src); cbErr != nil {
				return cbErr
			}
		}
		if p7Err != nil {
			ir.addDiagnostic(DiagMalformedBlock, "PKCS7", strings.TrimSuffix(p7Err.Error(), "\n"),
				Source{Name: ir.Name, Format: "DER", Block: len(p7bBlocks) + 1})
		}
		return nil
	}

	ir.addDiagnostic(DiagMalformedBlock, "",
		fmt.Sprintf("unable to parse certificates from DER data\n* X.509 parser gave: %s\n* PKCS7 parser gave: %s\n", x509Err, p7Err),
		Source{Name: ir.Name, Format: "DER"})
	return nil
}

func readPKCS12Blocks(reader io.Reader, ir *InputParseResult, password func(string) string, headers map[string]string, callback blockFunc) error {
	data, err := readAllLimited(reader)
	if err != nil {
		recordContainerReadError(ir, "PKCS12", err)
		return nil
	}
	blocks, err := pkcs12ToPemBlocks(data, password(""))
	if err != nil {
		ir.addDiagnostic(DiagMalformedBlock, "PKCS12", "unable to read keystore: "+strings.TrimSuffix(err.Error(), "\n"),
			Source{Name: ir.Name, Format: "PKCS12"})
		return nil
	}
	if len(blocks) == 0 {
		ir.addDiagnostic(DiagMalformedBlock, "PKCS12", "keystore appears to be empty or password was incorrect",
			Source{Name: ir.Name, Format: "PKCS12"})
		return nil
	}
	for i, block := range blocks {
		src := Source{Name: ir.Name, Format: "PKCS12", Block: i + 1}
		if i+1 > maxBlocksPerInput {
			ir.addDiagnostic(DiagResourceLimit, block.Type,
				fmt.Sprintf("keystore contains more than the allowed %d blocks", maxBlocksPerInput), src)
			return errTooManyBlocks
		}
		block.Headers = mergeHeaders(block.Headers, headers)
		if err := ir.emit(callback, block, src); err != nil {
			return err
		}
	}
	return nil
}

func readJCEKSBlocks(reader io.Reader, ir *InputParseResult, password func(string) string, headers map[string]string, callback blockFunc) error {
	keyStore, err := jceks.LoadFromReader(&limitedReader{r: reader, remaining: maxContainerBytes + 1}, []byte(password("")))
	if err != nil {
		if errors.Is(err, errInputTooLarge) {
			ir.addDiagnostic(DiagResourceLimit, "JCEKS",
				fmt.Sprintf("keystore exceeds maximum allowed size of %d bytes", maxContainerBytes),
				Source{Name: ir.Name, Format: "JCEKS"})
			return nil
		}
		ir.addDiagnostic(DiagMalformedBlock, "JCEKS", "unable to parse keystore: "+strings.TrimSuffix(err.Error(), "\n"),
			Source{Name: ir.Name, Format: "JCEKS"})
		return nil
	}

	ordinal := 0
	next := func(blockType string) (Source, bool) {
		ordinal++
		src := Source{Name: ir.Name, Format: "JCEKS", Block: ordinal}
		if ordinal > maxBlocksPerInput {
			ir.addDiagnostic(DiagResourceLimit, blockType,
				fmt.Sprintf("keystore contains more than the allowed %d blocks", maxBlocksPerInput), src)
			return src, false
		}
		return src, true
	}

	for _, alias := range keyStore.ListCerts() {
		cert, _ := keyStore.GetCert(alias)
		src, ok := next("CERTIFICATE")
		if !ok {
			return errTooManyBlocks
		}
		if err := ir.emit(callback, EncodeX509ToPEM(cert, mergeHeaders(headers, map[string]string{nameHeader: alias})), src); err != nil {
			return err
		}
	}
	for _, alias := range keyStore.ListPrivateKeys() {
		key, certs, err := keyStore.GetPrivateKeyAndCerts(alias, []byte(password(alias)))
		if err != nil {
			ir.addDiagnostic(DiagMalformedBlock, "JCEKS", "unable to parse keystore: "+strings.TrimSuffix(err.Error(), "\n"),
				Source{Name: ir.Name, Format: "JCEKS"})
			return nil
		}

		mergedHeaders := mergeHeaders(headers, map[string]string{nameHeader: alias})

		block, err := keyToPem(key, mergedHeaders)
		if err != nil {
			ir.addDiagnostic(DiagMalformedBlock, "JCEKS", strings.TrimSuffix(err.Error(), "\n"),
				Source{Name: ir.Name, Format: "JCEKS"})
			return nil
		}

		src, ok := next(block.Type)
		if !ok {
			return errTooManyBlocks
		}
		if err := ir.emit(callback, block, src); err != nil {
			return err
		}

		for _, cert := range certs {
			src, ok := next("CERTIFICATE")
			if !ok {
				return errTooManyBlocks
			}
			if err := ir.emit(callback, EncodeX509ToPEM(cert, mergedHeaders), src); err != nil {
				return err
			}
		}
	}
	return nil
}

func recordContainerReadError(ir *InputParseResult, format string, err error) {
	src := Source{Name: ir.Name, Format: format}
	if errors.Is(err, errInputTooLarge) {
		ir.addDiagnostic(DiagResourceLimit, "",
			fmt.Sprintf("input exceeds maximum allowed size of %d bytes", maxContainerBytes), src)
		return
	}
	//nolint:staticcheck // See errorFromErrors
	ir.addDiagnostic(DiagReadError, "", fmt.Sprintf("unable to read input: %s\n", err), src)
}

// readAllLimited reads the whole binary container while enforcing
// maxContainerBytes.
func readAllLimited(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxContainerBytes+1))
	if int64(len(data)) > maxContainerBytes {
		return data[:maxContainerBytes], errInputTooLarge
	}
	return data, err
}

// limitedReader enforces a hard byte budget while reading. A file that ends
// exactly at the limit yields io.EOF; any further bytes produce
// errInputTooLarge.
type limitedReader struct {
	r         io.Reader
	remaining int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.remaining <= 0 {
		n, err := l.r.Read(p)
		if n > 0 {
			return n, errInputTooLarge
		}
		return 0, err
	}
	if int64(len(p)) > l.remaining {
		p = p[:l.remaining]
	}
	n, err := l.r.Read(p)
	l.remaining -= int64(n)
	return n, err
}

// TODO: replace misuse of error type in future version (errors should not act as multi-line output templates)
func errorFromErrors(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	if len(errs) == 1 {
		return errs[0]
	}
	buffer := new(bytes.Buffer)
	buffer.WriteString("encountered multiple errors:\n")
	for _, err := range errs {
		buffer.WriteString("* ")
		buffer.WriteString(strings.TrimSuffix(err.Error(), "\n"))
		buffer.WriteString("\n")
	}
	return errors.New(buffer.String())
}

func mergeHeaders(baseHeaders, extraHeaders map[string]string) (headers map[string]string) {
	headers = map[string]string{}
	for k, v := range baseHeaders {
		headers[k] = v
	}
	for k, v := range extraHeaders {
		headers[k] = v
	}
	return
}

// EncodeX509ToPEM converts an X.509 certificate into a PEM block for output.
func EncodeX509ToPEM(cert *x509.Certificate, headers map[string]string) *pem.Block {
	return &pem.Block{
		Type:    "CERTIFICATE",
		Bytes:   cert.Raw,
		Headers: headers,
	}
}

// Convert a PKCS7 envelope into a PEM block for output.
func pkcs7ToPem(block *pkcs7.SignedDataEnvelope, headers map[string]string) *pem.Block {
	return &pem.Block{
		Type:    "PKCS7",
		Bytes:   block.Raw,
		Headers: headers,
	}
}

// Convert a key into one or more PEM blocks for output.
func keyToPem(key crypto.PrivateKey, headers map[string]string) (*pem.Block, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{
			Type:    "RSA PRIVATE KEY",
			Bytes:   x509.MarshalPKCS1PrivateKey(k),
			Headers: headers,
		}, nil
	case *ecdsa.PrivateKey:
		raw, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			//nolint:staticcheck // See errorFromErrors
			return nil, fmt.Errorf("error marshaling key: %s\n", reflect.TypeOf(key))
		}
		return &pem.Block{
			Type:    "EC PRIVATE KEY",
			Bytes:   raw,
			Headers: headers,
		}, nil
	}
	//nolint:staticcheck // See errorFromErrors
	return nil, fmt.Errorf("unknown key type: %s\n", reflect.TypeOf(key))
}

// pkcs12ToPemBlocks converts all PKCS#12 safe bags in data to PEM blocks.
func pkcs12ToPemBlocks(data []byte, password string) ([]*pem.Block, error) {
	// pkcs12.ToPEM is deprecated because it returns "PRIVATE KEY" PEM blocks that are not in PKCS#8 format, but rather
	// in a format specific to the key type. However, the pkcs12 package does not provide an equivalent replacement:
	// there is no other way to preserve the order of the safe bag contents or to preserve "friendlyName", "localKeyId",
	// and "Microsoft CSP Name" attributes that may be present in the PKCS#12 data. Therefore, this function calls the
	// deprecated function and then attempts to fix the invalid PEM blocks by giving them appropriate block types.
	//nolint:staticcheck // See comment
	blocks, err := pkcs12.ToPEM(data, password)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#12 data: %w", err)
	}
	for _, block := range blocks {
		if block.Type != "PRIVATE KEY" {
			continue
		}
		if _, parseErr := x509.ParseECPrivateKey(block.Bytes); parseErr == nil {
			block.Type = "EC PRIVATE KEY"
			continue
		}
		if _, parseErr := x509.ParsePKCS1PrivateKey(block.Bytes); parseErr == nil {
			block.Type = "RSA PRIVATE KEY"
			continue
		}

		//nolint:staticcheck // See errorFromErrors
		return nil, fmt.Errorf("PKCS#12 conversion produced unknown private key type\n")
	}

	return blocks, nil
}

// formatForFile returns the file format (either from flags or
// based on file extension).
func formatForFile(file *bufio.Reader, filename, format string) (string, error) {
	// First, honor --format flag we got from user
	format = strings.TrimSpace(format)
	if format != "" {
		return format, nil
	}

	// Second, attempt to guess based on extension
	guess, ok := fileExtToFormat[strings.ToLower(filepath.Ext(filename))]
	if ok {
		return guess, nil
	}

	// Third, attempt to guess based on first 4 bytes of input
	data, err := file.Peek(4)
	if err != nil {
		return "", fmt.Errorf("unable to read file: %s\n", err) //nolint:staticcheck // See errorFromErrors
	}

	// Heuristics for guessing -- best effort.
	magic := binary.BigEndian.Uint32(data)
	if magic == 0xCECECECE || magic == 0xFEEDFEED {
		// JCEKS/JKS files always start with this prefix
		return "JCEKS", nil
	}
	if magic == 0x2D2D2D2D || magic == 0x434f4e4e {
		// Starts with '----' or 'CONN' (what s_client prints...)
		return "PEM", nil
	}
	if magic&0xFFFF0000 == 0x30820000 {
		// Looks like the input is DER-encoded, so it's either PKCS12 or X.509.
		if magic&0x0000FF00 == 0x0300 {
			// Probably X.509
			return "DER", nil
		}
		return "PKCS12", nil
	}

	return "", fmt.Errorf("unable to guess file format")
}
