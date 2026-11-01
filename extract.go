package main

import (
	"bytes"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func flagsByte(password string) byte {
	if password != "" {
		return 0x11
	}
	return 0
}

func extractARJ(path string, patterns []string, password string,
	assumeYes bool) error {

	a, err := OpenARJ(path)
	if err != nil {
		return err
	}
	defer a.Close()

	a.Password = password

	match := func(name string) bool {
		if len(patterns) == 0 {
			return true
		}
		for _, p := range patterns {
			if ok, _ := filepath.Match(p, name); ok {
				return true
			}
		}
		return false
	}

	var curOut *os.File
	var curName string
	var curHdr *ARJHeader

	finishCurrent := func() error {
		if curOut == nil {
			return nil
		}
		err := curOut.Close()
		curOut = nil
		if curHdr != nil && err == nil {
			if curHdr.FileAccessMode != 0 {
				os.Chmod(curName, os.FileMode(curHdr.FileAccessMode)&0o777)
			}
			if curHdr.Timestamp != 0 {
				mtime := dosTimestampToTime(curHdr.Timestamp)
				os.Chtimes(curName, mtime, mtime)
			}
			fmt.Printf("  extracting: %s\n", curName)
		}
		curHdr = nil
		curName = ""
		return err
	}

	for {
		hdr, err := a.Next()
		if err != nil {
			finishCurrent()
			return err
		}
		if hdr == nil {
			break
		}

		isContinuation := hdr.HasFlag(EXTFILE_FLAG) && curOut != nil && hdr.Filename == curName

		if !isContinuation {
			if err := finishCurrent(); err != nil {
				return err
			}

			if !match(hdr.Filename) {
				if err := a.SkipData(hdr); err != nil {
					return err
				}
				continue
			}

			if hdr.FileType == ARJT_DIR {
				if err := os.MkdirAll(hdr.Filename, 0o755); err != nil {
					fmt.Fprintf(os.Stderr, "arj: %s: %v\n", hdr.Filename, err)
				}
				if err := a.SkipData(hdr); err != nil {
					return err
				}
				continue
			}
			if hdr.FileType != ARJT_BINARY && hdr.FileType != ARJT_TEXT {
				fmt.Fprintf(os.Stderr, "arj: skipping non-file entry: %s (type %d)\n",
					hdr.Filename, hdr.FileType)
				if err := a.SkipData(hdr); err != nil {
					return err
				}
				continue
			}

			if _, statErr := os.Stat(hdr.Filename); statErr == nil {
				if !promptYes(fmt.Sprintf("%s already exists. Overwrite?", hdr.Filename), assumeYes) {
					fmt.Printf("  skipping:  %s\n", hdr.Filename)
					if err := a.SkipData(hdr); err != nil {
						return err
					}
					continue
				}
				os.Remove(hdr.Filename)
			}

			if dir := filepath.Dir(hdr.Filename); dir != "." && dir != "" {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					return fmt.Errorf("%s: %w", hdr.Filename, err)
				}
			}

			out, err := os.OpenFile(hdr.Filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
			if err != nil {
				return fmt.Errorf("%s: %w", hdr.Filename, err)
			}

			curOut = out
			curName = hdr.Filename
			curHdr = hdr
		}

		if err := a.ExtractFile(hdr, curOut); err != nil {
			fmt.Fprintf(os.Stderr, "arj: %s: %v\n", hdr.Filename, err)
			finishCurrent()
			os.Remove(curName)
			return err
		}

		if !hdr.HasFlag(VOLUME_FLAG) {
			if err := finishCurrent(); err != nil {
				return err
			}
		}
	}

	if err := finishCurrent(); err != nil {
		return err
	}
	return nil
}

func testARJ(path string, password string) error {
	// Pre-scan: find the latest entry timestamp and the longest
	// filename so the header line (created/modified) and the name
	// column are known before the first "Testing ..." line.
	nameWidth := 36
	var maxTS uint32

	pre, err := OpenARJ(path)
	if err != nil {
		return err
	}
	for {
		hdr, err := pre.Next()
		if err != nil {
			pre.Close()
			return err
		}
		if hdr == nil {
			break
		}
		if len(hdr.Filename) > nameWidth {
			nameWidth = len(hdr.Filename)
		}
		if hdr.Timestamp > maxTS {
			maxTS = hdr.Timestamp
		}
		if err := pre.SkipData(hdr); err != nil {
			pre.Close()
			return err
		}
	}
	pre.Close()
	if nameWidth > 60 {
		nameWidth = 60
	}

	a, err := OpenARJ(path)
	if err != nil {
		return err
	}
	defer a.Close()

	a.Password = password

	mh := a.MainHeader()

	// created/modified come from the main header. For HostOS == 0
	// they are DOS timestamps; otherwise epoch seconds.
	createdT := time.Unix(int64(mh.Timestamp), 0)
	modT := time.Unix(int64(mh.Modified), 0)
	if mh.HostOS == 0 {
		createdT = dosTimestampToTime(mh.Timestamp)
		modT = dosTimestampToTime(mh.Modified)
	}
	if mh.Modified == 0 {
		modT = createdT
	}

	fmt.Printf("Processing archive: %s\n", path)
	fmt.Printf("Archive created: %s, modified: %s\n",
		createdT.Format("2006-01-02 15:04:05"),
		modT.Format("2006-01-02 15:04:05"))
	fmt.Println()

	type pendingFile struct {
		hdr     *ARJHeader
		lastHdr *ARJHeader
		data    []byte
		errored bool // already reported an error for this file
	}
	var current *pendingFile

	var total, ok int

	// nameWidth is the width of the "Testing <name>" column. 40 is
	// what the original ARJ 3.10 uses on a 80-column terminal; we
	// grow it if any filename is longer, capped at 60 so the OK
	// column never wraps.
	var names []string

	// shortStatus maps an extraction error to a short label that
	// fits in the status column, like the original arj does.
	shortStatus := func(err error) string {
		msg := err.Error()
		switch {
		case strings.Contains(msg, "encrypted file"):
			return "ENCRYPTED"
		case strings.Contains(msg, "MAC verification"):
			return "MAC ERROR"
		case strings.Contains(msg, "CRC"):
			return "CRC ERROR"
		case strings.Contains(msg, "unsupported method"):
			return "METHOD"
		default:
			return "ERROR"
		}
	}

	flushCurrent := func() {
		if current == nil {
			return
		}
		if current.errored {
			current = nil
			return
		}
		status := "OK"
		if current.lastHdr == nil ||
			crc32.ChecksumIEEE(current.data) != current.lastHdr.CRC32 {
			status = "CRC ERROR"
		}
		date, timeStr := formatTimestamp(current.hdr)
		name := current.hdr.Filename
		if len(name) > nameWidth {
			name = name[:nameWidth]
		}
		fmt.Printf("%-*s  %s %s  %-10s\n",
			nameWidth, name, date, timeStr, status)
		if status == "OK" {
			ok++
		}
		current = nil
	}

	for {
		hdr, err := a.Next()
		if err != nil {
			flushCurrent()
			return err
		}
		if hdr == nil {
			break
		}
		if hdr.FileType != ARJT_BINARY && hdr.FileType != ARJT_TEXT {
			if err := a.SkipData(hdr); err != nil {
				flushCurrent()
				return err
			}
			continue
		}

		isContinuation := hdr.HasFlag(EXTFILE_FLAG) && current != nil &&
			hdr.Filename == current.hdr.Filename

		if !isContinuation {
			flushCurrent()
			current = &pendingFile{hdr: hdr}
			names = append(names, hdr.Filename)
			total++ // count the attempt here, once per file
		}
		current.lastHdr = hdr

		// Already failed on the first chunk: skip the rest of this
		// file without trying again, but still consume the payload
		// so the next header is read from the right position.
		if current.errored {
			if err := a.SkipData(hdr); err != nil {
				flushCurrent()
				return err
			}
			if !hdr.HasFlag(VOLUME_FLAG) {
				flushCurrent()
			}
			continue
		}

		var buf bytes.Buffer
		buf.Write(current.data)
		w := &resizeOnSeek{buf: &buf, pos: int64(buf.Len())}
		if err := a.ExtractFile(hdr, w); err != nil {
			date, timeStr := formatTimestamp(hdr)
			name := hdr.Filename
			if len(name) > nameWidth {
				name = name[:nameWidth]
			}
			fmt.Printf("%-*s  %s %s  %-10s\n",
				nameWidth, name, date, timeStr, shortStatus(err))
			current.errored = true
			continue
		}
		current.data = append([]byte{}, buf.Bytes()...)

		if !hdr.HasFlag(VOLUME_FLAG) {
			flushCurrent()
		}
	}

	for _, n := range names {
		if len(n) > nameWidth {
			nameWidth = len(n)
			if nameWidth > 60 {
				nameWidth = 60
			}
		}
	}

	if ok != total {
		fmt.Printf("%6d/%d file(s)\n", ok, total)
		return fmt.Errorf("%d file(s) failed", total-ok)
	}
	fmt.Printf("%6d file(s)\n", total)
	return nil
}

// resizeOnSeek is a growable buffer with a real position, so that
// ExtractFile's Seek(ResumePosition) positions the next Write at the
// correct offset instead of always appending to the end.
type resizeOnSeek struct {
	buf *bytes.Buffer
	pos int64
}

func (w *resizeOnSeek) Write(b []byte) (int, error) {
	need := int(w.pos) + len(b)
	if need > w.buf.Len() {
		pad := make([]byte, need-w.buf.Len())
		w.buf.Write(pad)
	}
	copy(w.buf.Bytes()[w.pos:], b)
	w.pos += int64(len(b))
	return len(b), nil
}

func (w *resizeOnSeek) Seek(offset int64, whence int) (int64, error) {
	var base int64
	switch whence {
	case io.SeekStart:
		base = 0
	case io.SeekCurrent:
		base = w.pos
	case io.SeekEnd:
		base = int64(w.buf.Len())
	default:
		return 0, fmt.Errorf("invalid whence")
	}
	target := base + offset
	if target < 0 {
		return 0, fmt.Errorf("negative seek")
	}
	w.pos = target
	return target, nil
}

type sliceWriter struct{ p *[]byte }

func (w *sliceWriter) Write(b []byte) (int, error) {
	*w.p = append(*w.p, b...)
	return len(b), nil
}

