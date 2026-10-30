package main

import (
	"bytes"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
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
	a, err := OpenARJ(path)
	if err != nil {
		return err
	}
	defer a.Close()

	a.Password = password

	type pendingFile struct {
		hdr     *ARJHeader
		lastHdr *ARJHeader
		data    []byte
	}
	var current *pendingFile

	var total, ok int

	flushCurrent := func() {
		if current == nil {
			return
		}
		total++
		// The CRC32 in the *last* chunk's header covers the whole
		// file. current.hdr is the first chunk, so use lastHdr.CRC32.
		if crc32.ChecksumIEEE(current.data) == current.lastHdr.CRC32 {
			fmt.Printf("  %s: OK\n", current.hdr.Filename)
			ok++
		} else {
			fmt.Printf("  %s: CRC MISMATCH (got %d bytes, want %d)\n",
				current.hdr.Filename, len(current.data), current.hdr.OriginalSize)
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
		}
		current.lastHdr = hdr

		var buf bytes.Buffer
		buf.Write(current.data)
		w := &resizeOnSeek{buf: &buf, pos: int64(buf.Len())}
		if err := a.ExtractFile(hdr, w); err != nil {
			fmt.Printf("  %s: ERROR: %v\n", hdr.Filename, err)
			current = nil
			continue
		}
		current.data = append([]byte{}, buf.Bytes()...)

		if !hdr.HasFlag(VOLUME_FLAG) {
			flushCurrent()
		}
	}

	fmt.Printf("\n%d/%d files OK\n", ok, total)
	if ok != total {
		return fmt.Errorf("%d file(s) failed", total-ok)
	}
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

