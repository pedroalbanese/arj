package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	// Parsing de -gPASS / -g PASS
	password := ""
	filtered := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-g" && i+1 < len(args):
			password = args[i+1]
			i++
		case strings.HasPrefix(a, "-g") && len(a) > 2:
			password = a[2:]
		default:
			filtered = append(filtered, a)
		}
	}
	args = filtered

	switch cmd {
	case "-h", "--help", "help":
		usage()
		return
	case "a", "add":
		if len(args) < 2 {
			fail("arj: usage: arj a [-gPASS] archive.arj file...")
		}
		if err := addARJ(args[0], args[1:], password); err != nil {
			fail("arj: %v", err)
		}
	case "l", "list":
		if len(args) < 1 {
			fail("arj: usage: arj l archive.arj")
		}
		if err := listARJ(args[0]); err != nil {
			fail("arj: %v", err)
		}
	case "x", "extract":
		if len(args) < 1 {
			fail("arj: usage: arj x [-gPASS] archive.arj [files...]")
		}
		if err := extractARJ(args[0], args[1:], password); err != nil {
			fail("arj: %v", err)
		}
	case "t", "test":
		if len(args) < 1 {
			fail("arj: usage: arj t [-gPASS] archive.arj")
		}
		if err := testARJ(args[0], password); err != nil {
			fail("arj: %v", err)
		}
	default:
		fail("arj: unknown command: %s", cmd)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `ARJ Evolved — The ARJ format, modernized with Kuznyechik encryption.

Usage:     arj <command> [-<sw> [-<sw>...]] <archive_name> [<file_names>...]
Examples:  arj a -gsecret archive, arj x -gsecret archive, arj l archive

<Commands>
  a: Add files to archive               l: List contents of archive
  x: eXtract files with full pathname   t: Test integrity of archive
  -h: Show this help                    -?: Same as -h

<Switches>
  g: Garble with password (Kuznyechik)  y: assume Yes on all queries

Notes:
  - Compression uses method 4 (LZ77/LZSS).
  - Decompression accepts methods 0 (stored) and 4.
  - Encryption uses Kuznyechik (GOST R 34.12-2015).
  - CRC32 is kept for header compatibilityz.
`)
}

func fail(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func VerifyCRC32(hdr *ARJHeader, data []byte) bool {
	return crc32.ChecksumIEEE(data) == hdr.CRC32
}

func dosTimestampFromTime(t time.Time) uint32 {
	year := t.Year()
	month := int(t.Month())
	day := t.Day()
	hour := t.Hour()
	min := t.Minute()
	sec := t.Second()
	return uint32((year-1980)<<25 | month<<21 | day<<16 | hour<<11 | min<<5 | sec/2)
}

// ===========================================================================
// CONSTANTES DE CRIPTOGRAFIA
// ===========================================================================

const (
	ARJ_PMOD  byte = 0
	ARJ_FLAGS byte = 0x11
)

// ===========================================================================
// MODIFIER
// ===========================================================================

func buildModifier(dosTS uint32, pmod byte) [2]uint32 {
	return [2]uint32{dosTS, uint32(int32(int8(pmod)))}
}

// ===========================================================================
// ENCRYPT
// ===========================================================================

func encrypt(data []byte, password string, dosTS uint32) ([]byte, byte, error) {
	var compressed bytes.Buffer
	enc := newEncState(&compressed, len(data))
	enc.in = data
	if err := enc.encodeF(); err != nil {
		return nil, 0, fmt.Errorf("compress: %w", err)
	}

	out := compressed.Bytes()
	if password == "" {
		return out, 0, nil
	}

	pmod := ARJ_PMOD
	modifier := buildModifier(dosTS, pmod)

	cipherText := make([]byte, len(out))
	copy(cipherText, out)

	cipher := &ARJCrypt{}
	cipher.Init(password, modifier)
	cipher.Encode(cipherText)
	return cipherText, pmod, nil
}

// ===========================================================================
// ADD
// ===========================================================================

func addARJ(archivePath string, files []string, password string) error {
	type inputFile struct {
		name string
		path string
		info os.FileInfo
	}
	var inputs []inputFile

	for _, f := range files {
		info, err := os.Stat(f)
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		if info.IsDir() {
			err := filepath.Walk(f, func(path string, fi os.FileInfo, err error) error {
				if err != nil {
					return nil
				}
				if fi.IsDir() {
					return nil
				}
				inputs = append(inputs, inputFile{
					name: filepath.ToSlash(path),
					path: path,
					info: fi,
				})
				return nil
			})
			if err != nil {
				return err
			}
		} else {
			inputs = append(inputs, inputFile{
				name: filepath.ToSlash(f),
				path: f,
				info: info,
			})
		}
	}

	if len(inputs) == 0 {
		return fmt.Errorf("no files to add")
	}

	out, err := os.Create(archivePath)
	if err != nil {
		return err
	}
	defer out.Close()

	if err := writeMainHeader(out, archivePath, password); err != nil {
		return fmt.Errorf("main header: %w", err)
	}

	for _, in := range inputs {
		if err := addOneFile(out, in.name, in.path, in.info, password); err != nil {
			return fmt.Errorf("%s: %w", in.name, err)
		}
		mark := ""
		if password != "" {
			mark = " [encrypted]"
		}
		fmt.Printf("  adding: %s (%d bytes)%s\n", in.name, in.info.Size(), mark)
	}

	if err := writeEndHeader(out); err != nil {
		return err
	}
	return nil
}

// ===========================================================================
// MAIN HEADER
// ===========================================================================

func writeMainHeader(w io.Writer, archiveName string, password string) error {
	hdr := make([]byte, 0, 64)
	hdr = append(hdr, 34) // first_hdr_size
	hdr = append(hdr, 11) // version
	hdr = append(hdr, 1)  // min_version
	hdr = append(hdr, 2)  // host_os = OS_UNIX

	var flags byte
	if password != "" {
		flags = 0x11
	}
	hdr = append(hdr, flags) // flags
	hdr = append(hdr, 0)     // method
	hdr = append(hdr, 2)     // file_type = ARJT_COMMENT
	hdr = append(hdr, 0)     // password_mod

	var ts [4]byte
	binary.LittleEndian.PutUint32(ts[:], dosTimestampFromTime(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)))
	hdr = append(hdr, ts[:]...)

	for i := 0; i < 12; i++ {
		hdr = append(hdr, 0)
	}
	hdr = append(hdr, 0, 0) // entry_pos
	hdr = append(hdr, 0, 0) // file_mode
	hdr = append(hdr, 0, 0) // ext_flags, chapter_number
	hdr = append(hdr, 0, 0) // prot_blocks, arjprot_id
	hdr = append(hdr, 0, 0) // host_data

	base := filepath.Base(archiveName)
	hdr = append(hdr, []byte(base)...)
	hdr = append(hdr, 0)
	hdr = append(hdr, 0)

	basicSize := uint16(len(hdr))
	if _, err := w.Write([]byte{0x60, 0xEA}); err != nil {
		return err
	}
	var sz [2]byte
	binary.LittleEndian.PutUint16(sz[:], basicSize)
	if _, err := w.Write(sz[:]); err != nil {
		return err
	}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	var crc [4]byte
	binary.LittleEndian.PutUint32(crc[:], crc32.ChecksumIEEE(hdr))
	if _, err := w.Write(crc[:]); err != nil {
		return err
	}
	if _, err := w.Write([]byte{0, 0}); err != nil {
		return err
	}
	return nil
}

func writeEndHeader(w io.Writer) error {
	if _, err := w.Write([]byte{0x60, 0xEA, 0, 0}); err != nil {
		return err
	}
	return nil
}

// ===========================================================================
// LOCAL HEADER
// ===========================================================================

func addOneFile(w io.Writer, name, path string, info os.FileInfo,
	password string) error {

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	dosTS := dosTimestampFromTime(info.ModTime())
	fileCRC := crc32.ChecksumIEEE(data)

	storedData, pmod, err := encrypt(data, password, dosTS)
	if err != nil {
		return err
	}

	hdr := make([]byte, 0, 64)
	hdr = append(hdr, 46) // first_hdr_size
	hdr = append(hdr, 11) // version
	hdr = append(hdr, 1)  // min_version
	hdr = append(hdr, 2)  // host_os = OS_UNIX

	var flags byte
	if password != "" {
		flags = 0x11
	}
	hdr = append(hdr, flags) // flags
	hdr = append(hdr, 4)     // method = 4
	hdr = append(hdr, 0)     // file_type = ARJT_BINARY
	hdr = append(hdr, pmod)  // password_mod

	var ts [4]byte
	binary.LittleEndian.PutUint32(ts[:], dosTS)
	hdr = append(hdr, ts[:]...)

	var cs [4]byte
	binary.LittleEndian.PutUint32(cs[:], uint32(len(storedData)))
	hdr = append(hdr, cs[:]...)

	var osz [4]byte
	binary.LittleEndian.PutUint32(osz[:], uint32(len(data)))
	hdr = append(hdr, osz[:]...)

	var crc [4]byte
	binary.LittleEndian.PutUint32(crc[:], fileCRC)
	hdr = append(hdr, crc[:]...)

	hdr = append(hdr, 0, 0) // entry_pos
	var mode [2]byte
	binary.LittleEndian.PutUint16(mode[:], 0o644)
	hdr = append(hdr, mode[:]...) // file_mode = 0o644
	hdr = append(hdr, 0, 0)       // ext_flags, chapter_number
	hdr = append(hdr, 0, 0, 0, 0) // resume_position
	hdr = append(hdr, 0, 0, 0, 0) // atime
	hdr = append(hdr, 0, 0, 0, 0) // ctime
	hdr = append(hdr, 0, 0, 0, 0) // reserved

	hdr = append(hdr, []byte(name)...)
	hdr = append(hdr, 0)
	hdr = append(hdr, 0)

	basicSize := uint16(len(hdr))
	if _, err := w.Write([]byte{0x60, 0xEA}); err != nil {
		return err
	}
	var sz [2]byte
	binary.LittleEndian.PutUint16(sz[:], basicSize)
	if _, err := w.Write(sz[:]); err != nil {
		return err
	}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	var hcrc [4]byte
	binary.LittleEndian.PutUint32(hcrc[:], crc32.ChecksumIEEE(hdr))
	if _, err := w.Write(hcrc[:]); err != nil {
		return err
	}
	if _, err := w.Write([]byte{0, 0}); err != nil {
		return err
	}

	if _, err := w.Write(storedData); err != nil {
		return err
	}
	return nil
}

// ===========================================================================
// LIST, EXTRACT, TEST
// ===========================================================================

func extractARJ(path string, patterns []string, password string) error {
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

	for {
		hdr, err := a.Next()
		if err != nil {
			return err
		}
		if hdr == nil {
			break
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

		if dir := filepath.Dir(hdr.Filename); dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("%s: %w", hdr.Filename, err)
			}
		}

		out, err := os.Create(hdr.Filename)
		if err != nil {
			return fmt.Errorf("%s: %w", hdr.Filename, err)
		}
		if err := a.ExtractFile(hdr, out); err != nil {
			out.Close()
			os.Remove(hdr.Filename)
			return fmt.Errorf("%s: %w", hdr.Filename, err)
		}
		out.Close()
		fmt.Printf("  extracting: %s\n", hdr.Filename)
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

	var total, ok int
	for {
		hdr, err := a.Next()
		if err != nil {
			return err
		}
		if hdr == nil {
			break
		}
		if hdr.FileType != ARJT_BINARY && hdr.FileType != ARJT_TEXT {
			if err := a.SkipData(hdr); err != nil {
				return err
			}
			continue
		}
		total++
		var buf []byte
		err = a.ExtractFile(hdr, &sliceWriter{&buf})
		if err != nil {
			fmt.Printf("  %s: ERROR: %v\n", hdr.Filename, err)
			continue
		}
		if !VerifyCRC32(hdr, buf) {
			fmt.Printf("  %s: CRC MISMATCH\n", hdr.Filename)
			continue
		}
		fmt.Printf("  %s: OK\n", hdr.Filename)
		ok++
	}
	fmt.Printf("\n%d/%d files OK\n", ok, total)
	if ok != total {
		return fmt.Errorf("%d file(s) failed", total-ok)
	}
	return nil
}

type sliceWriter struct{ p *[]byte }

func (w *sliceWriter) Write(b []byte) (int, error) {
	*w.p = append(*w.p, b...)
	return len(b), nil
}
