package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const MULTIVOLUME_RESERVE = 4096

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	password := ""
	assumeYes := false
	updateOnly := false
	volumeLimitKB := 0
	filtered := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-y":
			assumeYes = true
		case a == "-u":
			updateOnly = true
		case a == "-g" && i+1 < len(args):
			password = args[i+1]
			i++
		case strings.HasPrefix(a, "-g") && len(a) > 2:
			password = a[2:]
		case a == "-v" && i+1 < len(args):
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n <= 0 {
				fail("arj: invalid volume size: %s", args[i+1])
			}
			volumeLimitKB = n
			i++
		case strings.HasPrefix(a, "-v") && len(a) > 2:
			n, err := strconv.Atoi(a[2:])
			if err != nil || n <= 0 {
				fail("arj: invalid volume size: %s", a[2:])
			}
			volumeLimitKB = n
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
			fail("arj: usage: arj a [-y] [-u] [-gPASS] [-vN] archive.arj file...")
		}
		if err := addARJ(args[0], args[1:], password, assumeYes, volumeLimitKB, updateOnly); err != nil {
			fail("arj: %v", err)
		}
	case "d", "delete":
		if len(args) < 2 {
			fail("arj: usage: arj d archive.arj file...")
		}
		if err := deleteARJ(args[0], args[1:]); err != nil {
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
			fail("arj: usage: arj x [-y] [-gPASS] archive.arj [files...]")
		}
		if err := extractARJ(args[0], args[1:], password, assumeYes); err != nil {
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
	fmt.Fprintf(os.Stderr, `ARJ Evolved — The ARJ format, with a modern encryption layer.

Usage:     arj <command> [-<sw> [-<sw>...]] <archive_name> [<file_names>...]
Examples:  arj a -gsecret archive, arj x -gsecret archive, arj l archive
           arj a -v1440 archive.arj file1 file2

<Commands>
  a: Add files to archive               d: Delete files from archive
  l: List contents of archive           t: Test integrity of archive
  x: eXtract files with full pathname   -h: Show this help

<Switches>
  g: Garble with password (Kuznyechik)  y: assume Yes on all queries
  v: create multi-Volume archive in KB  u: Update files (new and newer)

Notes:
  - Compression uses method 4 (LZ77/LZSS).
  - Decompression accepts methods 0–4.
  - Encryption uses Kuznyechik (GOST R 34.12-2015) in CFB Mode.
  - Key derivation uses PBKDF2-Streebog-256 (GOST R 34.11-2012).
  - Authentication uses HMAC-Streebog-256 (GOST R 34.11-2012).
  - CRC32 is kept for header compatibility.
`)
}

func fail(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func promptYes(question string, assumeYes bool) bool {
	if assumeYes {
		return true
	}
	stat, err := os.Stdin.Stat()
	if err != nil || (stat.Mode()&os.ModeCharDevice) == 0 {
		return false
	}
	fmt.Fprintf(os.Stderr, "%s (y/N) ", question)
	reader := bufio.NewReader(os.Stdin)
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == "y" || answer == "yes"
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

func dosTimestampToTime(ts uint32) time.Time {
	sec := int(ts&0x1F) * 2
	min := int((ts >> 5) & 0x3F)
	hour := int((ts >> 11) & 0x1F)
	day := int((ts >> 16) & 0x1F)
	month := int((ts >> 21) & 0x0F)
	year := int((ts>>25)&0x7F) + 1980
	return time.Date(year, time.Month(month), day, hour, min, sec, 0, time.Local)
}

const (
	ARJ_PMOD  byte = 0
	ARJ_FLAGS byte = 0x11
)

type rawEntry struct {
	name        string
	baseHdr     []byte
	comp        []byte
	salt        uint32
	dosTS       uint32
	origSize    uint32
	fileCRC     uint32
	fileMode    uint16
	checkpoints []checkpoint
}

func checkpointAtOrBefore(cps []checkpoint, target int64) (checkpoint, bool) {
	if len(cps) == 0 {
		return checkpoint{}, false
	}
	lo, hi := 0, len(cps)
	for lo < hi {
		mid := (lo + hi) / 2
		if cps[mid].compOffset <= target {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo == 0 {
		return checkpoint{}, false
	}
	return cps[lo-1], true
}

func checkpointAfter(cps []checkpoint, target int64) (checkpoint, bool) {
	if len(cps) == 0 {
		return checkpoint{}, false
	}
	lo, hi := 0, len(cps)
	for lo < hi {
		mid := (lo + hi) / 2
		if cps[mid].compOffset <= target {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo >= len(cps) {
		return checkpoint{}, false
	}
	return cps[lo], true
}

func insertSorted(entries []rawEntry, e rawEntry) []rawEntry {
	lo, hi := 0, len(entries)
	for lo < hi {
		mid := (lo + hi) / 2
		if entries[mid].name < e.name {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	entries = append(entries, rawEntry{})
	copy(entries[lo+1:], entries[lo:])
	entries[lo] = e
	return entries
}

func addARJ(archivePath string, files []string, password string,
	assumeYes bool, volumeLimitKB int, updateOnly bool) error {

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

	newNames := make(map[string]bool)
	for _, in := range inputs {
		newNames[in.name] = true
	}

	var entries []rawEntry
	skipNew := make(map[string]bool)

	archiveExists := false
	if _, err := os.Stat(archivePath); err == nil {
		archiveExists = true
	}
	if archiveExists && volumeLimitKB > 0 {
		return fmt.Errorf("multi-volume update is not supported; remove existing archive first")
	}

	if archiveExists {
		a, err := OpenARJ(archivePath)
		if err != nil {
			return err
		}
		defer a.Close()

		for {
			hdr, err := a.Next()
			if err != nil {
				return err
			}
			if hdr == nil {
				break
			}

			if newNames[hdr.Filename] {
				if updateOnly {
					diskInfo, statErr := os.Stat(hdr.Filename)
					if statErr == nil {
						diskTime := dosTimestampFromTime(diskInfo.ModTime())
						if diskTime <= hdr.Timestamp {
							skipNew[hdr.Filename] = true
							fmt.Printf("  keeping (up to date): %s\n", hdr.Filename)
							if err := a.SkipData(hdr); err != nil {
								return err
							}
							continue
						}
					}
				}
				if promptYes(fmt.Sprintf("%s is already in the archive. Overwrite?", hdr.Filename), assumeYes) {
					if err := a.SkipData(hdr); err != nil {
						return err
					}
					fmt.Printf("  replacing: %s\n", hdr.Filename)
					continue
				}
				skipNew[hdr.Filename] = true
				fmt.Printf("  keeping:   %s\n", hdr.Filename)
			}

			headerStart := hdr.DataOffset - int64(hdr.BasicHeaderSize) - 10 - int64(len(hdr.ExtendedHdr))
			totalSize := int64(hdr.BasicHeaderSize) + 10 + int64(len(hdr.ExtendedHdr)) + int64(hdr.CompressedSize)
			buf := make([]byte, totalSize)
			if _, err := a.f.ReadAt(buf, headerStart); err != nil {
				return err
			}

			basicHdr := append([]byte{}, buf[4:4+int(hdr.BasicHeaderSize)]...)
			comp := append([]byte{}, buf[int64(hdr.BasicHeaderSize)+10+int64(len(hdr.ExtendedHdr)):]...)

			// Preserve the existing salt so the MAC stays valid.
			var existingSalt uint32
			if len(basicHdr) >= 38 {
				existingSalt = binary.LittleEndian.Uint32(basicHdr[34:38])
			}

			e := rawEntry{
				name:     hdr.Filename,
				baseHdr:  basicHdr,
				comp:     comp,
				salt:     existingSalt,
				dosTS:    hdr.Timestamp,
				origSize: hdr.OriginalSize,
				fileCRC:  hdr.CRC32,
				fileMode: hdr.FileAccessMode,
			}
			entries = insertSorted(entries, e)

			if _, err := a.f.Seek(int64(hdr.CompressedSize), io.SeekCurrent); err != nil {
				return err
			}
			a.pos += int64(hdr.CompressedSize)
		}
	}

	for _, in := range inputs {
		if skipNew[in.name] {
			continue
		}

		e, err := buildOneEntry(in.name, in.path, in.info, password, volumeLimitKB > 0)
		if err != nil {
			return fmt.Errorf("%s: %w", in.name, err)
		}
		entries = insertSorted(entries, e)

		mark := ""
		if password != "" {
			mark = " [encrypted+mac]"
		}
		fmt.Printf("  adding: %s (%d bytes)%s\n", in.name, in.info.Size(), mark)
	}

	if volumeLimitKB > 0 {
		return writeVolumes(archivePath, entries, password, volumeLimitKB)
	}

	tmpPath := archivePath + ".tmp"
	tmp, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	defer tmp.Close()

	if err := writeMainHeader(tmp, archivePath, password, false, true, false); err != nil {
		return fmt.Errorf("main header: %w", err)
	}
	for _, e := range entries {
		hdr := buildVolumeHdr(e, uint32(len(e.comp)), e.origSize, 0, true, false)
		ext := assembleExt(e, password)
		hdrBytes := assembleHdr(hdr, ext)
		if _, err := tmp.Write(hdrBytes); err != nil {
			return err
		}
		if _, err := tmp.Write(e.comp); err != nil {
			return err
		}
	}
	if err := writeEndHeader(tmp, false); err != nil {
		return err
	}
	tmp.Close()

	return os.Rename(tmpPath, archivePath)
}

func buildVolumeHdr(ra rawEntry, compSize, origSize, resumePos uint32,
	isFirst, hasNext bool) []byte {

	hdr := make([]byte, len(ra.baseHdr))
	copy(hdr, ra.baseHdr)

	var flags byte
	if hasNext {
		flags |= VOLUME_FLAG
	}
	if !isFirst {
		flags |= EXTFILE_FLAG
	}
	flags |= PATHSYM_FLAG
	flags |= ra.baseHdr[4] & GARBLED_FLAG
	hdr[4] = flags

	binary.LittleEndian.PutUint32(hdr[12:16], compSize)
	binary.LittleEndian.PutUint32(hdr[16:20], origSize)
	binary.LittleEndian.PutUint32(hdr[30:34], resumePos)

	return hdr
}

func assembleExt(ra rawEntry, password string) []byte {
	var extBuf bytes.Buffer
	if password != "" && ra.salt != 0 {
		_, macKey := deriveKeys(password, ra.salt)
		tag := hmacStreebog256(macKey, append(append([]byte{}, ra.baseHdr...), ra.comp...))
		block := make([]byte, 2+macTagLen)
		block[0] = extHdrID_MAC
		block[1] = 0
		copy(block[2:], tag)
		var szb [2]byte
		binary.LittleEndian.PutUint16(szb[:], uint16(len(block)))
		extBuf.Write(szb[:])
		extBuf.Write(block)
		var bcrc [4]byte
		binary.LittleEndian.PutUint32(bcrc[:], crc32.ChecksumIEEE(block))
		extBuf.Write(bcrc[:])
	}
	extBuf.Write([]byte{0, 0})
	return extBuf.Bytes()
}

func assembleHdr(hdr []byte, ext []byte) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x60, 0xEA})
	var sz [2]byte
	binary.LittleEndian.PutUint16(sz[:], uint16(len(hdr)))
	buf.Write(sz[:])
	buf.Write(hdr)
	var crc [4]byte
	binary.LittleEndian.PutUint32(crc[:], crc32.ChecksumIEEE(hdr))
	buf.Write(crc[:])
	buf.Write(ext)
	return buf.Bytes()
}

func writeVolumes(archivePath string, raws []rawEntry, password string,
	volumeLimitKB int) error {

	limit := int64(volumeLimitKB) * 1024

	totalChunks := 0
	totalComp := int64(0)
	for _, ra := range raws {
		totalChunks += len(ra.checkpoints) - 1
		totalComp += int64(len(ra.comp))
	}
	if totalChunks == 0 {
		return fmt.Errorf("nothing to write")
	}
	totalSize := totalComp + int64(totalChunks)*200
	numVolumes := int((totalSize + limit - 1) / limit)
	if numVolumes < 1 {
		numVolumes = 1
	}
	if enc4Debug {
		dbg4("VOL: totalChunks=%d totalComp=%d totalSize=%d numVolumes=%d",
			totalChunks, totalComp, totalSize, numVolumes)
	}

	volNum := 0
	path := volumePath(archivePath, volNum)

	cur, err := os.Create(path)
	if err != nil {
		return err
	}
	curSize := int64(0)

	var mhBuf bytes.Buffer
	hasNext := numVolumes > 1
	if err := writeMainHeader(&mhBuf, path, password, true, true, hasNext); err != nil {
		cur.Close()
		return fmt.Errorf("main header: %w", err)
	}
	if _, err := cur.Write(mhBuf.Bytes()); err != nil {
		cur.Close()
		return err
	}
	curSize += int64(mhBuf.Len())
	fmt.Printf("Creating archive  : %s\n", filepath.Base(path))

	closeAndOpenNext := func() error {
		if err := writeEndHeader(cur, true); err != nil {
			return err
		}
		if err := cur.Close(); err != nil {
			return err
		}
		volNum++
		path = volumePath(archivePath, volNum)
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		cur = f
		curSize = 0
		fmt.Printf("Creating archive  : %s\n", filepath.Base(path))
		nextHasNext := volNum < numVolumes-1
		var mh2 bytes.Buffer
		if err := writeMainHeader(&mh2, path, password, true, false, nextHasNext); err != nil {
			return err
		}
		if _, err := cur.Write(mh2.Bytes()); err != nil {
			return err
		}
		curSize += int64(mh2.Len())
		return nil
	}

	for _, ra := range raws {
		if len(ra.checkpoints) < 2 {
			cur.Close()
			return fmt.Errorf("%s: needs at least 2 checkpoints, got %d",
				ra.name, len(ra.checkpoints))
		}

		if enc4Debug {
			dbg4("VOL: %s: %d checkpoints, %d chunks",
				ra.name, len(ra.checkpoints), len(ra.checkpoints)-1)
		}

		compLen := int64(len(ra.comp))
		for i := range ra.checkpoints {
			if ra.checkpoints[i].compOffset < 0 {
				ra.checkpoints[i].compOffset = 0
			}
			if ra.checkpoints[i].compOffset > compLen {
				ra.checkpoints[i].compOffset = compLen
			}
			if ra.checkpoints[i].origOffset < 0 {
				ra.checkpoints[i].origOffset = 0
			}
			if ra.checkpoints[i].origOffset > int64(ra.origSize) {
				ra.checkpoints[i].origOffset = int64(ra.origSize)
			}
		}

		var encKey, macKey []byte
		if password != "" {
			encKey, macKey = deriveKeys(password, ra.salt)
		}

		chunkIdx := 0
		for chunkIdx < len(ra.checkpoints)-1 {
			isFirst := (chunkIdx == 0)
			resumePos := uint32(ra.checkpoints[chunkIdx].origOffset)
			compStart := ra.checkpoints[chunkIdx].compOffset

			nextIdx := chunkIdx + 1
			compEnd := ra.checkpoints[nextIdx].compOffset
			chunkSize := compEnd - compStart

			if chunkSize <= 0 {
				chunkIdx = nextIdx
				continue
			}

			isLast := (nextIdx == len(ra.checkpoints)-1)
			hasNextChunk := !isLast

			if enc4Debug {
				dbg4("VOL: %s chunk %d/%d: compStart=%d compEnd=%d isFirst=%v isLast=%v hasNext=%v",
					ra.name, chunkIdx, len(ra.checkpoints)-1,
					compStart, compEnd, isFirst, isLast, hasNextChunk)
			}

			chunkOrigSize := uint32(ra.checkpoints[nextIdx].origOffset) - resumePos

			// The last chunk carries the whole-file CRC32.
			chunkCRC := ra.checkpoints[chunkIdx].crc32
			if isLast {
				chunkCRC = ra.fileCRC
			}

			chunk := append([]byte{}, ra.comp[compStart:compEnd]...)

			var ext []byte
			if password != "" {
				iv := ra.salt ^ resumePos
				cipher := &ARJCrypt{}
				cipher.Init(encKey, iv)
				cipher.Encode(chunk)

				hdrForMAC := buildVolumeHdr(ra, uint32(chunkSize), chunkOrigSize, resumePos, isFirst, hasNextChunk)
				binary.LittleEndian.PutUint32(hdrForMAC[20:24], chunkCRC)
				binary.LittleEndian.PutUint32(hdrForMAC[34:38], ra.salt)

				tag := hmacStreebog256(macKey, append(append([]byte{}, hdrForMAC...), chunk...))
				block := make([]byte, 2+macTagLen)
				block[0] = extHdrID_MAC
				block[1] = 0
				copy(block[2:], tag)

				var buf bytes.Buffer
				var szb [2]byte
				binary.LittleEndian.PutUint16(szb[:], uint16(len(block)))
				buf.Write(szb[:])
				buf.Write(block)
				var bcrc [4]byte
				binary.LittleEndian.PutUint32(bcrc[:], crc32.ChecksumIEEE(block))
				buf.Write(bcrc[:])
				buf.Write([]byte{0, 0})
				ext = buf.Bytes()
			} else {
				ext = []byte{0, 0}
			}

			hdr := buildVolumeHdr(ra, uint32(chunkSize), chunkOrigSize, resumePos, isFirst, hasNextChunk)
			binary.LittleEndian.PutUint32(hdr[20:24], chunkCRC)
			binary.LittleEndian.PutUint32(hdr[34:38], ra.salt)

			hdrBytes := assembleHdr(hdr, ext)
			entrySize := int64(len(hdrBytes)) + int64(len(chunk))

			lastVolume := (volNum+1 >= numVolumes)
			if curSize+entrySize+MULTIVOLUME_RESERVE > limit {
				if !lastVolume && !isLast {
					if err := closeAndOpenNext(); err != nil {
						cur.Close()
						return err
					}
					if entrySize+MULTIVOLUME_RESERVE > limit {
						cur.Close()
						return fmt.Errorf("%s: chunk of %d bytes does not fit in volume size %d KB",
							ra.name, entrySize, volumeLimitKB)
					}
				}
			}

			if _, err := cur.Write(hdrBytes); err != nil {
				cur.Close()
				return err
			}
			if _, err := cur.Write(chunk); err != nil {
				cur.Close()
				return err
			}
			curSize += entrySize

			if isLast {
				fmt.Printf("Adding    %-27s\n", ra.name)
				chunkIdx = nextIdx
				break
			}

			chunkIdx = nextIdx
		}
	}

	if err := writeEndHeader(cur, false); err != nil {
		cur.Close()
		return err
	}
	return cur.Close()
}

func deleteARJ(archivePath string, patterns []string) error {
	if _, err := os.Stat(volumePath(archivePath, 1)); err == nil {
		return fmt.Errorf("delete not supported on multi-volume archives")
	}

	a, err := OpenARJ(archivePath)
	if err != nil {
		return err
	}
	defer a.Close()

	tmpPath := archivePath + ".tmp"
	tmp, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	defer tmp.Close()

	if err := writeMainHeader(tmp, archivePath, "", false, true, false); err != nil {
		return fmt.Errorf("main header: %w", err)
	}

	match := func(name string) bool {
		for _, p := range patterns {
			if ok, _ := filepath.Match(p, name); ok {
				return true
			}
		}
		return false
	}

	deleted := 0
	kept := 0

	for {
		hdr, err := a.Next()
		if err != nil {
			return err
		}
		if hdr == nil {
			break
		}

		if match(hdr.Filename) {
			if err := a.SkipData(hdr); err != nil {
				return err
			}
			fmt.Printf("  deleting: %s\n", hdr.Filename)
			deleted++
			continue
		}

		if err := copyFileEntry(a, tmp, hdr); err != nil {
			return fmt.Errorf("%s: %w", hdr.Filename, err)
		}
		kept++
	}

	if err := writeEndHeader(tmp, false); err != nil {
		return err
	}

	tmp.Close()
	a.Close()

	if err := os.Rename(tmpPath, archivePath); err != nil {
		return err
	}

	fmt.Printf("\n%d file(s) deleted, %d file(s) kept\n", deleted, kept)
	return nil
}

func copyFileEntry(a *ARJArchive, out io.Writer, hdr *ARJHeader) error {
	headerStart := hdr.DataOffset - int64(hdr.BasicHeaderSize) - 10 - int64(len(hdr.ExtendedHdr))
	totalSize := int64(hdr.BasicHeaderSize) + 10 + int64(len(hdr.ExtendedHdr)) + int64(hdr.CompressedSize)

	entryBuf := make([]byte, totalSize)
	if _, err := a.f.ReadAt(entryBuf, headerStart); err != nil {
		return err
	}

	if _, err := out.Write(entryBuf); err != nil {
		return err
	}

	if _, err := a.f.Seek(int64(hdr.CompressedSize), io.SeekCurrent); err != nil {
		return err
	}
	a.pos += int64(hdr.CompressedSize)

	return nil
}

func writeMainHeader(w io.Writer, archiveName string, password string,
	multiVolume bool, isFirstVolume bool, hasNextVolume bool) error {
	hdr := make([]byte, 0, 64)
	hdr = append(hdr, 34)
	hdr = append(hdr, 11)
	hdr = append(hdr, 1)
	hdr = append(hdr, 2)

	var flags byte
	if password != "" {
		flags = 0x11
	}
	if multiVolume {
		if hasNextVolume {
			flags |= PATHSYM_FLAG
		}
		if isFirstVolume {
			flags |= VOLUME_FLAG
		}
	}
	hdr = append(hdr, flags)
	hdr = append(hdr, 0)
	hdr = append(hdr, 2)
	hdr = append(hdr, 0)

	var ts [4]byte
	binary.LittleEndian.PutUint32(ts[:], dosTimestampFromTime(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)))
	hdr = append(hdr, ts[:]...)

	for i := 0; i < 12; i++ {
		hdr = append(hdr, 0)
	}
	hdr = append(hdr, 0, 0)
	hdr = append(hdr, 0, 0)
	hdr = append(hdr, 0, 0)
	hdr = append(hdr, 0, 0)
	hdr = append(hdr, 0, 0)

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

func writeEndHeader(w io.Writer, hasNext bool) error {
	var flags byte
	if hasNext {
		flags = VOLUME_FLAG
	}
	if _, err := w.Write([]byte{0x60, 0xEA, flags, 0}); err != nil {
		return err
	}
	return nil
}

func buildOneEntry(name, path string, info os.FileInfo, password string, multiVolume bool) (rawEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return rawEntry{}, err
	}

	dosTS := dosTimestampFromTime(info.ModTime())
	fileCRC := crc32.ChecksumIEEE(data)

	var salt [4]byte
	var saltVal uint32
	if password != "" {
		if _, err := rand.Read(salt[:]); err != nil {
			return rawEntry{}, err
		}
		saltVal = binary.LittleEndian.Uint32(salt[:])
	}

	var compressed bytes.Buffer
	enc := newEncState(&compressed, len(data))
	enc.in = data
	if err := enc.encodeF(multiVolume); err != nil {
		return rawEntry{}, fmt.Errorf("compress: %w", err)
	}
	comp := compressed.Bytes()
	enc.in = nil

	cps := make([]checkpoint, len(enc.checkpoints))
	copy(cps, enc.checkpoints)

	// Fallback to store (method 0) if compression expanded the data.
	method := byte(4)
	if len(comp) >= len(data) {
		comp = append([]byte{}, data...)
		cps = []checkpoint{
			{compOffset: 0, origOffset: 0, crc32: fileCRC},
			{compOffset: int64(len(data)), origOffset: int64(len(data)), crc32: 0},
		}
		method = 0
	}

	storedData := comp
	if password != "" && !multiVolume {
		encKey, _ := deriveKeys(password, saltVal)
		cipherText := make([]byte, len(comp))
		copy(cipherText, comp)
		cipher := &ARJCrypt{}
		// Single-volume: IV = salt, because ExtractFile decrypts
		// with iv = salt ^ ResumePosition and ResumePosition is 0.
		cipher.Init(encKey, saltVal)
		cipher.Encode(cipherText)
		storedData = cipherText
	}

	hdr := make([]byte, 0, 64)
	hdr = append(hdr, 46)
	hdr = append(hdr, 11)
	hdr = append(hdr, 1)
	hdr = append(hdr, 2)
	var f byte
	if password != "" {
		f |= 0x11
	}
	hdr = append(hdr, f)
	hdr = append(hdr, method)
	hdr = append(hdr, 0)
	hdr = append(hdr, ARJ_PMOD)

	var ts [4]byte
	binary.LittleEndian.PutUint32(ts[:], dosTS)
	hdr = append(hdr, ts[:]...)

	var csz [4]byte
	binary.LittleEndian.PutUint32(csz[:], uint32(len(storedData)))
	hdr = append(hdr, csz[:]...)

	var osz [4]byte
	binary.LittleEndian.PutUint32(osz[:], uint32(len(data)))
	hdr = append(hdr, osz[:]...)

	var crc [4]byte
	binary.LittleEndian.PutUint32(crc[:], fileCRC)
	hdr = append(hdr, crc[:]...)

	hdr = append(hdr, 0, 0)

	var mode [2]byte
	binary.LittleEndian.PutUint16(mode[:], uint16(info.Mode().Perm()))
	hdr = append(hdr, mode[:]...)

	hdr = append(hdr, 0, 0)

	hdr = append(hdr, 0, 0, 0, 0)

	var saltBytes [4]byte
	binary.LittleEndian.PutUint32(saltBytes[:], saltVal)
	hdr = append(hdr, saltBytes[:]...)

	var ctime [4]byte
	binary.LittleEndian.PutUint32(ctime[:], dosTS)
	hdr = append(hdr, ctime[:]...)

	hdr = append(hdr, 0, 0, 0, 0)

	hdr = append(hdr, []byte(name)...)
	hdr = append(hdr, 0)
	hdr = append(hdr, 0)

	return rawEntry{
		name:        name,
		baseHdr:     hdr,
		comp:        storedData,
		salt:        saltVal,
		dosTS:       dosTS,
		origSize:    uint32(len(data)),
		fileCRC:     fileCRC,
		fileMode:    uint16(info.Mode().Perm()),
		checkpoints: cps,
	}, nil
}
