package main

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	HEADER_ID        = 0xEA60
	HEADER_ID_LO     = 0x60
	HEADER_ID_HI     = 0xEA
	FIRST_HDR_SIZE   = 30
	FIRST_HDR_SIZE_V = 34
	R9_HDR_SIZE      = 34
	STD_HDR_SIZE     = 30
	HEADERSIZE_MAX   = FIRST_HDR_SIZE + 10 + 260 + 2048

	GARBLED_FLAG   = 0x01
	VOLUME_FLAG    = 0x04
	EXTFILE_FLAG   = 0x08
	PATHSYM_FLAG   = 0x10
	BACKUP_FLAG    = 0x20
	SECURED_FLAG   = 0x40
	DUAL_NAME_FLAG = 0x80

	ARJT_BINARY    = 0
	ARJT_TEXT      = 1
	ARJT_COMMENT   = 2
	ARJT_DIR       = 3
	ARJT_LABEL     = 4
	ARJT_CHAPTER   = 5
	ARJT_UXSPECIAL = 6

	OS_DOS     = 0
	OS_UNIX    = 2
	OS_OS2     = 5
	OS_WIN95   = 10
	OS_WINNT   = 11
	OS_SPECIAL = 0xFFFF

	MAXMETHOD = 4
)

type ARJHeader struct {
	HeaderID        uint16
	BasicHeaderSize uint16
	FirstHdrSize    uint8
	Version         uint8
	MinVersion      uint8
	HostOS          uint8
	Flags           uint8
	Method          uint8
	FileType        uint8
	PasswordMod     uint8
	Timestamp       uint32
	CompressedSize  uint32
	OriginalSize    uint32
	CRC32           uint32
	EntryPos        uint16
	FileAccessMode  uint16

	ExtFlags      uint8
	ChapterNumber uint8

	ProtBlocks uint8
	ArjProtID  uint8
	HostData   uint16

	ResumePosition uint32
	ATime          uint32
	CTime          uint32

	IV uint32

	Filename    string
	Comment     string
	ExtendedHdr []byte

	RawBasicHdr []byte

	DataOffset int64

	ContinuedPrev bool
	ContinuedNext bool
}

func (h *ARJHeader) HasFlag(f uint8) bool { return h.Flags&f != 0 }
func (h *ARJHeader) IsMain() bool        { return h.FileType == ARJT_COMMENT && h.Filename == "" }

type ARJArchive struct {
    f        *os.File
    pos      int64
    mainHdr  *ARJHeader
    Password string

    basePath    string
    curVolNum   int
    multiVolume bool

    // Cache of derived keys, keyed by salt.
    keyCache map[uint32][2][]byte
}

func (a *ARJArchive) getKeys(salt uint32) (encKey, macKey []byte) {
    if a.keyCache == nil {
        a.keyCache = make(map[uint32][2][]byte)
    }
    if k, ok := a.keyCache[salt]; ok {
        return k[0], k[1]
    }
    encKey, macKey = deriveKeys(a.Password, salt)
    a.keyCache[salt] = [2][]byte{encKey, macKey}
    return encKey, macKey
}

func volumePath(basePath string, n int) string {
	if n == 0 {
		return basePath
	}
	dir := filepath.Dir(basePath)
	base := filepath.Base(basePath)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	return filepath.Join(dir, fmt.Sprintf("%s.a%02d", stem, n))
}

func OpenARJ(path string) (*ARJArchive, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	a := &ARJArchive{f: f, basePath: path, curVolNum: 0}
	hdr, err := a.readHeader(true)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("arj: main header: %w", err)
	}
	if hdr == nil {
		f.Close()
		return nil, fmt.Errorf("arj: empty archive")
	}
	a.mainHdr = hdr
	a.multiVolume = hdr.HasFlag(VOLUME_FLAG)
	return a, nil
}

func (a *ARJArchive) Close() error           { return a.f.Close() }
func (a *ARJArchive) MainHeader() *ARJHeader { return a.mainHdr }

func (a *ARJArchive) Next() (*ARJHeader, error) {
	for {
		hdr, err := a.readHeader(false)
		if err != nil {
			return nil, err
		}
		if hdr != nil {
			return hdr, nil
		}
		if !a.multiVolume {
			return nil, nil
		}
		nextPath := volumePath(a.basePath, a.curVolNum+1)
		if _, statErr := os.Stat(nextPath); statErr != nil {
			return nil, nil
		}
		if err := a.openNextVolume(); err != nil {
			return nil, err
		}
	}
}

func (a *ARJArchive) openNextVolume() error {
	next := a.curVolNum + 1
	path := volumePath(a.basePath, next)
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cannot open volume %s: %w", path, err)
	}
	a.f.Close()
	a.f = f
	a.curVolNum = next
	a.pos = 0

	mhdr, err := a.readHeader(true)
	if err != nil {
		return err
	}
	if mhdr == nil {
		return fmt.Errorf("empty volume %s", path)
	}
	return nil
}

func (a *ARJArchive) SkipData(hdr *ARJHeader) error {
	_, err := a.f.Seek(int64(hdr.CompressedSize), io.SeekCurrent)
	if err == nil {
		a.pos += int64(hdr.CompressedSize)
	}
	return err
}

func (a *ARJArchive) DataReader(hdr *ARJHeader) io.Reader {
	return io.LimitReader(a.f, int64(hdr.CompressedSize))
}

func (a *ARJArchive) readHeader(first bool) (*ARJHeader, error) {
	prefix := make([]byte, FIRST_HDR_SIZE)
	if _, err := io.ReadFull(a.f, prefix); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil, nil
		}
		return nil, err
	}

	hdrID := binary.LittleEndian.Uint16(prefix[0:2])
	if hdrID != HEADER_ID {
		return nil, fmt.Errorf("bad signature: 0x%04X (want 0x%04X)", hdrID, HEADER_ID)
	}

	basicHdrSize := binary.LittleEndian.Uint16(prefix[2:4])
	if basicHdrSize == 0 {
		return nil, nil
	}
	if basicHdrSize > HEADERSIZE_MAX {
		return nil, fmt.Errorf("header too large: %d", basicHdrSize)
	}

	remaining := int(basicHdrSize) - (FIRST_HDR_SIZE - 4)
	if remaining < 0 {
		return nil, fmt.Errorf("basic_hdr_size too small: %d", basicHdrSize)
	}
	rest := make([]byte, remaining)
	if _, err := io.ReadFull(a.f, rest); err != nil {
		return nil, err
	}

	basicHdr := append(append([]byte{}, prefix[4:]...), rest...)

	crcBuf := make([]byte, 4)
	if _, err := io.ReadFull(a.f, crcBuf); err != nil {
		return nil, err
	}
	storedCRC := binary.LittleEndian.Uint32(crcBuf)
	computedCRC := crc32.ChecksumIEEE(basicHdr)
	if storedCRC != computedCRC {
		return nil, fmt.Errorf("header CRC mismatch: stored 0x%08X, computed 0x%08X",
			storedCRC, computedCRC)
	}

	hdr := &ARJHeader{
		HeaderID:        hdrID,
		BasicHeaderSize: basicHdrSize,
		FirstHdrSize:    basicHdr[0],
		Version:         basicHdr[1],
		MinVersion:      basicHdr[2],
		HostOS:          basicHdr[3],
		Flags:           basicHdr[4],
		Method:          basicHdr[5],
		FileType:        basicHdr[6],
		PasswordMod:     basicHdr[7],
		Timestamp:       binary.LittleEndian.Uint32(basicHdr[8:12]),
		CompressedSize:  binary.LittleEndian.Uint32(basicHdr[12:16]),
		OriginalSize:    binary.LittleEndian.Uint32(basicHdr[16:20]),
		CRC32:           binary.LittleEndian.Uint32(basicHdr[20:24]),
		EntryPos:        binary.LittleEndian.Uint16(basicHdr[24:26]),
		FileAccessMode:  binary.LittleEndian.Uint16(basicHdr[26:28]),
		RawBasicHdr:     append([]byte{}, basicHdr...),
	}

	pos := 28
	if hdr.FirstHdrSize >= FIRST_HDR_SIZE_V {
		if pos+2 <= len(basicHdr) {
			hdr.ExtFlags = basicHdr[pos]
			hdr.ChapterNumber = basicHdr[pos+1]
			pos += 2
		}
	}

	if first {
		if hdr.FirstHdrSize >= FIRST_HDR_SIZE_V && pos+4 <= len(basicHdr) {
			hdr.ProtBlocks = basicHdr[pos]
			hdr.ArjProtID = basicHdr[pos+1]
			hdr.HostData = binary.LittleEndian.Uint16(basicHdr[pos+2:])
			pos += 4
		}
	} else {
		resumeOff := 28
		if hdr.FirstHdrSize >= FIRST_HDR_SIZE_V {
			resumeOff = 30
		}
		if resumeOff+4 <= len(basicHdr) {
			hdr.ResumePosition = binary.LittleEndian.Uint32(basicHdr[resumeOff : resumeOff+4])
		}

		if hdr.FirstHdrSize >= R9_HDR_SIZE {
			if resumeOff+16 <= len(basicHdr) {
				hdr.ATime = binary.LittleEndian.Uint32(basicHdr[resumeOff+4:])
				hdr.CTime = binary.LittleEndian.Uint32(basicHdr[resumeOff+8:])
			}
		}

		ivOff := resumeOff + 12
		if ivOff+4 <= len(basicHdr) {
			hdr.IV = binary.LittleEndian.Uint32(basicHdr[ivOff : ivOff+4])
		}

		hdr.ContinuedPrev = hdr.HasFlag(EXTFILE_FLAG)
		hdr.ContinuedNext = hdr.HasFlag(VOLUME_FLAG)
	}

	nameStart := int(hdr.FirstHdrSize)
	if nameStart < 0 || nameStart >= len(basicHdr) {
		return nil, fmt.Errorf("invalid FirstHdrSize: %d (basicHdr len=%d)",
			hdr.FirstHdrSize, len(basicHdr))
	}
	nameEnd := -1
	for i := nameStart; i < len(basicHdr); i++ {
		if basicHdr[i] == 0 {
			nameEnd = i
			break
		}
	}
	if nameEnd < 0 {
		return nil, fmt.Errorf("unterminated filename")
	}
	hdr.Filename = string(basicHdr[nameStart:nameEnd])

	commentStart := nameEnd + 1
	commentEnd := -1
	for i := commentStart; i < len(basicHdr); i++ {
		if basicHdr[i] == 0 {
			commentEnd = i
			break
		}
	}
	if commentEnd < 0 {
		return nil, fmt.Errorf("unterminated comment")
	}
	hdr.Comment = string(basicHdr[commentStart:commentEnd])

	ext, err := a.readExtendedHeaders()
	if err != nil {
		return nil, err
	}
	hdr.ExtendedHdr = ext

	cur, _ := a.f.Seek(0, io.SeekCurrent)
	hdr.DataOffset = cur
	a.pos = cur

	return hdr, nil
}

func (a *ARJArchive) readExtendedHeaders() ([]byte, error) {
	var all []byte
	for {
		var sizeBuf [2]byte
		if _, err := io.ReadFull(a.f, sizeBuf[:]); err != nil {
			if err == io.EOF {
				return all, nil
			}
			return nil, err
		}
		size := binary.LittleEndian.Uint16(sizeBuf[:])
		if size == 0 {
			return all, nil
		}
		block := make([]byte, size)
		if _, err := io.ReadFull(a.f, block); err != nil {
			return nil, err
		}
		var crcBuf [4]byte
		if _, err := io.ReadFull(a.f, crcBuf[:]); err != nil {
			return nil, err
		}
		stored := binary.LittleEndian.Uint32(crcBuf[:])
		computed := crc32.ChecksumIEEE(block)
		if stored != computed {
			return nil, fmt.Errorf("extended header CRC mismatch")
		}
		all = append(all, sizeBuf[:]...)
		all = append(all, block...)
		all = append(all, crcBuf[:]...)
	}
}

func extractMacTag(ext []byte) []byte {
	i := 0
	for i+2 <= len(ext) {
		size := int(binary.LittleEndian.Uint16(ext[i:]))
		if size == 0 {
			return nil
		}
		if i+2+size+4 > len(ext) {
			return nil
		}
		block := ext[i+2 : i+2+size]
		if size >= 2 && block[0] == extHdrID_MAC {
			tag := make([]byte, macTagLen)
			copy(tag, block[2:])
			return tag
		}
		i += 2 + size + 4
	}
	return nil
}

func (a *ARJArchive) ExtractFile(hdr *ARJHeader, out io.Writer) error {
	if hdr.CompressedSize == 0 {
		return nil
	}

	compressed := make([]byte, hdr.CompressedSize)
	if _, err := io.ReadFull(a.f, compressed); err != nil {
		return err
	}
	a.pos += int64(hdr.CompressedSize)

	if hdr.HasFlag(GARBLED_FLAG) {
		if a.Password == "" {
			return fmt.Errorf("encrypted file; use -gPASSWORD")
		}

		// Salt is stored in basicHdr[34:38] (the ATime field).
		var salt uint32
		if len(hdr.RawBasicHdr) >= 38 {
			salt = binary.LittleEndian.Uint32(hdr.RawBasicHdr[34:38])
		}
		iv := salt ^ hdr.ResumePosition
		encKey, macKey := a.getKeys(salt)

		tag := extractMacTag(hdr.ExtendedHdr)
		if tag == nil {
			return fmt.Errorf("missing MAC tag; file may be corrupted or tampered")
		}

		// Reconstruct the header exactly as writeVolumes did before MAC.
		hdrForMAC := append([]byte{}, hdr.RawBasicHdr...)
		binary.LittleEndian.PutUint32(hdrForMAC[20:24], hdr.CRC32)
		binary.LittleEndian.PutUint32(hdrForMAC[30:34], hdr.ResumePosition)
		binary.LittleEndian.PutUint32(hdrForMAC[34:38], salt)

		expected := hmacStreebog256(macKey, append(hdrForMAC, compressed...))
		if !hmac.Equal(tag, expected) {
			return fmt.Errorf("MAC verification failed; file was tampered with")
		}

		cipher := &ARJCrypt{}
		cipher.Init(encKey, iv)
		cipher.Decode(compressed)
	}

	if hdr.ResumePosition != 0 {
		if seeker, ok := out.(io.Seeker); ok {
			if _, err := seeker.Seek(int64(hdr.ResumePosition), io.SeekStart); err != nil {
				return err
			}
		}
	}

	extract := func(data []byte, _ int) bool {
		_, err := out.Write(data)
		return err != nil
	}

	switch hdr.Method {
	case 0:
		_, err := out.Write(compressed)
		return err
	case 1, 2, 3:
		d := newARJDecoder(compressed, int64(hdr.OriginalSize), 0, extract)
		return d.decode()
	case 4:
		d := newARJDecoder(compressed, int64(hdr.OriginalSize), 0, extract)
		return d.decodeF()
	default:
		return fmt.Errorf("arj: unsupported method %d", hdr.Method)
	}
}

func listARJ(path string) error {
	a, err := OpenARJ(path)
	if err != nil {
		return err
	}
	defer a.Close()

	mh := a.MainHeader()

	type entry struct {
		hdr  *ARJHeader
		size uint64
		date string
		time string
	}
	var entries []entry
	var maxSize uint64
	var total uint64

	// current is the entry being accumulated across chunks.
	var current *entry

	flushCurrent := func() {
		if current == nil {
			return
		}
		entries = append(entries, *current)
		if current.size > maxSize {
			maxSize = current.size
		}
		total += current.size
		current = nil
	}

	for {
		hdr, err := a.Next()
		if err != nil {
			return err
		}
		if hdr == nil {
			break
		}

		// Skip directory entries and non-file entries in the listing?
		// Keep them but do not merge.
		isContinuation := hdr.HasFlag(EXTFILE_FLAG) && current != nil && hdr.Filename == current.hdr.Filename

		if !isContinuation {
			flushCurrent()
			date, timeStr := dosTimestamp(hdr.Timestamp)
			current = &entry{
				hdr:  hdr,
				size: uint64(hdr.OriginalSize),
				date: date,
				time: timeStr,
			}
		} else {
			// Accumulate the chunk's OriginalSize.
			current.size += uint64(hdr.OriginalSize)
		}

		if !hdr.HasFlag(VOLUME_FLAG) {
			flushCurrent()
		}

		if err := a.SkipData(hdr); err != nil {
			return err
		}
	}
	flushCurrent()

	sizeWidth := len(fmt.Sprintf("%d", maxSize))
	if sizeWidth < 9 {
		sizeWidth = 9
	}

	fmt.Printf("Archive: %s\n", path)
	fmt.Printf("  Version: %d.%02d  Host OS: %d  Flags: 0x%02X\n",
		mh.Version/10, mh.Version%10, mh.HostOS, mh.Flags)
	fmt.Println()

	fmt.Printf("  %-*s  %-10s %-5s %-10s %s\n",
		sizeWidth, "Length", "Date", "Time", "Mode", "Name")
	fmt.Printf("  %s  %s %s %s %s\n",
		strings.Repeat("-", sizeWidth),
		strings.Repeat("-", 10),
		strings.Repeat("-", 5),
		strings.Repeat("-", 10),
		"----")

	for _, e := range entries {
		mode := formatFileMode(e.hdr.FileAccessMode)
		fmt.Printf("  %*d  %-10s %-5s %-10s %s\n",
			sizeWidth, e.size, e.date, e.time, mode, e.hdr.Filename)
	}

	fmt.Printf("  %s  %s %s %s %s\n",
		strings.Repeat("-", sizeWidth),
		strings.Repeat("-", 10),
		strings.Repeat("-", 5),
		strings.Repeat("-", 10),
		"-------")
	fmt.Printf("  %*d  %s %s %s %d files\n",
		sizeWidth, total,
		strings.Repeat(" ", 10),
		strings.Repeat(" ", 5),
		strings.Repeat(" ", 10),
		len(entries))

	return nil
}

func formatFileMode(mode uint16) string {
	if mode == 0 {
		return "----------"
	}
	perms := mode & 0o777
	var sb strings.Builder
	if perms&0o400 != 0 { sb.WriteByte('r') } else { sb.WriteByte('-') }
	if perms&0o200 != 0 { sb.WriteByte('w') } else { sb.WriteByte('-') }
	if perms&0o100 != 0 { sb.WriteByte('x') } else { sb.WriteByte('-') }
	if perms&0o040 != 0 { sb.WriteByte('r') } else { sb.WriteByte('-') }
	if perms&0o020 != 0 { sb.WriteByte('w') } else { sb.WriteByte('-') }
	if perms&0o010 != 0 { sb.WriteByte('x') } else { sb.WriteByte('-') }
	if perms&0o004 != 0 { sb.WriteByte('r') } else { sb.WriteByte('-') }
	if perms&0o002 != 0 { sb.WriteByte('w') } else { sb.WriteByte('-') }
	if perms&0o001 != 0 { sb.WriteByte('x') } else { sb.WriteByte('-') }
	return sb.String()
}

func dosTimestamp(ts uint32) (string, string) {
	sec := int(ts&0x1F) * 2
	min := int((ts >> 5) & 0x3F)
	hour := int((ts >> 11) & 0x1F)
	day := int((ts >> 16) & 0x1F)
	month := int((ts >> 21) & 0x0F)
	year := int((ts>>25)&0x7F) + 1980
	_ = sec
	return fmt.Sprintf("%04d-%02d-%02d", year, month, day),
		fmt.Sprintf("%02d:%02d", hour, min)
}
