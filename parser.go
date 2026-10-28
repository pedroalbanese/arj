package main

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"strings"
)

// ===========================================================================
// Constants from defines.h
// ===========================================================================

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

// ===========================================================================
// Parsed header
// ===========================================================================

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

	Filename    string
	Comment     string
	ExtendedHdr []byte

	DataOffset int64
}

func (h *ARJHeader) HasFlag(f uint8) bool { return h.Flags&f != 0 }
func (h *ARJHeader) IsMain() bool        { return h.FileType == ARJT_COMMENT && h.Filename == "" }

// ===========================================================================
// ARJArchive
// ===========================================================================

type ARJArchive struct {
	f        *os.File
	pos      int64
	mainHdr  *ARJHeader
	Password string
}

func OpenARJ(path string) (*ARJArchive, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	a := &ARJArchive{f: f}
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
	return a, nil
}

func (a *ARJArchive) Close() error           { return a.f.Close() }
func (a *ARJArchive) MainHeader() *ARJHeader { return a.mainHdr }

func (a *ARJArchive) Next() (*ARJHeader, error) {
	return a.readHeader(false)
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
		if hdr.FirstHdrSize < R9_HDR_SIZE {
			if hdr.HasFlag(EXTFILE_FLAG) && pos+4 <= len(basicHdr) {
				hdr.ResumePosition = binary.LittleEndian.Uint32(basicHdr[pos:])
				pos += 4
			}
		} else {
			if pos+16 <= len(basicHdr) {
				hdr.ResumePosition = binary.LittleEndian.Uint32(basicHdr[pos:])
				hdr.ATime = binary.LittleEndian.Uint32(basicHdr[pos+4:])
				hdr.CTime = binary.LittleEndian.Uint32(basicHdr[pos+8:])
				pos += 16
			}
		}
	}

	// O filename começa no offset first_hdr_size do header local.
	// O basicHdr começa no offset 0x04 do arquivo, então o filename está em
	// basicHdr[first_hdr_size - 4].
	// O main.go grava first_hdr_size = 46 (offset do filename no header local).
	// O filename está em basicHdr[46 - 4] = basicHdr[42].
	nameStart := int(hdr.FirstHdrSize)
	if nameStart < 0 || nameStart >= len(basicHdr) {
		return nil, fmt.Errorf("invalid FirstHdrSize: %d", hdr.FirstHdrSize)
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

// ===========================================================================
// Extraction
// ===========================================================================

func (a *ARJArchive) ExtractFile(hdr *ARJHeader, out io.Writer) error {
	if hdr.CompressedSize == 0 {
		return nil
	}

	compressed := make([]byte, hdr.CompressedSize)
	if _, err := io.ReadFull(a.f, compressed); err != nil {
		return err
	}
	a.pos += int64(hdr.CompressedSize)

	// Descriptografia GOST (se o arquivo estiver marcado como GARBLED).
	// O modifier é {timestamp, password_mod} — o mesmo que o encrypt usa.
	if hdr.HasFlag(GARBLED_FLAG) {
		if a.Password == "" {
			return fmt.Errorf("encrypted file; use -gPASSWORD")
		}
		modifier := buildModifier(hdr.Timestamp, hdr.PasswordMod)
		cipher := &ARJCrypt{}
		cipher.Init(a.Password, modifier)
		cipher.Decode(compressed)
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

// ===========================================================================
// Listing
// ===========================================================================

func listARJ(path string) error {
	a, err := OpenARJ(path)
	if err != nil {
		return err
	}
	defer a.Close()

	mh := a.MainHeader()

	// Primeira passada: coleta os headers e calcula a largura máxima do tamanho.
	type entry struct {
		hdr  *ARJHeader
		date string
		time string
	}
	var entries []entry
	var maxSize uint64
	var total uint64

	for {
		hdr, err := a.Next()
		if err != nil {
			return err
		}
		if hdr == nil {
			break
		}
		date, timeStr := dosTimestamp(hdr.Timestamp)
		entries = append(entries, entry{hdr: hdr, date: date, time: timeStr})
		if uint64(hdr.OriginalSize) > maxSize {
			maxSize = uint64(hdr.OriginalSize)
		}
		total += uint64(hdr.OriginalSize)
		if err := a.SkipData(hdr); err != nil {
			return err
		}
	}

	// Calcula a largura: número de dígitos do maior tamanho (mínimo 9).
	sizeWidth := len(fmt.Sprintf("%d", maxSize))
	if sizeWidth < 9 {
		sizeWidth = 9
	}

	// Segunda passada: imprime com a largura calculada.
	fmt.Printf("Archive: %s\n", path)
	fmt.Printf("  Version: %d.%02d  Host OS: %d  Flags: 0x%02X\n",
		mh.Version/10, mh.Version%10, mh.HostOS, mh.Flags)
	fmt.Println()

	// Cabeçalho alinhado
	fmt.Printf("  %-*s  %-10s %-5s   %s\n",
		sizeWidth, "Length", "Date", "Time", "Name")
	fmt.Printf("  %s  %s %s   %s\n",
		strings.Repeat("-", sizeWidth),
		strings.Repeat("-", 10),
		strings.Repeat("-", 5),
		"----")

	for _, e := range entries {
		fmt.Printf("  %*d  %-10s %-5s   %s\n",
			sizeWidth, e.hdr.OriginalSize, e.date, e.time, e.hdr.Filename)
	}

	// Rodapé alinhado
	fmt.Printf("  %s  %s %s   %s\n",
		strings.Repeat("-", sizeWidth),
		strings.Repeat("-", 10),
		strings.Repeat("-", 5),
		"-------")
	fmt.Printf("  %*d  %s %s   %d files\n",
		sizeWidth, total,
		strings.Repeat(" ", 10),
		strings.Repeat(" ", 5),
		len(entries))

	return nil
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
