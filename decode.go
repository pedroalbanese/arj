package main

// ===========================================================================
// ARJ decompression — port of decode.c (arj 3.10.22) — with token debug
// ===========================================================================

const (
	CODE_BIT   = 16
	CBIT       = 9
	TBIT       = 5
	PBIT       = 5
	NC         = 255
	NP         = 16
	NT         = 19
	CTABLESIZE = 4096
	PTABLESIZE = 256
	DICSIZ     = 26624
	FDICSIZ    = 26624
	THRESHOLD  = 3
	MAXMATCH   = 256
	NPT        = 19
	UCHAR_MAX  = 255
)

type arjError struct{ msg string }

func (e *arjError) Error() string { return e.msg }

var errBadTable = &arjError{"ARJ: bad Huffman table"}

type arjDecoder struct {
	bitbuf         uint32
	bitcount       int
	lastByte       byte
	in             []byte
	inPos          int
	fileGarbled    bool
	decText        []byte
	nText          []byte
	origSize       int64
	action         int
	cTable         [CTABLESIZE]uint16
	ptTable        [PTABLESIZE]uint16
	cLen           [NC]uint8
	ptLen          [NPT]uint8
	left           [2*NC - 1]uint16
	right          [2*NC - 1]uint16
	blocksize      int
	extractionStub func(data []byte, action int) bool
}

func newARJDecoder(compressed []byte, origSize int64, action int,
	extract func(data []byte, action int) bool) *arjDecoder {
	dbg4("newARJDecoder: compressed=%d bytes, origSize=%d", len(compressed), origSize)
	return &arjDecoder{
		in:             compressed,
		origSize:       origSize,
		action:         action,
		extractionStub: extract,
	}
}

func (d *arjDecoder) readByte() byte {
	if d.inPos >= len(d.in) {
		return 0
	}
	b := d.in[d.inPos]
	d.inPos++
	if d.fileGarbled {
		b = garbleDecodeByte(b)
	}
	return b
}

func garbleDecodeByte(b byte) byte { return b }

func (d *arjDecoder) fillbuf(n int) {
	for d.bitcount < n {
		d.bitbuf = (d.bitbuf << uint(d.bitcount)) |
			(uint32(d.lastByte) >> uint(8-d.bitcount))
		n -= d.bitcount
		d.lastByte = d.readByte()
		d.bitcount = 8
	}
	d.bitcount -= n
	d.bitbuf = ((d.bitbuf << uint(n)) | (uint32(d.lastByte) >> uint(8-n))) & 0xFFFF
	d.lastByte <<= uint(n)
}

func (d *arjDecoder) getbits(n int) int {
	rc := int(d.bitbuf >> uint(CODE_BIT-n))
	d.fillbuf(n)
	return rc
}

func (d *arjDecoder) makeTable(nchar int, bitlen []uint8, tablebits int,
	table []uint16, tablesize int) error {
	var count [17]uint16
	var weight [17]uint16
	var start [18]uint16

	for i := 1; i <= 16; i++ {
		count[i] = 0
	}
	for i := 0; i < nchar; i++ {
		if bitlen[i] > 16 {
			return errBadTable
		}
		count[bitlen[i]]++
	}
	start[1] = 0
	for i := 1; i <= 16; i++ {
		start[i+1] = start[i] + (count[i] << uint(16-i))
	}
	if start[17] != 0 {
		return errBadTable
	}

	jutbits := 16 - tablebits
	for i := 1; i <= tablebits; i++ {
		start[i] >>= uint(jutbits)
		weight[i] = 1 << uint(tablebits-i)
	}
	for i := tablebits + 1; i <= 16; i++ {
		weight[i] = 1 << uint(16-i)
	}
	i := int(start[tablebits+1] >> uint(jutbits))
	if i != 1<<uint(tablebits) {
		k := 1 << uint(tablebits)
		for i != k {
			table[i] = 0
			i++
		}
	}

	avail := uint16(nchar)
	mask := uint16(1 << uint(15-tablebits))

	for ch := 0; ch < nchar; ch++ {
		length := int(bitlen[ch])
		if length == 0 {
			continue
		}
		k := start[length]
		nextcode := k + weight[length]
		if length <= tablebits {
			if int(nextcode) > tablesize {
				return errBadTable
			}
			for i := int(start[length]); i < int(nextcode); i++ {
				table[i] = uint16(ch)
			}
		} else {
			p := &table[k>>uint(jutbits)]
			i := length - tablebits
			for i != 0 {
				if *p == 0 {
					d.right[avail] = 0
					d.left[avail] = 0
					*p = avail
					avail++
				}
				if k&mask != 0 {
					p = &d.right[*p]
				} else {
					p = &d.left[*p]
				}
				k <<= 1
				i--
			}
			*p = uint16(ch)
		}
		start[length] = nextcode
	}
	return nil
}

func (d *arjDecoder) readPTLen(nn, nbit, iSpecial int) error {
	n := d.getbits(nbit)
	if n == 0 {
		c := uint16(d.getbits(nbit))
		for i := 0; i < nn; i++ {
			d.ptLen[i] = 0
		}
		for i := 0; i < PTABLESIZE; i++ {
			d.ptTable[i] = c
		}
		return nil
	}

	i := 0
	if n >= NPT {
		n = NPT
	}
	for i < n && i < nn {
		c := int(d.bitbuf >> 13)
		if c == 7 {
			mask := uint32(1 << 12)
			for mask&d.bitbuf != 0 {
				mask >>= 1
				c++
			}
		}
		if c < 7 {
			d.fillbuf(3)
		} else {
			d.fillbuf(c - 3)
		}
		d.ptLen[i] = uint8(c)
		i++
		if i == iSpecial && i < nn {
			c = d.getbits(2)
			for c-1 >= 0 && i < nn {
				d.ptLen[i] = 0
				i++
				c--
			}
		}
	}
	for i < nn {
		d.ptLen[i] = 0
		i++
	}
	return d.makeTable(nn, d.ptLen[:], 8, d.ptTable[:], PTABLESIZE)
}

func (d *arjDecoder) readCLen() error {
	n := d.getbits(CBIT)
	if n == 0 {
		c := uint16(d.getbits(CBIT))
		for i := 0; i < NC; i++ {
			d.cLen[i] = 0
		}
		for i := 0; i < CTABLESIZE; i++ {
			d.cTable[i] = c
		}
		return nil
	}

	i := 0
	for i < n && i < NC {
		c := int(d.ptTable[d.bitbuf>>8])
		if c >= NT {
			mask := uint32(1 << 7)
			for {
				if d.bitbuf&mask != 0 {
					c = int(d.right[c])
				} else {
					c = int(d.left[c])
				}
				mask >>= 1
				if c < NT {
					break
				}
			}
		}
		d.fillbuf(int(d.ptLen[c]))
		if c <= 2 {
			switch c {
			case 0:
				c = 1
			case 1:
				c = d.getbits(4) + 3
			case 2:
				c = d.getbits(CBIT) + 20
			}
			for c-1 >= 0 && i < NC {
				d.cLen[i] = 0
				i++
				c--
			}
		} else {
			d.cLen[i] = uint8(c - 2)
			i++
		}
	}
	for i < NC {
		d.cLen[i] = 0
		i++
	}
	return d.makeTable(NC, d.cLen[:], 12, d.cTable[:], CTABLESIZE)
}

func (d *arjDecoder) decodeC() (uint16, error) {
	if d.blocksize == 0 {
		d.blocksize = d.getbits(CODE_BIT)
		if err := d.readPTLen(NT, TBIT, 3); err != nil {
			return 0, err
		}
		if err := d.readCLen(); err != nil {
			return 0, err
		}
		if err := d.readPTLen(NP, PBIT, -1); err != nil {
			return 0, err
		}
	}
	d.blocksize--

	j := d.cTable[d.bitbuf>>4]
	if j >= NC {
		mask := uint32(1 << 3)
		for {
			if d.bitbuf&mask != 0 {
				j = d.right[j]
			} else {
				j = d.left[j]
			}
			mask >>= 1
			if j < NC {
				break
			}
		}
	}
	d.fillbuf(int(d.cLen[j]))
	return j, nil
}

func (d *arjDecoder) decodeP() uint16 {
	j := d.ptTable[d.bitbuf>>8]
	if j >= NP {
		mask := uint32(1 << 7)
		for {
			if d.bitbuf&mask != 0 {
				j = d.right[j]
			} else {
				j = d.left[j]
			}
			mask >>= 1
			if j < NP {
				break
			}
		}
	}
	d.fillbuf(int(d.ptLen[j]))
	if j != 0 {
		j--
		j = (1 << uint(j)) + uint16(d.getbits(int(j)))
	}
	return j
}

func (d *arjDecoder) decode() error {
	d.decText = make([]byte, DICSIZ)
	d.blocksize = 0
	d.bitbuf = 0
	d.bitcount = 0
	d.lastByte = 0
	d.fillbuf(16)

	count := d.origSize
	r := 0

	for count > 0 {
		c, err := d.decodeC()
		if err != nil {
			return err
		}
		if c <= UCHAR_MAX {
			d.decText[r] = byte(c)
			count--
			r++
			if r >= DICSIZ {
				r = 0
				if d.extractionStub != nil && d.extractionStub(d.decText, d.action) {
					return nil
				}
			}
		} else {
			j := int(c) - (UCHAR_MAX + 1 - THRESHOLD)
			count -= int64(j)
			i := r - int(d.decodeP()) - 1
			if i < 0 {
				i += DICSIZ
			}
			if r > i && r < DICSIZ-MAXMATCH-1 {
				for ; j > 0; j-- {
					d.decText[r] = d.decText[i]
					r++
					i++
				}
			} else {
				for ; j > 0; j-- {
					d.decText[r] = d.decText[i]
					r++
					if r >= DICSIZ {
						r = 0
						if d.extractionStub != nil && d.extractionStub(d.decText, d.action) {
							return nil
						}
					}
					i++
					if i >= DICSIZ {
						i = 0
					}
				}
			}
		}
	}
	if r > 0 && d.extractionStub != nil {
		d.extractionStub(d.decText[:r], d.action)
	}
	return nil
}

func (d *arjDecoder) decodePtr() int {
	plus := 0
	pwr := 1 << 9
	width := 9
	for ; width < 13; width++ {
		if d.getbits(1) == 0 {
			break
		}
		plus += pwr
		pwr <<= 1
	}
	var c int
	if width != 0 {
		c = d.getbits(width)
	}
	c += plus
	return c
}

func (d *arjDecoder) decodeLen() int {
	plus := 0
	pwr := 1
	width := 0
	for ; width < 7; width++ {
		if d.getbits(1) == 0 {
			break
		}
		plus += pwr
		pwr <<= 1
	}
	var c int
	if width != 0 {
		c = d.getbits(width)
	}
	c += plus
	return c
}

func (d *arjDecoder) decodeF() error {
	if d.nText == nil {
		d.nText = make([]byte, FDICSIZ)
	}
	d.bitbuf = 0
	d.bitcount = 0
	d.lastByte = 0
	d.fillbuf(16)

	ncount := int64(0)
	r := 0
	for ncount < d.origSize {
		c := d.decodeLen()
		if c == 0 {
			// ▼▼▼ DEBUG: print literal token ▼▼▼
			if enc4Debug {
				dbg4("DEC: LIT %02X (ncount=%d)", d.bitbuf>>8, ncount)
			}
			// ▲▲▲ END DEBUG ▲▲▲
			ncount++
			d.nText[r] = byte(d.bitbuf >> 8)
			d.fillbuf(8)
			r++
			if r >= FDICSIZ {
				r = 0
				if d.extractionStub != nil && d.extractionStub(d.nText, d.action) {
					return nil
				}
			}
		} else {
			j := c - 1 + THRESHOLD
			ncount += int64(j)
			p := d.decodePtr()
			// ▼▼▼ DEBUG: print match token ▼▼▼
			if enc4Debug {
				dbg4("DEC: MATCH len=%d dicpos=%d (ncount=%d)", j, p, ncount)
			}
			// ▲▲▲ END DEBUG ▲▲▲
			i := r - int(p) - 1
			if i < 0 {
				i += FDICSIZ
			}
			for ; j > 0; j-- {
				d.nText[r] = d.nText[i]
				r++
				if r >= FDICSIZ {
					r = 0
					if d.extractionStub != nil && d.extractionStub(d.nText, d.action) {
						return nil
					}
				}
				i++
				if i >= FDICSIZ {
					i = 0
				}
			}
		}
	}
	if r > 0 && d.extractionStub != nil {
		d.extractionStub(d.nText[:r], d.action)
	}
	return nil
}
