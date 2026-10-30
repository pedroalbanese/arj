package main

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
)

const (
	ENC4_THRESHOLD = 3
	ENC4_UCHAR_MAX = 255
)

var enc4Debug = os.Getenv("ARJ_DEBUG") != ""

func dbg4(format string, a ...interface{}) {
	if enc4Debug {
		fmt.Fprintf(os.Stderr, format+"\n", a...)
	}
}

type checkpoint struct {
	compOffset int64
	origOffset int64
	crc32      uint32
}

type encState struct {
	bitbuf   uint32
	bitcount int
	outBuf   []byte
	outPos   int
	out      io.Writer

	tree      []byte
	dtree     []int16
	fpbuf     []int16
	dicbit    int
	fpcount   int
	fpMax     int
	treesize  int
	dicsizCur int
	dicpos    int
	tcPasses  int
	numchars  int

	in       []byte
	inPos    int
	origSize int

	compWritten  int64
	origConsumed int64
	checkpoints  []checkpoint
}

func newEncState(out io.Writer, origSize int) *encState {
	e := &encState{out: out, origSize: origSize}
	e.dicbit = 14
	e.numchars = 32
	e.dicsizCur = 15800
	e.treesize = 32768
	if origSize < 16384 {
		e.dicbit = 12
	}
	e.fpcount = 1 << e.dicbit
	e.fpMax = e.fpcount - 1
	e.tree = make([]byte, e.treesize+2)
	e.dtree = make([]int16, e.treesize+16)
	e.fpbuf = make([]int16, e.fpcount+4)
	e.tcPasses = 0
	e.checkpoints = make([]checkpoint, 0, 64)
	return e
}

func treeU16(t []byte, off int) uint16 {
	if off < 0 || off+2 > len(t) {
		panic(fmt.Sprintf("treeU16: off=%d len=%d", off, len(t)))
	}
	return binary.LittleEndian.Uint16(t[off:])
}

func safeTreeU16(t []byte, off int) (uint16, bool) {
	if off < 0 || off+2 > len(t) {
		return 0, false
	}
	return binary.LittleEndian.Uint16(t[off:]), true
}

func (e *encState) putbits(nC int, nX uint16) {
	pN := nC
	nC = 16 - nC
	nX <<= uint(nC)
	nC = e.bitcount
	e.bitbuf |= uint32(nX) >> uint(nC)
	nC += pN
	if nC < 8 {
		e.bitcount = nC
		return
	}
	bt := e.outPos
	if bt >= len(e.outBuf) {
		e.flushCompdata()
		bt = e.outPos
	}
	e.outBuf[bt] = byte(e.bitbuf >> 8)
	bt++
	nC -= 8
	if nC < 8 {
		e.bitbuf <<= 8
		e.outPos = bt
		e.bitcount = nC
		return
	}
	if bt >= len(e.outBuf) {
		e.outPos = bt
		e.flushCompdata()
		bt = e.outPos
	}
	e.outBuf[bt] = byte(e.bitbuf)
	bt++
	nC -= 8
	pN -= nC
	e.bitbuf = uint32(nX) << uint(pN)
	e.outPos = bt
	e.bitcount = nC
}

func (e *encState) flushCompdata() {
	if e.outPos > 0 {
		e.out.Write(e.outBuf[:e.outPos])
		e.compWritten += int64(e.outPos)
		e.outPos = 0
	}
}

func (e *encState) initPutbits() {
	e.bitcount = 0
	e.bitbuf = 0
	e.outPos = 0
	e.outBuf = make([]byte, 512)
	e.compWritten = 0
	e.origConsumed = 0
	e.checkpoints = e.checkpoints[:0]
}

func (e *encState) shutdownPutbits() {
	pad := (8 - e.bitcount%8) % 8
	if pad > 0 {
		e.putbits(pad, 0)
	}
	if e.outPos != 0 {
		e.flushCompdata()
	}
}

func (e *encState) flushCheckpoint() {
	if e.bitcount != 0 {
		return
	}
	if e.outPos != 0 {
		e.flushCompdata()
	}
	e.checkpoints = append(e.checkpoints, checkpoint{
		compOffset: e.compWritten,
		origOffset: e.origConsumed,
	})
}

func (e *encState) fillFpbuf() {
	for i := range e.fpbuf {
		e.fpbuf[i] = -1
	}
}

func (e *encState) updTree(nC int) int {
	dptr := e.dtree
	rBx := int(dptr[nC])
	rBp := 1
	if rBx < 0 {
		e.tcPasses = rBp
		return e.tcPasses
	}

	tptr := nC
	tdptr := rBx
	rAx := treeU16(e.tree, tptr)
	rDx := e.numchars
	if rDx-1 < 0 {
		e.tcPasses = rBp
		return e.tcPasses
	}
	rDx--

	var (
		prevTptr  int
		prevTdptr int
		remainder int
		diff      int
		v         uint16
		ok        bool
		v1        uint16
		ok1       bool
		v2        uint16
		ok2       bool
		c         int
	)

	goto utLoop

utFetch:
	v, ok = safeTreeU16(e.tree, tptr+rBp-1)
	if !ok {
		goto updFinish
	}
	rAx = v

	tdptr = rBp
	for {
		rDx--
		if rDx < 0 {
			goto updFinish
		}
		rBx = int(dptr[rBx])
		if rBx < 0 {
			goto updFinish
		}
		if rBx+tdptr-1 < 0 || rBx+tdptr-1+2 > len(e.tree) {
			goto updFinish
		}
		if rAx == treeU16(e.tree, tdptr+rBx-1) {
			break
		}
	}
	tdptr += rBx - rBp
	if tdptr < 0 || tdptr+2 > len(e.tree) {
		goto updFinish
	}
	if tdptr >= tptr {
		goto utFetch
	}

utLoop:
	if treeU16(e.tree, tptr) != treeU16(e.tree, tdptr) {
		goto selectPos
	}

	prevTptr = tptr
	prevTdptr = tdptr
	tptr += 2
	tdptr += 2
	for c = 128; c > 0; c-- {
		v1, ok1 = safeTreeU16(e.tree, tptr)
		v2, ok2 = safeTreeU16(e.tree, tdptr)
		if !ok1 || !ok2 {
			break
		}
		if v1 != v2 {
			break
		}
		tptr += 2
		tdptr += 2
	}
	if tdptr >= len(e.tree) || tptr >= len(e.tree) {
		goto updFinish
	}
	diff = int(e.tree[tdptr]) - int(e.tree[tptr])
	remainder = tdptr - prevTdptr
	if diff == 0 {
		remainder++
	}
	tptr = prevTptr
	tdptr = prevTdptr
	if tptr <= tdptr {
		goto updFinish
	}
	if remainder <= rBp {
		goto utFetch
	}
	if tptr-tdptr <= e.dicsizCur {
		e.dicpos = tptr - tdptr - 1
		rBp = remainder
		if rBp < 256 {
			goto utFetch
		}
	}
	rBp = remainder
	goto utFetch

selectPos:
	for {
		rDx--
		if rDx < 0 {
			goto updFinish
		}
		rBx = int(dptr[rBx])
		if rBx < 0 {
			goto updFinish
		}
		if rBx+tdptr-1 < 0 || rBx+tdptr-1+2 > len(e.tree) {
			goto updFinish
		}
		if rAx == treeU16(e.tree, tdptr+rBx-1) {
			break
		}
	}
	tdptr += rBx - rBp
	if tdptr < 0 || tdptr+2 > len(e.tree) {
		goto updFinish
	}
	if tdptr >= tptr {
		goto utFetch
	}
	goto utLoop

updFinish:
	if rBp > 256 {
		rBp = 256
	}
	e.tcPasses = rBp
	return e.tcPasses
}

func (e *encState) enc4Pass1(nC int) {
	rBx := 1
	rCx := 0
	for nC >= rBx {
		nC -= rBx
		rCx++
		rBx <<= 1
	}
	if rCx != 0 {
		e.putbits(rCx, 0xFFFF)
	}
	if rCx < 7 {
		rCx++
	}
	e.putbits(rCx, uint16(nC))
}

func (e *encState) enc4Pass2(nC int) {
	if nC < 0 {
		nC = 0
	}
	rBx := 1 << 9
	rCx := 9
	for nC >= rBx {
		nC -= rBx
		rCx++
		rBx <<= 1
	}
	if rCx != 9 {
		e.putbits(rCx-9, 0xFFFF)
	}
	if rCx < 13 {
		rCx++
	}
	e.putbits(rCx, uint16(nC))
}

// encodeF compresses e.in into e.out.
//
// For single-volume (multiVolume == false), the whole file is
// compressed as one continuous bit stream. shutdownPutbits is called
// only at the very end. This is what decodeF expects for a single
// entry, so the decompressed output matches the original.
//
// For multi-volume (multiVolume == true), the input is processed in
// chunks of e.treesize (32 KB). Each chunk restarts the LZ77
// dictionary and ends with shutdownPutbits, so every chunk is
// self-contained and can be placed in its own volume. A checkpoint
// with the chunk's CRC32 is recorded at the start of each chunk.
func (e *encState) encodeF(multiVolume bool) error {
	e.initPutbits()
	e.dicpos = 0
	e.tcPasses = 0

	hashBits := (e.dicbit + 2) / 3

	for e.inPos < len(e.in) {
		fetch := e.treesize
		if len(e.in)-e.inPos < fetch {
			fetch = len(e.in) - e.inPos
		}

		e.flushCheckpoint()
		chunkCRC := crc32.ChecksumIEEE(e.in[e.inPos : e.inPos+fetch])

		copy(e.tree, e.in[e.inPos:e.inPos+fetch])
		e.inPos += fetch

		e.fillFpbuf()
		for i := fetch; i < e.treesize; i++ {
			e.dtree[i] = -1
		}

		e.dicpos = 0
		e.tcPasses = 0

		rDx := uint16(e.tree[0])
		rCx := uint16(e.fpMax&0xFF00) | uint16(hashBits&0xFF)
		rDx <<= uint(hashBits & 0xFF)
		rDx ^= uint16(e.tree[1])
		rDx &= rCx | 0xFF

		tptr := 2
		for m := 0; m < fetch; m++ {
			rDx <<= uint(rCx & 0xFF)
			rDx ^= uint16(e.tree[tptr])
			tptr++
			rDx &= rCx & 0xFF
			t := e.fpbuf[rDx]
			e.fpbuf[rDx] = int16(m)
			e.dtree[m] = t
		}

		m := 0
		i := fetch
		for i > 0 {
			if m < 0 || m >= len(e.tree) {
				panic(fmt.Sprintf("encodeF: m=%d i=%d fetch=%d tcPasses=%d", m, i, fetch, e.tcPasses))
			}

			rAx := e.updTree(m)
			if rAx > i {
				rAx = i
				e.tcPasses = i
			}
			if rAx < ENC4_THRESHOLD {
				e.putbits(9, uint16(e.tree[m]))
				i--
				m++
				e.origConsumed++
			} else {
				if e.tcPasses <= 0 || e.tcPasses > i {
					e.putbits(9, uint16(e.tree[m]))
					i--
					m++
					e.origConsumed++
					continue
				}
				i -= e.tcPasses
				m += e.tcPasses
				e.origConsumed += int64(e.tcPasses)
				e.enc4Pass1(e.tcPasses - 2)
				e.enc4Pass2(e.dicpos)
			}
		}

		// Multi-volume: finish this chunk on a byte boundary so
		// the next chunk starts clean. Single-volume: keep the
		// stream continuous.
		if multiVolume {
			e.shutdownPutbits()
		}

		last := len(e.checkpoints) - 1
		e.checkpoints[last].crc32 = chunkCRC
	}

	if !multiVolume {
		e.shutdownPutbits()
	}

	e.checkpoints = append(e.checkpoints, checkpoint{
		compOffset: e.compWritten,
		origOffset: e.origConsumed,
		crc32:      0,
	})
	return nil
}

func (e *encState) resumePositionFor(target int64) uint32 {
	if len(e.checkpoints) == 0 {
		return 0
	}
	lo, hi := 0, len(e.checkpoints)
	for lo < hi {
		mid := (lo + hi) / 2
		if e.checkpoints[mid].compOffset <= target {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo == 0 {
		return uint32(e.checkpoints[0].origOffset)
	}
	return uint32(e.checkpoints[lo-1].origOffset)
}
