// Package nfqueue gives Go bindings for the NFQUEUE netfilter target
// libnetfilter_queue is a userspace library providing an API to access packets
// that have been queued by the Linux kernel packet filter.
//
// This provides an easy way to filter packets from userspace, and use tools
// or libraries that are not accessible from kernelspace.
package nfqueue

// #cgo pkg-config: libnetfilter_queue
// #include <netfilter.h>
import "C"

import (
	"errors"
	"unsafe"
)

// ErrNotInitialized means queue is not initialized
var ErrNotInitialized = errors.New("nfqueue: queue not initialized")

// ErrOpenFailed means nfqueue open failed
var ErrOpenFailed = errors.New("nfqueue: open failed")

// ErrRuntime means runtime error
var ErrRuntime = errors.New("nfqueue: runtime error")

// NFDrop flag
var NFDrop = C.NF_DROP

// NFAccept flag
var NFAccept = C.NF_ACCEPT

// NFQueue flag
var NFQueue = C.NF_QUEUE

// NFRepeat flag
var NFRepeat = C.NF_REPEAT

// NFStop flag
var NFStop = C.NF_STOP

// NFQNLCopyNone flag
var NFQNLCopyNone = uint8(C.NFQNL_COPY_NONE)

// NFQNLCopyMeta flag
var NFQNLCopyMeta = uint8(C.NFQNL_COPY_META)

// NFQNLCopyPacket flag
var NFQNLCopyPacket = uint8(C.NFQNL_COPY_PACKET)

// Callback receives the NFQUEUE ID of the packet, and the packet payload.
// Packet data start from the IP layer (ethernet information are not included).
// It must return the verdict for the packet.
type Callback func(*Payload)

// Queue is an opaque structure describing a connection to a kernel NFQUEUE,
// and the associated Go callback.
type Queue struct {
	cH  (*C.struct_nfq_handle)
	cQh (*C.struct_nfq_q_handle)

	cb Callback
}

// Init creates a netfilter queue which can be used to receive packets
// from the kernel.
func (q *Queue) Init() error {
	q.cH = C.nfq_open()

	if q.cH == nil {
		return ErrOpenFailed
	}

	return nil
}

// SetCallback sets the callback function, fired when a packet is received.
func (q *Queue) SetCallback(cb Callback) error {
	q.cb = cb
	return nil
}

// Close closes netfilter queue
func (q *Queue) Close() {
	if q.cH != nil {
		C.nfq_close(q.cH)
		q.cH = nil
	}
}

// Bind binds a Queue to a given protocol family.
//
// Usually, the family is syscall.AF_INET for IPv4, and syscall.AF_INET6 for IPv6
func (q *Queue) Bind(afFamily int) error {
	if q.cH == nil {
		return ErrNotInitialized
	}

	/* Errors in nfq_bind_pf are non-fatal ...
	 * This function just tells the kernel that nfnetlink_queue is
	 * the chosen module to queue packets to userspace.
	 */
	_ = C.nfq_bind_pf(q.cH, C.u_int16_t(afFamily))

	return nil
}

// Unbind a queue from the given protocol family.
//
// Note that errors from this function can usually be ignored.
func (q *Queue) Unbind(afFamily int) error {
	if q.cH == nil {
		return ErrNotInitialized
	}

	rc := C.nfq_unbind_pf(q.cH, C.u_int16_t(afFamily))

	if rc < 0 {
		return ErrRuntime
	}

	return nil
}

// CreateQueue creates a new queue handle
// The queue must be initialized (using Init) and bound (using Bind), and
// a callback function must be set (using SetCallback).
func (q *Queue) CreateQueue(queueNum int) error {
	if q.cH == nil {
		return ErrNotInitialized
	}

	if q.cb == nil {
		return ErrNotInitialized
	}

	q.cQh = C.nfq_create_queue(q.cH, C.u_int16_t(queueNum), (*C.nfq_callback)(C.c_nfq_cb), unsafe.Pointer(q))

	if q.cQh == nil {
		return ErrRuntime
	}

	// Default mode
	C.nfq_set_mode(q.cQh, C.NFQNL_COPY_PACKET, 0xffff)

	return nil
}

// SetMode sets the amount of packet data that nfqueue copies to userspace
//
// Default mode is NFQNL_COPY_PACKET
func (q *Queue) SetMode(mode uint8) error {
	if q.cH == nil {
		return ErrNotInitialized
	}

	if q.cQh == nil {
		return ErrNotInitialized
	}

	C.nfq_set_mode(q.cQh, C.u_int8_t(mode), 0xffff)

	return nil
}

func (q *Queue) SetNoEnobufs() {
	var value int = 1
	C.setsockopt(C.nfq_fd(q.cH), C.SOL_NETLINK, C.NETLINK_NO_ENOBUFS, unsafe.Pointer(&value), C.sizeof_int)
}

func (q *Queue) SetBufferSize(size uint32) {
	C.nfnl_rcvbufsiz(C.nfq_nfnlh(q.cH), C.uint(size))
}

func (q *Queue) SetQueueMaxlen(size uint32) {
	C.nfq_set_queue_maxlen(q.cQh, C.u_int32_t(size))
}

// TryRun starts an infinite loop, receiving kernel events
// and processing packets using the callback function.
//
// BUG(TryRun): The TryRun function really is an infinite loop.
func (q *Queue) TryRun() error {
	if q.cH == nil {
		return ErrNotInitialized
	}

	if q.cQh == nil {
		return ErrNotInitialized
	}

	if q.cb == nil {
		return ErrNotInitialized
	}

	fd := C.nfq_fd(q.cH)

	if fd < 0 {
		return ErrRuntime
	}

	// XXX
	result := C._process_loop(q.cH, fd, 0)

	if result < 0 {
		return ErrRuntime
	}

	return nil
}

// Payload is a structure describing a packet received from the kernel
type Payload struct {
	cQh  (*C.struct_nfq_q_handle)
	nfad *C.struct_nfq_data

	ID   uint32 // NFQueue ID of the packet
	Data []byte // Packet data
}

func buildPayload(cQh *C.struct_nfq_q_handle, ptrNfad *unsafe.Pointer) *Payload {
	var payloadData *C.uchar
	var data []byte

	nfad := (*C.struct_nfq_data)(unsafe.Pointer(ptrNfad))

	ph := C.nfq_get_msg_packet_hdr(nfad)
	id := C.ntohl(C.uint32_t(ph.packet_id))
	payloadLen := C.nfq_get_payload(nfad, &payloadData)

	if payloadLen >= 0 {
		data = C.GoBytes(unsafe.Pointer(payloadData), C.int(payloadLen))
	}

	p := new(Payload)
	p.cQh = cQh
	p.nfad = nfad
	p.ID = uint32(id)
	p.Data = data

	return p
}

// SetVerdict issues a verdict for a packet.
//
// Every queued packet _must_ have a verdict specified by userspace.
func (p *Payload) SetVerdict(verdict int) error {
	C.nfq_set_verdict(p.cQh, C.u_int32_t(p.ID), C.u_int32_t(verdict), 0, nil)

	return nil
}

// SetVerdictModified issues a verdict for a packet, but replaces the packet
// with the provided one.
//
// Every queued packet _must_ have a verdict specified by userspace.
func (p *Payload) SetVerdictModified(verdict int, data []byte) error {
	C.nfq_set_verdict(
		p.cQh,
		C.u_int32_t(p.ID),
		C.u_int32_t(verdict),
		C.u_int32_t(len(data)),
		(*C.uchar)(unsafe.Pointer(&data[0])),
	)

	return nil
}

// SetVerdictMark issues a verdict for a packet, but a mark can be set
//
// Every queued packet _must_ have a verdict specified by userspace.
func (p *Payload) SetVerdictMark(verdict int, mark uint32) error {
	C.nfq_set_verdict2(
		p.cQh,
		C.u_int32_t(p.ID),
		C.u_int32_t(verdict),
		C.u_int32_t(mark),
		0, nil,
	)

	return nil
}

// SetVerdictMarkModified issues a verdict for a packet, but replaces the
// packet with the provided one, and a mark can be set.
//
// Every queued packet _must_ have a verdict specified by userspace.
func (p *Payload) SetVerdictMarkModified(verdict int, mark uint32, data []byte) error {
	C.nfq_set_verdict2(
		p.cQh,
		C.u_int32_t(p.ID),
		C.u_int32_t(verdict),
		C.u_int32_t(mark),
		C.u_int32_t(len(data)),
		(*C.uchar)(unsafe.Pointer(&data[0])),
	)

	return nil
}

// GetNFMark returns the packet mark
func (p *Payload) GetNFMark() uint32 {
	return uint32(C.nfq_get_nfmark(p.nfad))
}

// GetInDev returns the interface that the packet was received through
func (p *Payload) GetInDev() uint32 {
	return uint32(C.nfq_get_indev(p.nfad))
}

// GetOutDev returns the interface that the packet will be routed out
func (p *Payload) GetOutDev() uint32 {
	return uint32(C.nfq_get_outdev(p.nfad))
}

// GetPhysInDev returns the physical interface that the packet was received through
func (p *Payload) GetPhysInDev() uint32 {
	return uint32(C.nfq_get_physindev(p.nfad))
}

// GetPhysOutDev returns the physical interface that the packet will be routed out
func (p *Payload) GetPhysOutDev() uint32 {
	return uint32(C.nfq_get_physoutdev(p.nfad))
}
