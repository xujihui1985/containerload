package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net/http"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

type Connection struct {
	fd   int
	pid  uint32
	seq  uint32
	addr syscall.SockaddrNetlink
	rbuf *bufio.Reader
}

func (c *Connection) Write(p []byte) (n int, err error) {
	err = syscall.Sendto(c.fd, p, 0, &c.addr)
	return len(p), err
}

func (c *Connection) Read(p []byte) (n int, err error) {
	n, _, err = syscall.Recvfrom(c.fd, p, 0)
	return n, err
}

func (c *Connection) Close() error {
	return syscall.Close(c.fd)
}

func (c *Connection) WriteMessage(msg syscall.NetlinkMessage) error {
	w := bytes.NewBuffer(nil)
	msg.Header.Len = uint32(syscall.NLMSG_HDRLEN + len(msg.Data))
	msg.Header.Seq = c.seq
	c.seq++
	// msg.Header.Pid = c.pid
	err := binary.Write(w, binary.LittleEndian, msg.Header)
	if err != nil {
		return err
	}
	_, err = w.Write(msg.Data)
	if err != nil {
		return err
	}
	_, err = c.Write(w.Bytes())
	return err
}

func (c *Connection) ReadMessage() (syscall.NetlinkMessage, error) {
	var msg syscall.NetlinkMessage
	err := binary.Read(c.rbuf, binary.LittleEndian, &msg.Header)
	if err != nil {
		return msg, err
	}
	msg.Data = make([]byte, msg.Header.Len-syscall.NLMSG_HDRLEN)
	_, err = c.rbuf.Read(msg.Data)
	return msg, err
}

func newConnection() (*Connection, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM, syscall.NETLINK_GENERIC)
	if err != nil {
		return nil, err
	}
	conn := Connection{
		fd:  fd,
		pid: 0,
		seq: uint32(os.Getegid()),
		addr: syscall.SockaddrNetlink{
			Family: syscall.AF_NETLINK,
		},
	}
	conn.rbuf = bufio.NewReader(&conn)
	err = syscall.Bind(fd, &conn.addr)
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return &conn, err
}

type genMsghdr struct {
	Command  uint8
	Version  uint8
	Reserved uint16
}

type netlinkMessage struct {
	Header    syscall.NlMsghdr
	GenHeader genMsghdr
	Data      []byte
}

// Return required padding to align 'size' to 'alignment'.
func padding(size int, alignment int) int {
	unalignedPart := size % alignment
	return (alignment - unalignedPart) % alignment
}

func addAttribute(buf *bytes.Buffer, attrType uint16, data interface{}, dataSize int) {
	http.DefaultClient.Get()
	attr := syscall.RtAttr{
		Len:  syscall.SizeofRtAttr,
		Type: attrType,
	}
	attr.Len += uint16(dataSize)
	binary.Write(buf, binary.LittleEndian, attr)
	switch data := data.(type) {
	case string:
		binary.Write(buf, binary.LittleEndian, []byte(data))
		buf.WriteByte(0) // terminate
	default:
		binary.Write(buf, binary.LittleEndian, data)
	}
	for i := 0; i < padding(int(attr.Len), syscall.NLMSG_ALIGNTO); i++ {
		buf.WriteByte(0)
	}
}

// Prepares the message and generic headers and appends attributes as data.
func prepareMessage(headerType uint16, cmd uint8, attributes []byte) (msg netlinkMessage) {
	msg.Header.Type = headerType
	msg.Header.Flags = syscall.NLM_F_REQUEST
	msg.GenHeader.Command = cmd
	msg.GenHeader.Version = 0x1
	msg.Data = attributes
	return msg
}

func (m netlinkMessage) toRawMsg() (rawmsg syscall.NetlinkMessage) {
	rawmsg.Header = m.Header
	w := bytes.NewBuffer([]byte{})
	binary.Write(w, binary.LittleEndian, m.GenHeader)
	w.Write(m.Data)
	rawmsg.Data = w.Bytes()
	return rawmsg
}

func prepareFamilyMessage() (msg netlinkMessage) {
	buf := bytes.NewBuffer([]byte{})
	addAttribute(buf, unix.CTRL_ATTR_FAMILY_NAME, unix.TASKSTATS_GENL_NAME, len(unix.TASKSTATS_GENL_NAME)+1)
	return prepareMessage(unix.GENL_ID_CTRL, unix.CTRL_CMD_GETFAMILY, buf.Bytes())
}

func verifyHeader(msg syscall.NetlinkMessage) error {
	switch msg.Header.Type {
	case syscall.NLMSG_DONE:
		return fmt.Errorf("expected a response, got nil")
	case syscall.NLMSG_ERROR:
		buf := bytes.NewBuffer(msg.Data)
		var errno int32
		err := binary.Read(buf, binary.LittleEndian, errno)
		if err != nil {
			return err
		}
		return fmt.Errorf("netlink request failed with error %s", syscall.Errno(-errno))
	}
	return nil
}

func parseFamilyResp(msg syscall.NetlinkMessage) (uint16, error) {
	m := new(netlinkMessage)
	m.Header = msg.Header
	err := verifyHeader(msg)
	if err != nil {
		return 0, err
	}
	buf := bytes.NewBuffer(msg.Data)
	// extract generic header from data.
	err = binary.Read(buf, binary.LittleEndian, &m.GenHeader)
	if err != nil {
		return 0, err
	}
	id := uint16(0)
	// Extract attributes. kernel reports family name, id, version, etc.
	// Scan till we find id.
	for buf.Len() > syscall.SizeofRtAttr {
		var attr syscall.RtAttr
		err = binary.Read(buf, binary.LittleEndian, &attr)
		if err != nil {
			return 0, err
		}
		if attr.Type == unix.CTRL_ATTR_FAMILY_ID {
			err = binary.Read(buf, binary.LittleEndian, &id)
			if err != nil {
				return 0, err
			}
			return id, nil
		}
		payload := int(attr.Len) - syscall.SizeofRtAttr
		skipLen := payload + padding(payload, syscall.SizeofRtAttr)
		name := make([]byte, skipLen)
		err = binary.Read(buf, binary.LittleEndian, name)
		if err != nil {
			return 0, err
		}
	}
	return 0, fmt.Errorf("family id not found in the response")
}

func getFamilyID(conn *Connection) (uint16, error) {
	msg := prepareFamilyMessage()
	err := conn.WriteMessage(msg.toRawMsg())
	if err != nil {
		return 0, err
	}
	resp, err := conn.ReadMessage()
	if err != nil {
		return 0, err
	}
	id, err := parseFamilyResp(resp)
	if err != nil {
		return 0, err
	}
	return id, nil
}

type NetLinkReader struct {
	familyID uint16
	conn     *Connection
}

func NewNetLinkReader() (*NetLinkReader, error) {
	conn, err := newConnection()
	if err != nil {
		return nil, err
	}
	id, err := getFamilyID(conn)
	if err != nil {
		return nil, err
	}
	return &NetLinkReader{
		familyID: id,
		conn:     conn,
	}, nil
}

type LoadStats struct {
	// Number of sleeping tasks.
	NrSleeping uint64 `json:"nr_sleeping"`

	// Number of running tasks.
	NrRunning uint64 `json:"nr_running"`

	// Number of tasks in stopped state
	NrStopped uint64 `json:"nr_stopped"`

	// Number of tasks in uninterruptible state
	NrUninterruptible uint64 `json:"nr_uninterruptible"`

	// Number of tasks waiting on IO
	NrIoWait uint64 `json:"nr_io_wait"`
}

func (r *NetLinkReader) GetCpuLoad(path string) (LoadStats, error) {
	if len(path) == 0 {
		return LoadStats{}, fmt.Errorf("cgroup path can not be empty")
	}

	cfd, err := os.Open(path)
	if err != nil {
		return LoadStats{}, fmt.Errorf("failed to open cgroup path %s: %q", path, err)
	}
	defer cfd.Close()

	stats, err := getLoadStats(r.familyID, cfd, r.conn)
	if err != nil {
		return LoadStats{}, err
	}
	return stats, nil
}

func prepareCmdMessage(id uint16, cfd uintptr) (msg netlinkMessage) {
	buf := bytes.NewBuffer([]byte{})
	addAttribute(buf, unix.CGROUPSTATS_CMD_ATTR_FD, uint32(cfd), 4)
	return prepareMessage(id, unix.CGROUPSTATS_CMD_GET, buf.Bytes())
}

type loadStatsResp struct {
	Header    syscall.NlMsghdr
	GenHeader genMsghdr
	Stats     LoadStats
}

func parseLoadStatsResp(msg syscall.NetlinkMessage) (*loadStatsResp, error) {
	m := new(loadStatsResp)
	m.Header = msg.Header
	err := verifyHeader(msg)
	if err != nil {
		return m, err
	}
	buf := bytes.NewBuffer(msg.Data)
	// Scan the general header.
	err = binary.Read(buf, binary.LittleEndian, &m.GenHeader)
	if err != nil {
		return m, err
	}
	// cgroup stats response should have just one attribute.
	// Read it directly into the stats structure.
	var attr syscall.RtAttr
	err = binary.Read(buf, binary.LittleEndian, &attr)
	if err != nil {
		return m, err
	}
	err = binary.Read(buf, binary.LittleEndian, &m.Stats)
	if err != nil {
		return m, err
	}
	return m, err
}

func getLoadStats(id uint16, cfd *os.File, conn *Connection) (LoadStats, error) {
	msg := prepareCmdMessage(id, cfd.Fd())
	err := conn.WriteMessage(msg.toRawMsg())
	if err != nil {
		return LoadStats{}, err
	}

	resp, err := conn.ReadMessage()
	if err != nil {
		return LoadStats{}, err
	}

	parsedmsg, err := parseLoadStatsResp(resp)
	if err != nil {
		return LoadStats{}, err
	}
	return parsedmsg.Stats, nil
}

func main() {
	nl, err := NewNetLinkReader()
	if err != nil {
		panic(err)
	}
	defer nl.conn.Close()
	path := os.Args[1]
	if path == "" {
		path = "/sys/fs/cgroup/cpu"
	}
	res, err := nl.GetCpuLoad(path)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%+v\n", res)
}
