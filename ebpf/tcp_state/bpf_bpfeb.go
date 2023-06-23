// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64be || armbe || mips || mips64 || mips64p32 || ppc64 || s390 || s390x || sparc || sparc64
// +build arm64be armbe mips mips64 mips64p32 ppc64 s390 s390x sparc sparc64

package tcp_state

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bpfSkInfo struct {
	Fd  uint64
	Pid uint32
	_   [4]byte
}

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpfObjects
//	*bpfPrograms
//	*bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	InetSockSetState *ebpf.ProgramSpec `ebpf:"inet_sock_set_state"`
	SysEnterConnect  *ebpf.ProgramSpec `ebpf:"sys_enter_connect"`
	SysExitConnect   *ebpf.ProgramSpec `ebpf:"sys_exit_connect"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	FdByPidTgid      *ebpf.MapSpec `ebpf:"fd_by_pid_tgid"`
	SockMap          *ebpf.MapSpec `ebpf:"sock_map"`
	TcpConnectEvents *ebpf.MapSpec `ebpf:"tcp_connect_events"`
	TcpListenEvents  *ebpf.MapSpec `ebpf:"tcp_listen_events"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	FdByPidTgid      *ebpf.Map `ebpf:"fd_by_pid_tgid"`
	SockMap          *ebpf.Map `ebpf:"sock_map"`
	TcpConnectEvents *ebpf.Map `ebpf:"tcp_connect_events"`
	TcpListenEvents  *ebpf.Map `ebpf:"tcp_listen_events"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.FdByPidTgid,
		m.SockMap,
		m.TcpConnectEvents,
		m.TcpListenEvents,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	InetSockSetState *ebpf.Program `ebpf:"inet_sock_set_state"`
	SysEnterConnect  *ebpf.Program `ebpf:"sys_enter_connect"`
	SysExitConnect   *ebpf.Program `ebpf:"sys_exit_connect"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.InetSockSetState,
		p.SysEnterConnect,
		p.SysExitConnect,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_bpfeb.o
var _BpfBytes []byte
