package throughput

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/ddosify/alaz/k8s"
	"github.com/ddosify/alaz/log"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
)

type ThroughputEventBpf struct {
	Timestamp uint64
	Size      uint32
	SPort     uint16
	DPort     uint16
	SAddr     [16]byte
	DAddr     [16]byte
}

// for user space
type ThroughputEvent struct {
	Timestamp uint64
	Size      uint32
	SPort     uint16
	DPort     uint16
	SAddr     string
	DAddr     string
}

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf throughput.c -- -I../headers

const THROUGHPUT_EVENT = "throughput_event"

var NODE_NAME = os.Getenv("NODE_NAME")

func (e ThroughputEvent) Type() string {
	return THROUGHPUT_EVENT
}

// returns when the program is loaded
func DeployAndWait(ctx context.Context, ch chan interface{}, eventChan <-chan interface{}) {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Logger.Fatal().Err(err).Msg("failed to remove memlock limit")
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		fmt.Println(err.Error())
		log.Logger.Fatal().Err(err).Msg("loading objects")
	}
	defer objs.Close()

	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()

	time.Sleep(time.Second)

	// Set up network interfaces for the first time, then do it again on pod events
	if err := setFiltersOnCiliumInterfaces(objs); err != nil {
		log.Logger.Fatal().Err(err).Msg("failed to set up filters on cilium interfaces")
	}

	go watchNetworkInterfaces(ctx, objs, eventChan)

	throughputEventReader, err := ringbuf.NewReader(objs.ThroughputEvents)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("failed to create perf event reader")
	}
	defer func() {
		log.Logger.Info().Msg("closing throughputEventReader perf event reader")
		throughputEventReader.Close()
	}()

	readDone := make(chan struct{})
	go func() {
		for {
			read := func() {
				record, err := throughputEventReader.Read()
				if err != nil {
					log.Logger.Warn().Err(err).Msg("error reading from perf array")
				}

				if record.RawSample == nil || len(record.RawSample) == 0 {
					return
				}

				bpfEvent := (*ThroughputEventBpf)(unsafe.Pointer(&record.RawSample[0]))

				go func() {
					ch <- ThroughputEvent{
						Timestamp: bpfEvent.Timestamp,
						Size:      bpfEvent.Size,
						SPort:     bpfEvent.SPort,
						DPort:     bpfEvent.DPort,
						SAddr:     fmt.Sprintf("%d.%d.%d.%d", bpfEvent.SAddr[0], bpfEvent.SAddr[1], bpfEvent.SAddr[2], bpfEvent.SAddr[3]),
						DAddr:     fmt.Sprintf("%d.%d.%d.%d", bpfEvent.DAddr[0], bpfEvent.DAddr[1], bpfEvent.DAddr[2], bpfEvent.DAddr[3]),
					}
				}()
			}

			select {
			case <-readDone:
				return
			default:
				read()
			}
		}
	}()

	<-ctx.Done()
	readDone <- struct{}{}
}

func watchNetworkInterfaces(ctx context.Context, objs bpfObjects, eventChan <-chan interface{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-eventChan:
			data := event.(k8s.K8sResourceMessage)
			if data.ResourceType == k8s.POD {
				if pod, ok := data.Object.(*corev1.Pod); ok && pod.Spec.NodeName == NODE_NAME {
					if err := setFiltersOnCiliumInterfaces(objs); err != nil {
						log.Logger.Warn().Err(err)
					}
				}
			}
		}
	}
}

func setFiltersOnCiliumInterfaces(objs bpfObjects) error {
	allLinks, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("failed to list links: %w", err)
	}

	var errs []error

	for _, link := range allLinks {
		// if link name starts with 'lxc' but is not 'lxc_health', then it is for Cilium
		if strings.HasPrefix(link.Attrs().Name, "lxc") && link.Attrs().Name != "lxc_health" {
			if err := setUpEgressFilter(link, objs); err != nil {
				errs = append(errs, fmt.Errorf("failed to set up egress filter for link %s: %w", link.Attrs().Name, err))
			}
			if err := setUpIngressQdiscAndFilter(link, objs); err != nil {
				errs = append(errs, fmt.Errorf("failed to set up ingress filter for link %s: %w", link.Attrs().Name, err))
			}
		}
	}

	return errors.Join(errs...)
}

func setUpEgressFilter(link netlink.Link, objs bpfObjects) error {
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           objs.bpfPrograms.PacketClassifier.FD(),
		Name:         "throughput_bpf_egress",
		DirectAction: true,
	}
	return netlink.FilterReplace(filter)
}

func setUpIngressQdiscAndFilter(link netlink.Link, objs bpfObjects) error {
	qdiscAttrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdisc := netlink.GenericQdisc{
		QdiscAttrs: qdiscAttrs,
		QdiscType:  "clsact",
	}
	if err := netlink.QdiscReplace(&qdisc); err != nil {
		return err
	}

	ingressFilter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           objs.bpfPrograms.PacketClassifier.FD(),
		Name:         "throughput_bpf_ingress",
		DirectAction: true,
	}
	return netlink.FilterReplace(ingressFilter)
}
