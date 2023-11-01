package main

import (
	"io"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/ddosify/alaz/aggregator"
	"github.com/ddosify/alaz/datastore"
	"github.com/ddosify/alaz/ebpf"
	"github.com/ddosify/alaz/k8s"
	"k8s.io/klog/v2"

	"context"

	"github.com/ddosify/alaz/log"

	_ "net/http/pprof"
)

func main() {
	klog.SetOutput(io.Discard) // disable klog traces

	ctx, cancel := context.WithCancel(context.Background())

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	go func() {
		<-c
		signal.Stop(c)
		cancel()
	}()

	var k8sCollector *k8s.K8sCollector
	kubeEvents := make(chan interface{}, 1000)
	if os.Getenv("K8S_COLLECTOR_ENABLED") != "false" {
		// k8s collector
		var err error
		k8sCollector, err = k8s.NewK8sCollector(ctx)
		if err != nil {
			panic(err)
		}
		go k8sCollector.Init(kubeEvents)
	}

	ebpfEnabled, _ := strconv.ParseBool(os.Getenv("EBPF_ENABLED"))

	// start Prometheus exporter
	exporter := datastore.NewPrometheusExporter(ctx)

	aggregatorKubeEvents := make(chan interface{})
	throughputKubeEvents := make(chan interface{})

	// deploy ebpf programs
	var ec *ebpf.EbpfCollector
	if ebpfEnabled {
		ec = ebpf.NewEbpfCollector(ctx)
		go ec.Deploy()
		go ec.DeployThroughput(throughputKubeEvents)

		a := aggregator.NewAggregator(aggregatorKubeEvents, nil, ec.EbpfEvents(), exporter)
		a.Run()
	}

	go fanOut(ctx, kubeEvents, aggregatorKubeEvents, throughputKubeEvents)

	<-k8sCollector.Done()
	log.Logger.Info().Msg("k8sCollector done")

	<-ec.Done()
	log.Logger.Info().Msg("ebpfCollector done")

	log.Logger.Info().Msg("alaz exiting...")
}

func fanOut(ctx context.Context, in <-chan any, out ...chan any) {
	for {
		select {
		case <-ctx.Done():
			for _, o := range out {
				close(o)
			}
			return
		case e, ok := <-in:
			if !ok {
				for _, o := range out {
					close(o)
				}
				return
			}

			for _, o := range out {
				o <- e
			}
		}
	}
}
