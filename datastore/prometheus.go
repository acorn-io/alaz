package datastore

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"sync"

	"github.com/ddosify/alaz/log"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	accountIDLabel    = "acorn.io/account-id"
	appLabel          = "acorn.io/app-public-name"
	appNamespaceLabel = "acorn.io/app-namespace"
	containerLabel    = "acorn.io/container-name"
	projectLabel      = "acorn.io/project-name"

	resolvedOfferingsAnnotation = "acorn.io/container-resolved-offerings"
)

var (
	latencyHistLabels       = []string{"toPod", "toAcornApp", "toAcornContainer", "toAcornAppNamespace"}
	statusCounterLabels     = []string{"toPod", "toAcornApp", "toAcornContainer", "toAcornAppNamespace", "status"}
	throughputCounterLabels = []string{"fromPod", "fromAcornApp", "fromAcornContainer", "fromAcornAppNamespace", "fromHostname", "toPod", "toAcornApp", "toAcornContainer", "toAcornAppNamespace", "toPort", "toHostname"}
	egressCounterLabels     = []string{"fromPod", "fromAcornApp", "fromAcornContainer", "fromAcornProject", "fromAcornAccountID", "fromAcornComputeClass"}
)

type PrometheusExporter struct {
	ctx context.Context
	reg *prometheus.Registry

	latencyHistogram  *prometheus.HistogramVec
	statusCounter     *prometheus.CounterVec
	throughputCounter *prometheus.CounterVec
	egressCounter     *prometheus.CounterVec

	podCache   *eventCache
	podIPCache *eventCache
	svcCache   *eventCache

	reqChanBuffer chan Request
	pktChanBuffer chan Packet
}

type eventCache struct {
	c map[string]Event
	m sync.RWMutex
}

func newEventCache() *eventCache {
	return &eventCache{
		c: make(map[string]Event),
		m: sync.RWMutex{},
	}
}

func (c *eventCache) get(uid string) (Event, bool) {
	c.m.RLock()
	defer c.m.RUnlock()
	val, ok := c.c[uid]
	return val, ok
}

func (c *eventCache) set(uid string, e Event) {
	c.m.Lock()
	defer c.m.Unlock()
	c.c[uid] = e
}

func (c *eventCache) delete(uid string) {
	c.m.Lock()
	defer c.m.Unlock()
	delete(c.c, uid)
}

func NewPrometheusExporter(ctx context.Context) *PrometheusExporter {
	exporter := &PrometheusExporter{
		ctx:           ctx,
		reg:           prometheus.NewRegistry(),
		podCache:      newEventCache(),
		podIPCache:    newEventCache(),
		svcCache:      newEventCache(),
		reqChanBuffer: make(chan Request, 10000),
		pktChanBuffer: make(chan Packet, 10000),
	}

	// Labels to consider using in the future:
	// fromPod, fromNamespace, fromAcornProject, fromAcornApp, fromAcornAppNamespace, fromAcornContainer, fromAcornAccountId,
	// toNamespace, toHost, toPort, toService, toAcornProject, toAcornAccountId

	exporter.latencyHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "alaz",
			Name:      "http_latency",
			Buckets:   []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000},
		},
		latencyHistLabels,
	)
	exporter.reg.MustRegister(exporter.latencyHistogram)

	exporter.statusCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "alaz",
			Name:      "http_status",
		},
		statusCounterLabels,
	)
	exporter.reg.MustRegister(exporter.statusCounter)

	exporter.throughputCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "alaz",
			Name:      "throughput",
		},
		throughputCounterLabels,
	)
	exporter.reg.MustRegister(exporter.throughputCounter)

	exporter.egressCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "alaz",
			Name:      "egress",
		},
		egressCounterLabels,
	)
	exporter.reg.MustRegister(exporter.egressCounter)

	go exporter.handleReqs()
	go exporter.handlePackets()

	server, err := NewServer(ctx, exporter.reg, exporter.podIPCache)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("error while creating prometheus server")
	}
	go server.Serve()

	return exporter
}

func (p *PrometheusExporter) handleReqs() {
	for {
		select {
		case <-p.ctx.Done():
			return
		case req := <-p.reqChanBuffer:
			p.handleReq(req)
		}
	}
}

func (p *PrometheusExporter) handleReq(req Request) {
	if req.ToType == "pod" {
		toPod, found := p.podCache.get(req.ToUID)
		if found {
			p.updateMetricsForReq(toPod.(PodEvent), req)
		}
	}
}

func (p *PrometheusExporter) updateMetricsForReq(toPod PodEvent, req Request) {
	// TODO - uncomment this when it is actually useful

	//p.latencyHistogram.With(prometheus.Labels{
	//	"toPod":               toPod.Name,
	//	"toAcornApp":          toPod.Labels[appLabel],
	//	"toAcornAppNamespace": toPod.Labels[appNamespaceLabel],
	//	"toAcornContainer":    toPod.Labels[containerLabel],
	//}).Observe(float64(req.Latency) / float64(1000000)) // divide by 1 million to convert nanoseconds to milliseconds
	//
	//p.statusCounter.With(prometheus.Labels{
	//	"toPod":               toPod.Name,
	//	"status":              strconv.Itoa(int(req.StatusCode)),
	//	"toAcornApp":          toPod.Labels[appLabel],
	//	"toAcornAppNamespace": toPod.Labels[appNamespaceLabel],
	//	"toAcornContainer":    toPod.Labels[containerLabel],
	//}).Inc()
}

func (p *PrometheusExporter) handlePackets() {
	for {
		select {
		case <-p.ctx.Done():
			return
		case pkt := <-p.pktChanBuffer:
			p.handlePacket(pkt)
		}
	}
}

func (p *PrometheusExporter) handlePacket(pkt Packet) {
	// Check for packets between pods in the same project.
	// (Reminder: !pkt.IsIngress means that the packet was detected by the egress eBPF filter.)
	if !pkt.IsIngress && pkt.FromType == PodSource && pkt.ToType == PodDest {
		fromPod, found := p.podCache.get(pkt.FromUID)
		toPod, found2 := p.podCache.get(pkt.ToUID)

		// Make sure that both pods exist in the cache, have a project label set, and have the same project and app names
		if found && found2 && fromPod.(PodEvent).Labels[appNamespaceLabel] != "" && toPod.(PodEvent).Labels[appNamespaceLabel] != "" &&
			fromPod.(PodEvent).Labels[appNamespaceLabel] == toPod.(PodEvent).Labels[appNamespaceLabel] &&
			fromPod.(PodEvent).Labels[appLabel] == toPod.(PodEvent).Labels[appLabel] {

			labels := prometheus.Labels{
				"toPort":                strconv.Itoa(int(pkt.ToPort)),
				"fromPod":               fromPod.(PodEvent).Name,
				"fromAcornApp":          fromPod.(PodEvent).Labels[appLabel],
				"fromAcornAppNamespace": fromPod.(PodEvent).Labels[appNamespaceLabel],
				"fromAcornContainer":    fromPod.(PodEvent).Labels[containerLabel],
				"toPod":                 toPod.(PodEvent).Name,
				"toAcornApp":            toPod.(PodEvent).Labels[appLabel],
				"toAcornAppNamespace":   toPod.(PodEvent).Labels[appNamespaceLabel],
				"toAcornContainer":      toPod.(PodEvent).Labels[containerLabel],
			}

			p.throughputCounter.With(setEmptyPrometheusLabels(labels, throughputCounterLabels)).Add(float64(pkt.Size))
		}
	}

	// Check for packets from pods to outside the cluster.
	// (Reminder: pkt.IsIngress just means that the packet was detected by the ingress eBPF filter, which is actually detecting egress traffic.)
	// OutsideDest indicates that the destination IP address is not a known pod or service IP address.
	// We also filter out the 10. prefix because that is the internal IP address range used by the cluster.
	if pkt.IsIngress && pkt.FromType == PodSource && pkt.ToType == OutsideDest && !strings.HasPrefix(pkt.ToIP, "10.") {
		fromPod, found := p.podCache.get(pkt.FromUID)

		if found && fromPod.(PodEvent).Labels[accountIDLabel] != "" {
			labels := prometheus.Labels{
				"fromPod":            fromPod.(PodEvent).Name,
				"fromAcornApp":       fromPod.(PodEvent).Labels[appLabel],
				"fromAcornProject":   fromPod.(PodEvent).Labels[projectLabel],
				"fromAcornContainer": fromPod.(PodEvent).Labels[containerLabel],
				"fromAcornAccountID": fromPod.(PodEvent).Labels[accountIDLabel],
			}

			if resolvedOfferingsJson, ok := fromPod.(PodEvent).Annotations[resolvedOfferingsAnnotation]; ok {
				offerings := map[string]any{}
				if err := json.Unmarshal([]byte(resolvedOfferingsJson), &offerings); err == nil {
					labels["fromAcornComputeClass"] = offerings["class"].(string)
				} else {
					log.Logger.Error().Msg(err.Error())
				}
			}

			p.egressCounter.With(setEmptyPrometheusLabels(labels, egressCounterLabels)).Add(float64(pkt.Size))
		}
	}
}

func setEmptyPrometheusLabels(labels prometheus.Labels, labelList []string) prometheus.Labels {
	for _, label := range labelList {
		if _, exists := labels[label]; !exists {
			labels[label] = ""
		}
	}
	return labels
}

func (p *PrometheusExporter) PersistRequest(request Request) error {
	p.reqChanBuffer <- request
	return nil
}

func (p *PrometheusExporter) PersistPacket(packet Packet) error {
	p.pktChanBuffer <- packet
	return nil
}

func (p *PrometheusExporter) PersistPod(pod Pod, eventType string) error {
	if eventType == "DELETE" {
		p.podCache.delete(pod.UID)
		p.podIPCache.delete(pod.IP)
	} else {
		podEvent := convertPodToPodEvent(pod, eventType)
		p.podCache.set(pod.UID, podEvent)
		p.podIPCache.set(pod.IP, podEvent)
	}
	return nil
}

func (p *PrometheusExporter) PersistService(service Service, eventType string) error {
	if eventType == "DELETE" {
		p.svcCache.delete(service.UID)
	} else {
		svcEvent := convertSvcToSvcEvent(service, eventType)
		p.svcCache.set(service.UID, svcEvent)
	}
	return nil
}

func (p *PrometheusExporter) PersistDeployment(_ Deployment, _ string) error {
	// ignore
	return nil
}

func (p *PrometheusExporter) PersistReplicaSet(_ ReplicaSet, _ string) error {
	// ignore
	return nil
}

func (p *PrometheusExporter) PersistEndpoints(_ Endpoints, _ string) error {
	// ignore
	return nil
}

func (p *PrometheusExporter) PersistDaemonSet(_ DaemonSet, _ string) error {
	// ignore
	return nil
}

func (p *PrometheusExporter) PersistContainer(_ Container, _ string) error {
	// ignore
	return nil
}
