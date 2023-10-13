package datastore

import (
	"context"
	"net/http"
	"strconv"
	"sync"

	"github.com/ddosify/alaz/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	appLabel          = "acorn.io/app-public-name"
	appNamespaceLabel = "acorn.io/app-namespace"
	containerLabel    = "acorn.io/container-name"
)

type PrometheusExporter struct {
	ctx context.Context
	reg *prometheus.Registry

	latencyHistogram *prometheus.HistogramVec
	statusCounter    *prometheus.CounterVec

	podCache *eventCache
	svcCache *eventCache

	reqChanBuffer chan Request
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
		svcCache:      newEventCache(),
		reqChanBuffer: make(chan Request, 10000),
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
		[]string{"toPod", "toAcornApp", "toAcornContainer", "toAcornAppNamespace"},
	)
	exporter.reg.MustRegister(exporter.latencyHistogram)

	exporter.statusCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "alaz",
			Name:      "http_status",
		},
		[]string{"toPod", "toAcornApp", "toAcornContainer", "toAcornAppNamespace", "status"},
	)
	exporter.reg.MustRegister(exporter.statusCounter)

	go exporter.handleReqs()

	go func() {
		http.Handle("/metricz", promhttp.HandlerFor(exporter.reg, promhttp.HandlerOpts{}))
		go func() {
			if err := http.ListenAndServe(":8080", nil); err != nil {
				log.Logger.Error().Err(err).Msg("error while serving metrics")
			}
		}()
		<-exporter.ctx.Done()
		log.Logger.Info().Msg("Prometheus exporter stopped")
	}()

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
			p.updateMetrics(toPod.(PodEvent), req)
		}
	}
}

func (p *PrometheusExporter) updateMetrics(toPod PodEvent, req Request) {
	p.latencyHistogram.With(prometheus.Labels{
		"toPod":               toPod.Name,
		"toAcornApp":          toPod.Labels[appLabel],
		"toAcornAppNamespace": toPod.Labels[appNamespaceLabel],
		"toAcornContainer":    toPod.Labels[containerLabel],
	}).Observe(float64(req.Latency) / float64(1000000)) // divide by 1 million to convert nanoseconds to milliseconds

	p.statusCounter.With(prometheus.Labels{
		"toPod":               toPod.Name,
		"status":              strconv.Itoa(int(req.StatusCode)),
		"toAcornApp":          toPod.Labels[appLabel],
		"toAcornAppNamespace": toPod.Labels[appNamespaceLabel],
		"toAcornContainer":    toPod.Labels[containerLabel],
	}).Inc()
}

func (p *PrometheusExporter) PersistRequest(request Request) error {
	p.reqChanBuffer <- request
	return nil
}

func (p *PrometheusExporter) PersistPod(pod Pod, eventType string) error {
	if eventType == "DELETE" {
		p.podCache.delete(pod.UID)
	} else {
		podEvent := convertPodToPodEvent(pod, eventType)
		p.podCache.set(pod.UID, podEvent)
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
