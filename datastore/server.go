package datastore

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/ddosify/alaz/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Server struct {
	ctx                 context.Context
	reg                 *prometheus.Registry
	podIPCache          *eventCache
	prometheusNamespace string
}

func NewServer(ctx context.Context, reg *prometheus.Registry, podIPCache *eventCache) (*Server, error) {
	promNamespace := os.Getenv("PROMETHEUS_NAMESPACE")
	if promNamespace == "" {
		return nil, fmt.Errorf("PROMETHEUS_NAMESPACE environment variable not set")
	}

	return &Server{
		ctx:                 ctx,
		reg:                 reg,
		podIPCache:          podIPCache,
		prometheusNamespace: promNamespace,
	}, nil
}

func (s *Server) Serve() {
	http.Handle("/metricz", s.authorize(promhttp.HandlerFor(s.reg, promhttp.HandlerOpts{})))
	go func() {
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Logger.Error().Err(err).Msg("error while serving metrics")
		}
	}()
	<-s.ctx.Done()
	log.Logger.Info().Msg("Prometheus HTTP server stopped")
}

func (s *Server) authorize(handler http.Handler) http.Handler {
	// Only two things are authorized to scrape Alaz:
	// - Prometheus
	// - cluster-agent
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var sourceIP string
		parts := strings.Split(r.RemoteAddr, ":")
		if len(parts) < 3 { // (i.e., <addr>:<port> or just addr)
			sourceIP = parts[0]
		} else {
			// shouldn't happen
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			w.Write([]byte("401 Unauthorized\n"))
			return
		}

		pod, ok := s.podIPCache.get(sourceIP)
		if ok && (isPrometheus(pod.(PodEvent)) || isClusterAgent(pod.(PodEvent))) {
			handler.ServeHTTP(w, r)
			return
		}

		log.Logger.Info().Msgf("unauthorized request from %s", r.RemoteAddr)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		w.Write([]byte("401 Unauthorized\n"))
	})
}

func isPrometheus(p PodEvent) bool {
	return p.Namespace == "prometheus-operator"
}

func isClusterAgent(p PodEvent) bool {
	return p.Labels[appLabel] == "cluster-agent" &&
		p.Labels[appNamespaceLabel] == "acorn" &&
		p.Labels[containerLabel] == "cluster-agent"
}
