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
	http.Handle("/metricz", s.authorizePrometheus(promhttp.HandlerFor(s.reg, promhttp.HandlerOpts{})))
	go func() {
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Logger.Error().Err(err).Msg("error while serving metrics")
		}
	}()
	//go s.purgeBans()
	<-s.ctx.Done()
	log.Logger.Info().Msg("Prometheus HTTP server stopped")
}

func (s *Server) authorizePrometheus(handler http.Handler) http.Handler {
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
		if ok && pod.(PodEvent).Namespace == os.Getenv("PROMETHEUS_NAMESPACE") {
			handler.ServeHTTP(w, r)
			return
		}

		log.Logger.Info().Msgf("unauthorized request from %s", r.RemoteAddr)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		w.Write([]byte("401 Unauthorized\n"))
	})
}

//func (s *Server) basicAuth(handler http.Handler) http.Handler {
//	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		source := r.RemoteAddr
//
//		s.m.RLock()
//		_, banned := s.bans[source]
//		s.m.RUnlock()
//		if banned {
//			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
//			w.Write([]byte("429 Too Many Requests\n"))
//			return
//		}
//
//		user, pass, ok := r.BasicAuth()
//		if !ok || user != s.username || pass != s.password {
//			s.m.Lock()
//			s.failedAttempts[source]++
//			if s.failedAttempts[source] >= 3 {
//				s.bans[source] = time.Now()
//				log.Logger.Info().Msgf("banning remote addr %s for 1 hour", source)
//			}
//			s.m.Unlock()
//
//			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
//			http.Error(w, "Unauthorized", http.StatusUnauthorized)
//			w.Write([]byte("401 Unauthorized\n"))
//			return
//		}
//
//		handler.ServeHTTP(w, r)
//	})
//}

//func (s *Server) purgeBans() {
//	ticker := time.NewTicker(5 * time.Minute)
//	select {
//	case <-s.ctx.Done():
//		ticker.Stop()
//		return
//	case <-ticker.C:
//		for source, banTime := range s.bans {
//			if time.Now().After(banTime.Add(time.Hour)) {
//				s.m.Lock()
//				delete(s.bans, source)
//				s.failedAttempts[source] = 0
//				s.m.Unlock()
//			}
//		}
//	}
//
//}
