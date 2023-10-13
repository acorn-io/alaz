package datastore

type Metadata struct {
	MonitoringID   string `json:"monitoring_id"`
	IdempotencyKey string `json:"idempotency_key"`
	NodeID         string `json:"node_id"`
	AlazVersion    string `json:"alaz_version"`
}

type HealthCheckPayload struct {
	Metadata Metadata `json:"metadata"`
	Info     struct {
		EbpfEnabled    bool `json:"ebpf"`
		MetricsEnabled bool `json:"metrics"`
	} `json:"alaz_info"`
}

type EventPayload struct {
	Metadata Metadata      `json:"metadata"`
	Events   []interface{} `json:"events"`
}

type Event interface {
	GetUID() string
}

type PodEvent struct {
	UID       string            `json:"uid"`
	EventType string            `json:"event_type"`
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	IP        string            `json:"ip"`
	OwnerType string            `json:"owner_type"`
	OwnerName string            `json:"owner_name"`
	OwnerID   string            `json:"owner_id"`
	Labels    map[string]string `json:"labels"`
}

func (p PodEvent) GetUID() string { return p.UID }

type SvcEvent struct {
	UID        string   `json:"uid"`
	EventType  string   `json:"event_type"`
	Name       string   `json:"name"`
	Namespace  string   `json:"namespace"`
	Type       string   `json:"type"`
	ClusterIPs []string `json:"cluster_ips"`
	Ports      []struct {
		Src      int32  `json:"src"`
		Dest     int32  `json:"dest"`
		Protocol string `json:"protocol"`
	} `json:"ports"`
	Selector map[string]string `json:"selector"`
}

func (s SvcEvent) GetUID() string { return s.UID }

type RsEvent struct {
	UID       string `json:"uid"`
	EventType string `json:"event_type"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Replicas  int32  `json:"replicas"`
	OwnerType string `json:"owner_type"`
	OwnerName string `json:"owner_name"`
	OwnerID   string `json:"owner_id"`
}

func (r RsEvent) GetUID() string { return r.UID }

type DsEvent struct {
	UID       string `json:"uid"`
	EventType string `json:"event_type"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

func (d DsEvent) GetUID() string { return d.UID }

type DepEvent struct {
	UID       string `json:"uid"`
	EventType string `json:"event_type"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Replicas  int32  `json:"replicas"`
}

func (d DepEvent) GetUID() string { return d.UID }

type EpEvent struct {
	UID       string    `json:"uid"`
	EventType string    `json:"event_type"`
	Name      string    `json:"name"`
	Namespace string    `json:"namespace"`
	Addresses []Address `json:"addresses"`
}

func (e EpEvent) GetUID() string { return e.UID }

type ContainerEvent struct {
	UID       string `json:"uid"`
	EventType string `json:"event_type"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Image     string `json:"image"`
	Ports     []struct {
		Port     int32  `json:"port"`
		Protocol string `json:"protocol"`
	} `json:"ports"`
}

func (c ContainerEvent) GetUID() string { return c.UID }

// 0) StartTime
// 1) Latency
// 2) Source IP
// 3) Source Type
// 4) Source ID
// 5) Source Port
// 6) Destination IP
// 7) Destination Type
// 8) Destination ID
// 9) Destination Port
// 10) Protocol
// 11) Response Code
// 12) ??
// 13) Method
// 14) Path
type ReqInfo [15]interface{}

type RequestsPayload struct {
	Metadata Metadata   `json:"metadata"`
	Requests []*ReqInfo `json:"requests"`
}

func convertPodToPodEvent(pod Pod, eventType string) PodEvent {
	return PodEvent{
		UID:       pod.UID,
		EventType: eventType,
		Name:      pod.Name,
		Namespace: pod.Namespace,
		IP:        pod.IP,
		OwnerType: pod.OwnerType,
		OwnerName: pod.OwnerName,
		OwnerID:   pod.OwnerID,
		Labels:    pod.Labels,
	}
}

func convertSvcToSvcEvent(service Service, eventType string) SvcEvent {
	return SvcEvent{
		UID:        service.UID,
		EventType:  eventType,
		Name:       service.Name,
		Namespace:  service.Namespace,
		Type:       service.Type,
		ClusterIPs: service.ClusterIPs,
		Ports:      service.Ports,
		Selector:   service.Selector,
	}
}
