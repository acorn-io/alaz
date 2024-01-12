package datastore

type Pod struct {
	UID         string // Pod UID
	Name        string // Pod Name
	Namespace   string // Namespace
	Image       string // Main container image
	IP          string // Pod IP
	OwnerType   string // ReplicaSet or nil
	OwnerID     string // ReplicaSet UID
	OwnerName   string // ReplicaSet Name
	Labels      map[string]string
	Annotations map[string]string
}

type Service struct {
	UID        string
	Name       string
	Namespace  string
	Type       string
	ClusterIP  string
	ClusterIPs []string
	Ports      []struct {
		Src      int32  `json:"src"`
		Dest     int32  `json:"dest"`
		Protocol string `json:"protocol"`
	}
	Selector map[string]string
}

type ReplicaSet struct {
	UID       string // ReplicaSet UID
	Name      string // ReplicaSet Name
	Namespace string // Namespace
	OwnerType string // Deployment or nil
	OwnerID   string // Deployment UID
	OwnerName string // Deployment Name
	Replicas  int32  // Number of replicas
}

type DaemonSet struct {
	UID       string // ReplicaSet UID
	Name      string // ReplicaSet Name
	Namespace string // Namespace
}

type Deployment struct {
	UID       string // Deployment UID
	Name      string // Deployment Name
	Namespace string // Namespace
	Replicas  int32  // Number of replicas
}

type Endpoints struct {
	UID       string // Endpoints UID
	Name      string // Endpoints Name
	Namespace string // Namespace
	Addresses []Address
}

type AddressIP struct {
	Type      string `json:"type"` // pod or external
	ID        string `json:"id"`   // Pod UID or empty
	Name      string `json:"name"`
	Namespace string `json:"namespace"` // Pod Namespace or empty
	IP        string `json:"ip"`        // Pod IP or external IP
}

type AddressPort struct {
	Port     int32  `json:"port"`     // Port number
	Protocol string `json:"protocol"` // TCP or UDP
}

// Subsets
type Address struct {
	IPs   []AddressIP   `json:"ips"`
	Ports []AddressPort `json:"ports"`
}

type Container struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	PodUID    string `json:"pod"` // Pod UID
	Image     string `json:"image"`
	Ports     []struct {
		Port     int32  `json:"port"`
		Protocol string `json:"protocol"`
	} `json:"ports"`
}

type Request struct {
	StartTime  int64
	Latency    uint64 // in ns
	FromIP     string
	FromType   string
	FromUID    string
	FromPort   uint16
	ToIP       string
	ToType     string
	ToUID      string
	ToPort     uint16
	Protocol   string
	Completed  bool
	StatusCode uint32
	FailReason string
	Method     string
	Path       string
}

type BackendResponse struct {
	Msg    string `json:"msg"`
	Errors []struct {
		EventNum int         `json:"event_num"`
		Event    interface{} `json:"event"`
		Error    string      `json:"error"`
	} `json:"errors"`
}

// The following types are used for throughput metrics

type Direction string

const (
	Ingress  Direction = "ingress"
	Egress   Direction = "egress"
	Internal Direction = "internal"
)

type Source string

const (
	PodSource     Source = "pod"
	OutsideSource Source = "outside"
)

type Dest string

const (
	PodDest     Dest = "pod"
	ServiceDest Dest = "service"
	OutsideDest Dest = "outside"
)

type Packet struct {
	Time      uint64
	Size      uint32
	Direction Direction
	FromIP    string
	FromType  Source
	FromUID   string
	FromPort  uint16
	ToIP      string
	ToType    Dest
	ToUID     string
	ToPort    uint16
	// IsIngress indicates whether the packet was detected on the ingress or egress bpf filter.
	// The egress bpf filter is used for the throughput metric, while the ingress bpf filter
	// is used for the egress metric. (Seems backwards, but that is how it actually works.)
	IsIngress bool
}
