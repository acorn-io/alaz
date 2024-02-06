package aggregator

import (
	"github.com/ddosify/alaz/datastore"
	"github.com/ddosify/alaz/k8s"
	"github.com/ddosify/alaz/log"

	corev1 "k8s.io/api/core/v1"
)

const (
	ADD    = "ADD"
	UPDATE = "UPDATE"
	DELETE = "DELETE"
)

func (a *Aggregator) persistPod(dto datastore.Pod, eventType string) {
	err := a.ds.PersistPod(dto, eventType)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("error on PersistPod call to %s, uid: %s", eventType, dto.UID)
	}
}

func (a *Aggregator) processPod(d k8s.K8sResourceMessage) {
	pod := d.Object.(*corev1.Pod)

	var ownerType, ownerID, ownerName string
	if len(pod.OwnerReferences) > 0 {
		ownerType = pod.OwnerReferences[0].Kind
		ownerID = string(pod.OwnerReferences[0].UID)
		ownerName = pod.OwnerReferences[0].Name
	} else {
		log.Logger.Debug().Msgf("Pod %s/%s has no owner, event: %s", pod.Namespace, pod.Name, d.EventType)
	}

	dtoPod := datastore.Pod{
		UID:       string(pod.UID),
		Name:      pod.Name,
		Namespace: pod.Namespace,
		Image:     pod.Spec.Containers[0].Image, // main containers
		IP:        pod.Status.PodIP,

		// Assuming that there is only one owner
		OwnerType: ownerType,
		OwnerID:   ownerID,
		OwnerName: ownerName,

		Labels:      pod.GetLabels(),
		Annotations: pod.GetAnnotations(),
	}

	switch d.EventType {
	case k8s.ADD:
		a.clusterInfo.mu.Lock()
		a.clusterInfo.PodIPToPodUid[pod.Status.PodIP] = pod.UID
		a.clusterInfo.mu.Unlock()
		go a.persistPod(dtoPod, ADD)
	case k8s.UPDATE:
		a.clusterInfo.mu.Lock()
		a.clusterInfo.PodIPToPodUid[pod.Status.PodIP] = pod.UID
		a.clusterInfo.mu.Unlock()
		go a.persistPod(dtoPod, UPDATE)
	case k8s.DELETE:
		a.clusterInfo.mu.Lock()
		delete(a.clusterInfo.PodIPToPodUid, pod.Status.PodIP)
		a.clusterInfo.mu.Unlock()
		go a.persistPod(dtoPod, DELETE)
	}
}

func (a *Aggregator) persistSvc(dto datastore.Service, eventType string) {
	err := a.ds.PersistService(dto, eventType)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("error on PersistService call to %s, uid: %s", eventType, dto.UID)
	}
}

func (a *Aggregator) processSvc(d k8s.K8sResourceMessage) {
	service := d.Object.(*corev1.Service)

	ports := []struct {
		Src      int32  "json:\"src\""
		Dest     int32  "json:\"dest\""
		Protocol string "json:\"protocol\""
	}{}

	for _, port := range service.Spec.Ports {
		ports = append(ports, struct {
			Src      int32  "json:\"src\""
			Dest     int32  "json:\"dest\""
			Protocol string "json:\"protocol\""
		}{
			Src:      port.Port,
			Dest:     int32(port.TargetPort.IntValue()),
			Protocol: string(port.Protocol),
		})
	}

	dtoSvc := datastore.Service{
		UID:        string(service.UID),
		Name:       service.Name,
		Namespace:  service.Namespace,
		Type:       string(service.Spec.Type),
		ClusterIPs: service.Spec.ClusterIPs,
		Ports:      ports,
		Selector:   service.Spec.Selector,
	}

	switch d.EventType {
	case k8s.ADD:
		a.clusterInfo.mu.Lock()
		a.clusterInfo.ServiceIPToServiceUid[service.Spec.ClusterIP] = service.UID
		a.clusterInfo.mu.Unlock()
		go a.persistSvc(dtoSvc, ADD)
	case k8s.UPDATE:
		a.clusterInfo.mu.Lock()
		a.clusterInfo.ServiceIPToServiceUid[service.Spec.ClusterIP] = service.UID
		a.clusterInfo.mu.Unlock()
		go a.persistSvc(dtoSvc, UPDATE)
	case k8s.DELETE:
		a.clusterInfo.mu.Lock()
		delete(a.clusterInfo.ServiceIPToServiceUid, service.Spec.ClusterIP)
		a.clusterInfo.mu.Unlock()
		go a.persistSvc(dtoSvc, DELETE)
	}
}

func (a *Aggregator) processContainer(d k8s.K8sResourceMessage) {
	c := d.Object.(*k8s.Container)

	dto := datastore.Container{
		Name:      c.Name,
		Namespace: c.Namespace,
		PodUID:    c.PodUID,
		Image:     c.Image,
		Ports:     c.Ports,
	}

	switch d.EventType {
	case k8s.ADD:
		go func() {
			err := a.ds.PersistContainer(dto, ADD)
			if err != nil {
				log.Logger.Error().Err(err).Msgf("error on PersistContainer call to %s", ADD)
			}
		}()
	case k8s.UPDATE:
		go func() {
			err := a.ds.PersistContainer(dto, UPDATE)
			if err != nil {
				log.Logger.Error().Err(err).Msgf("error on PersistContainer call to %s", UPDATE)
			}
		}()
		// No need for  delete container
	}
}
