# Alaz - Ddosify eBPF Agent - forked and modified by Acorn Labs

Alaz is an open-source Ddosify eBPF agent that can inspect and collect Kubernetes (K8s) service traffic without the need for code instrumentation, sidecars, or service restarts. This is possible due to its use of eBPF technology. Alaz can create a Service Map that helps identify golden signals and problems like high latencies, 5xx errors, zombie services, SQL queries. Additionally, it can gather system information and resources via the Prometheus Node Exporter, which is readily available on the agent. Alaz Docker image is available on [Docker Hub](https://hub.docker.com/r/ddosify/alaz).

## License

Alaz is licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
