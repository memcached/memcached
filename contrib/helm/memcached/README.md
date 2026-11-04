# memcached

![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 1.6.45](https://img.shields.io/badge/AppVersion-1.6.45-informational?style=flat-square)

Memcached, a high performance multithreaded event-based key/value cache store.

The chart runs the [Docker official image](https://hub.docker.com/_/memcached) as the `memcache` user with a read-only root filesystem and no service account token. It does not create an Ingress: memcached has no authentication by default and should only be reachable from inside the cluster. Use `networkPolicy` to narrow that further.

## Install

```console
helm install cache ./contrib/helm/memcached --set memcached.memoryLimitMB=512 \
  --set resources.requests.memory=600Mi --set resources.limits.memory=640Mi
```

Keep the container memory limit comfortably above `memcached.memoryLimitMB`: the item memory is only part of what memcached allocates.

## Deployment or StatefulSet

The default `kind: Deployment` puts every pod behind one ClusterIP Service. That is fine for a single pod, or for clients that do not care which server holds a key.

Most clients shard keys over a fixed list of servers. Use `kind: StatefulSet` for them: each pod gets a stable name through a headless Service, for example `cache-memcached-0.cache-memcached-headless.default.svc:11211`.

```yaml
kind: StatefulSet
replicaCount: 3
podDisruptionBudget:
  enabled: true
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: topology.kubernetes.io/zone
    whenUnsatisfiable: ScheduleAnyway
```

## Metrics

`metrics.enabled` adds [memcached_exporter](https://github.com/prometheus/memcached_exporter) as a sidecar on port 9150, and `metrics.serviceMonitor.enabled` creates a ServiceMonitor for the Prometheus Operator.

## Requirements

Kubernetes: `>=1.25.0-0`

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | Affinity rules. |
| commonLabels | object | `{}` | Extra labels added to every resource. |
| fullnameOverride | string | `""` | Overrides the fully qualified resource name. |
| image.digest | string | `""` | Image digest. Takes precedence over the tag when set. |
| image.pullPolicy | string | `"IfNotPresent"` | Image pull policy. |
| image.repository | string | `"memcached"` | Image repository. Defaults to the Docker official image. |
| image.tag | string | `""` | Image tag. Defaults to the chart appVersion. |
| imagePullSecrets | list | `[]` | Secrets used to pull the images. |
| kind | string | `"Deployment"` | Workload kind. Deployment fits a plain cache behind one Service. StatefulSet gives every pod a stable DNS name through a headless Service, which clients that shard keys over a fixed server list need. |
| memcached.extraArgs | list | `[]` | Extra command line arguments, for example ["-o", "modern"] or extstore options. |
| memcached.maxConnections | int | `1024` | Max simultaneous connections (-c). |
| memcached.maxItemSize | string | `"1m"` | Max item size (-I), for example 1m or 4m. |
| memcached.memoryLimitMB | int | `64` | Item memory in megabytes (-m). Keep the container memory limit above this, memcached also needs memory for connections and hash tables. |
| memcached.threads | int | `4` | Worker threads (-t). |
| metrics.enabled | bool | `false` | Run prom/memcached-exporter as a sidecar. |
| metrics.extraArgs | list | `[]` | Extra exporter arguments. |
| metrics.image.pullPolicy | string | `"IfNotPresent"` | Exporter image pull policy. |
| metrics.image.repository | string | `"prom/memcached-exporter"` | Exporter image repository. |
| metrics.image.tag | string | `"v0.18.0"` | Exporter image tag. |
| metrics.port | int | `9150` | Exporter port. |
| metrics.resources | object | `{"limits":{"memory":"32Mi"},"requests":{"cpu":"10m","memory":"16Mi"}}` | Resources of the exporter container. |
| metrics.serviceMonitor.enabled | bool | `false` | Create a Prometheus Operator ServiceMonitor. |
| metrics.serviceMonitor.interval | string | `"30s"` | Scrape interval. |
| metrics.serviceMonitor.labels | object | `{}` | Extra labels, for example the one your Prometheus selects on. |
| metrics.serviceMonitor.scrapeTimeout | string | `"10s"` | Scrape timeout. |
| nameOverride | string | `""` | Overrides the chart name used in resource names and labels. |
| networkPolicy.allowedFrom | list | `[]` | Peers allowed to reach memcached. Empty allows only pods in the release namespace. |
| networkPolicy.enabled | bool | `false` | Create a NetworkPolicy that only admits the listed peers. |
| networkPolicy.metricsAllowedFrom | list | `[]` | Peers allowed to scrape the exporter. |
| nodeSelector | object | `{}` | Node selector. |
| podAnnotations | object | `{}` | Extra annotations added to the pods. |
| podDisruptionBudget.enabled | bool | `false` | Create a PodDisruptionBudget. |
| podDisruptionBudget.maxUnavailable | int | `1` | Pods that may be down at once during voluntary disruptions. |
| podLabels | object | `{}` | Extra labels added to the pods. |
| podSecurityContext | object | `{"fsGroup":11211,"runAsGroup":11211,"runAsNonRoot":true,"runAsUser":11211,"seccompProfile":{"type":"RuntimeDefault"}}` | Pod level security context. The official image runs as the memcache user (11211). |
| priorityClassName | string | `""` | Priority class of the pods. |
| probes.liveness.enabled | bool | `true` | TCP liveness probe on the memcached port. |
| probes.liveness.failureThreshold | int | `3` | Failures before the container is restarted. |
| probes.liveness.periodSeconds | int | `10` | Seconds between checks. |
| probes.readiness.enabled | bool | `true` | TCP readiness probe on the memcached port. |
| probes.readiness.failureThreshold | int | `3` | Failures before the pod is marked unready. |
| probes.readiness.periodSeconds | int | `5` | Seconds between checks. |
| replicaCount | int | `1` | Number of memcached pods. |
| resources | object | `{"limits":{"memory":"128Mi"},"requests":{"cpu":"100m","memory":"96Mi"}}` | Resources of the memcached container. |
| revisionHistoryLimit | int | `5` | Revisions kept for rollback. |
| securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true}` | Container level security context, shared by memcached and the exporter. |
| service.annotations | object | `{}` | Service annotations. |
| service.port | int | `11211` | Service port. |
| service.type | string | `"ClusterIP"` | Service type. |
| serviceAccount.annotations | object | `{}` | ServiceAccount annotations. |
| serviceAccount.create | bool | `true` | Create a ServiceAccount. |
| serviceAccount.name | string | `""` | ServiceAccount name. Generated when empty. |
| terminationGracePeriodSeconds | int | `30` | Grace period before the pod is killed. |
| tolerations | list | `[]` | Tolerations. |
| topologySpreadConstraints | list | `[]` | Topology spread constraints. The pod selector labels are filled in when labelSelector is omitted. |
