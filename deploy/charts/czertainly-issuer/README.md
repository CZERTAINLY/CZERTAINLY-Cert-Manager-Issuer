# CZERTAINLY cert-manager Issuer

> This repository is part of the open-source project CZERTAINLY. You can find more information about the project at [CZERTAINLY](https://github.com/CZERTAINLY/CZERTAINLY) repository, including the contribution guide.

This repository contains [Helm](https://helm.sh/) charts as part of the CZERTAINLY platform.

## Prerequisites
- Kubernetes 1.19+
- Helm 3.8.0+
- [cert-manager](https://cert-manager.io/docs/)

## Using this Chart

### Installation

**Create `values.yaml`**

> **Note**
> You can also use `--set` options for the helm to apply configuration for the chart.

Copy the default `values.yaml` from the Helm chart and modify the values accordingly:
```bash
helm show values oci://harbor.3key.company/czertainly-helm/czertainly-issuer > values.yaml
```
Now edit the `values.yaml` according to your desired stated, see [Configurable parameters](#configurable-parameters) for more information.

**Install**

For the basic installation, run:
```bash
helm install --namespace czertainly -f values.yaml czertainly-issuer oci://harbor.3key.company/czertainly-helm/czertainly-issuer
```

By default, the chart will install the CRDs required for the issuer to work properly. If you want to skip the installation of the CRDs, you can use the `--set crd.create=false` option.

### Upgrade

> **Warning**
> Be sure that you always save your previous configuration!

For upgrading the installation, update your configuration and run:
```bash
helm upgrade --namespace czertainly -f values.yaml czertainly-issuer oci://harbor.3key.company/czertainly-helm/czertainly-issuer
```

### Uninstall

You can use the `helm uninstall` command to uninstall the application:
```bash
helm uninstall --namespace czertainly czertainly-issuer
```

## Configurable parameters

You can find current values in the [values.yaml](values.yaml).
You can also Specify each parameter using the `--set` or `--set-file` argument to `helm install`.

The following values may be configured:

| Parameter                      | Default value                               | Description                                         |
|--------------------------------|---------------------------------------------|-----------------------------------------------------|
| crd.create                     | `true`                                      | Create CRDs for the issuer                          |
| crd.annotations                | `{}`                                        | Annotations for the CRDs                            |
| metrics.protect                | `false`                                     | Enable/disable metrics endpoint protection          |
| certmanager.namespace          | `cert-manager`                              | Namespace where cert-manager is installed           |
| certmanager.serviceAccountName | `cert-manager`                              | Service account name for cert-manager               |
| serviceAccount.create          | `true`                                      | Create service account for the issuer               |
| serviceAccount.annotations     | `{}`                                        | Annotations for the service account                 |
| serviceAccount.name            | `""`                                        | Service account name                                |
| image.registry                 | `docker.io`                                 | Docker registry name for the image                  |
| image.repository               | `czertainly`                                | Docker image repository name                        |
| image.name                     | `czertainly-cert-manager-issuer-controller` | Docker image name                                   |
| image.tag                      | `0.0.1`                                     | Docker image tag                                    |
| image.digest                   | `""`                                        | Docker image digest, will override tag if specified |
| image.pullPolicy               | `IfNotPresent`                              | Image pull policy                                   |
| image.pullSecrets              | `[]`                                        | Array of secret names for image pull                |
| image.command                  | `[]`                                        | Override the default command                        |
| image.args                     | `[]`                                        | Override the default args                           |
| image.ports                    | `[]`                                        | Ports for the container                             |
| image.securityContext          | `{}`                                        | Security context for the container                  |
| image.resources                | `{}`                                        | The resources for the container                     |
| podSecurityContext             | `{ runAsNonRoot: true }`                    | Pod security context                                |

#### Customization parameters

| Parameter                | Default value | Description                        |
|--------------------------|---------------|------------------------------------|
| initContainers           | `[]`          | Init containers                    |
| sidecarContainers        | `[]`          | Sidecar containers                 |
| additionalVolumes        | `[]`          | Additional volumes                 |
| additionalVolumeMounts   | `[]`          | Additional volume mounts           |
| additionalPorts          | `[]`          | Additional ports                   |
| additionalEnv.variables  | `[]`          | Additional environment variables   |
| additionalEnv.secrets    | `[]`          | Additional environment secrets     |
| additionalEnv.configMaps | `[]`          | Additional environment config maps |

#### Probes parameters

For mode details about probes, see the [Kubernetes documentation](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/).

| Parameter                                  | Default value | Description                                                                        |
|--------------------------------------------|---------------|------------------------------------------------------------------------------------|
| image.probes.liveness.enabled              | `true`        | Enable/disable liveness probe                                                      |
| image.probes.liveness.custom               | `{}`          | Custom liveness probe command. When defined, it will override the default command  |
| image.probes.liveness.initialDelaySeconds  | `15`          | Initial delay seconds for liveness probe                                           |
| image.probes.liveness.timeoutSeconds       | `1`           | Timeout seconds for liveness probe                                                 |
| image.probes.liveness.periodSeconds        | `20`          | Period seconds for liveness probe                                                  |
| image.probes.liveness.successThreshold     | `1`           | Success threshold for liveness probe                                               |
| image.probes.liveness.failureThreshold     | `3`           | Failure threshold for liveness probe                                               |
| image.probes.readiness.enabled             | `true`        | Enable/disable readiness probe                                                     |
| image.probes.readiness.custom              | `{}`          | Custom readiness probe command. When defined, it will override the default command |
| image.probes.readiness.initialDelaySeconds | `5`           | Initial delay seconds for readiness probe                                          |
| image.probes.readiness.timeoutSeconds      | `1`           | Timeout seconds for readiness probe                                                |
| image.probes.readiness.periodSeconds       | `10`          | Period seconds for readiness probe                                                 |
| image.probes.readiness.successThreshold    | `1`           | Success threshold for readiness probe                                              |
| image.probes.readiness.failureThreshold    | `3`           | Failure threshold for readiness probe                                              |
| image.probes.startup.enabled               | `false`       | Enable/disable startup probe                                                       |
| image.probes.startup.custom                | `{}`          | Custom startup probe command. When defined, it will override the default command   |
| image.probes.startup.initialDelaySeconds   | `15`          | Initial delay seconds for startup probe                                            |
| image.probes.startup.timeoutSeconds        | `5`           | Timeout seconds for startup probe                                                  |
| image.probes.startup.periodSeconds         | `20`          | Period seconds for startup probe                                                   |
| image.probes.startup.successThreshold      | `1`           | Success threshold for startup probe                                                |
| image.probes.startup.failureThreshold      | `10`          | Failure threshold for startup probe                                                |

### Parameters for associated containers

**Auth proxy**

| Parameter                   | Default value                                             | Description                                         |
|-----------------------------|-----------------------------------------------------------|-----------------------------------------------------|
| proxy.image.registry        | `gcr.io`                                                  | Docker registry name for the image                  |
| proxy.image.repository      | `kubebuilder`                                             | Docker image repository name                        |
| proxy.image.name            | `kube-rbac-proxy`                                         | Docker image name                                   |
| proxy.image.tag             | `v0.15.0`                                                 | Docker image tag                                    |
| proxy.image.digest          | `""`                                                      | Docker image digest, will override tag if specified |
| proxy.image.pullPolicy      | `IfNotPresent`                                            | Image pull policy                                   |
| proxy.image.pullSecrets     | `[]`                                                      | Array of secret names for image pull                |
| proxy.image.command         | `[]`                                                      | Override the default command                        |
| proxy.image.args            | `[]`                                                      | Override the default args                           |
| proxy.image.ports           | `[ { name: https, containerPort: 8443, protocol: TCP } ]` | Ports for the container                             |
| proxy.image.securityContext | `{}`                                                      | Security context for the container                  |
| proxy.image.resources       | `{}`                                                      | The resources for the container                     |
