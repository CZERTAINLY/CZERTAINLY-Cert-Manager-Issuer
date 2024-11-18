# CZERTAINLY-Cert-Manager-Issuer

> This repository is part of the open-source project CZERTAINLY. You can find more information about the project at [CZERTAINLY](https://github.com/CZERTAINLY/CZERTAINLY) repository, including the contribution guide.

CZERTAINLY Issuer is a implementation of the [cert-manager](https://cert-manager.io/) interface that allows to issue certificates using the CZERTAINLY platform.

## Getting started

Refer to [CZERTAINLY Cert-Manager Issuer](https://docs.czertainly.com/docs/certificate-key/integration-guides/cert-manager-issuer/overview) integration guide for more information.

## Generated CZERTAINLY OpenAPI client

The CZERTANILY client is generated from OpenAPI specification `doc-openapi-cert-manager.yaml` using [OpenAPI Generator](https://openapi-generator.tech/) and modified to work properly with the issuer implementation. All the changes are patched using the versioned patch files locatec in the [`openapi-patch`](openapi-patch) directory.

To regenerate and apply changes to the client, run the following command:
```bash
make openapi-generate
```

To clean the generated client, run the following command:
```bash
make openapi-clean
```

## Development Quick Start

Create new kind cluster for development purposes:
```bash
make kind-cluster deploy-cert-manager install install-rbac
```

This will create a new kind cluster, deploy cert-manager and install the CRDs of the CZERTAINLY issuer.
You can then run and debug the issuer implementation.

When you would like to remove the kind cluster and start over, run the following command:
```bash
make prune-kind-cluster
```
