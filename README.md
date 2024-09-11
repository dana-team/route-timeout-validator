# route-timeout-validator

This project implements a Kubernetes admission webhook that validates `Route` objects in OpenShift. It ensures that `Routes` do not use `haproxy.router.openshift.io/timeout` above a certain threshold, controlled by an environment variable.

## Features

- Validates the `Route` timeout annotation format.
- Checks if the `Route` timeout value is within the specified maximum timeout.
- Supports bypassing `Route` timeout validation based on namespace labels.

## Configuration

- Max Timeout Seconds: Set the maximum timeout value allowed for `Routes`. Controlled by the `secondsTimeout` environment variable.
- Bypass Timeout Label: Defines the label key to be specified in a `Namespace` in order to bypass timeout validation. To bypass, put the following label of a namespace:
    ```bash
    ...redacted...
    metadata:
      labels:  
        haproxy.router.dana.io/bypass-timeout: true
    ...redacted...
    ```

## Getting started

### Deploying the controller

```bash
$ make deploy IMG=ghcr.io/dana-team/route-timeout-validator:<release>
```

### Install with Helm

Helm chart docs are available on `charts/route-timeout-validator` directory.

Make sure `cert-manager` is [installed](https://cert-manager.io/docs/installation/helm/) as a prerequisite.

```
$ helm upgrade --install route-timeout-validator --namespace route-timeout-system --create-namespace oci://ghcr.io/dana-team/helm-charts/route-timeout-validator --version <release>
```

#### Build your own image

```bash
$ make docker-build docker-push IMG=<registry>/route-timeout-validator:<tag>
```