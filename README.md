# Kubewarden probes validation policy

This policy validates that all containers have livenessProbe and readinessProbe
defined. As well as ensure that some basic configuration are defined on them.

## Settings

This policy configuration allows users to define if they want to enforce both
liveness and readiness probes or only one of them in the containers definition.

```yaml
settings:
  liveness:
    enforce: true
  readiness:
    enforce: true
```
