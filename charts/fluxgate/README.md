# Fluxgate Helm Chart

Standalone Helm chart for deploying **Fluxgate** alongside `traefik-ingress` in the same Kubernetes namespace (for example `ingress-prod`) as a pluggable, GitOps-driven hybrid traffic-scheduling extension.

## Design Boundaries

1. **Co-existence without replacement**: `traefik-ingress` remains the sole public K3s Ingress / TLS / Flagger Canary controller. If Fluxgate is not installed, removed, or unhealthy, `traefik-ingress` continues operating independently without impact.
2. **Sensitive credentials only in Vault KV**: Vault KV (`prod/serverless/cloudflare` keys `CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_API_TOKEN`) is reserved strictly for sensitive credentials (DNS updates / private tokens). Routing rules and proportional traffic weights (`80` / `20`) live exclusively in GitOps (`config.fluxgatefile`).
3. **Zero-downtime ConfigMap hot reload**: `/etc/fluxgate` mounts the ConfigMap directory directly (without `subPath`), so Fluxgate's 5-second config hash watcher reloads proportional weights via `ArcSwap` without restarting Pods.

## Installation (Independent HelmRelease in `ingress-prod`)

```bash
helm upgrade --install fluxgate charts/fluxgate \
  --namespace ingress-prod \
  --create-namespace \
  --set traefikExtension.enabled=true
```
