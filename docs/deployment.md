<!--
Copyright (c) Subzero Development Team.
Distributed under the terms of the Modified BSD License.
-->

# Deployment Guide

This guide covers deploying Subzero Zero Trust API Gateway in various environments.

## Deployment Options

1. **Standalone** - Single instance for development/testing
2. **Docker** - Containerized deployment
3. **Docker Compose** - Multi-service local deployment
4. **Kubernetes** - Production-grade orchestration
5. **Cloud Providers** - AWS, GCP, Azure deployment

## Prerequisites

- Python 3.11+ (for standalone)
- Docker 20+ (for container deployments)
- Kubernetes 1.24+ (for K8s deployments)
- Auth0 tenant with API configured
- Auth0 FGA store (optional, for authorization)
- Redis 6+ (recommended for production)

## Standalone Deployment

### 1. Install from PyPI

```bash
pip install subzero
```

### 2. Configure Environment

```bash
export AUTH0_DOMAIN="your-tenant.auth0.com"
export AUTH0_CLIENT_ID="your_client_id"
export AUTH0_AUDIENCE="https://your-api"
export FGA_STORE_ID="your_fga_store_id"
export REDIS_URL="redis://localhost:6379/0"
```

### 3. Run the Gateway

```bash
# Development mode
subzero --host=0.0.0.0 --port=8000 --log-level=DEBUG

# Production mode (with workers)
subzero --host=0.0.0.0 --port=8000 --workers=4
```

## Docker Deployment

### 1. Pull Image from GHCR

```bash
docker pull ghcr.io/vladparakhin/subzero:latest
```

### 2. Create Environment File

Create `.env` file:

```bash
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_CLIENT_ID=your_client_id
AUTH0_CLIENT_SECRET=your_client_secret
AUTH0_AUDIENCE=https://your-api
FGA_STORE_ID=your_fga_store_id
FGA_CLIENT_ID=your_fga_client
FGA_CLIENT_SECRET=your_fga_secret
REDIS_URL=redis://redis:6379/0
```

### 3. Run Container

```bash
docker run -d \
  --name subzero-gateway \
  -p 8000:8000 \
  --env-file .env \
  ghcr.io/vladparakhin/subzero:latest
```

### 4. Health Check

```bash
curl http://localhost:8000/health
```

## Docker Compose Deployment

### 1. Use Provided Configuration

```bash
# Clone repository
git clone https://github.com/vladparakhin/subzero.git
cd subzero

# Copy environment template
cp .env.example .env
# Edit .env with your configuration

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f subzero

# Stop services
docker-compose down
```

### 2. Services Included

- **subzero**: Main gateway service
- **redis**: Caching layer
- **prometheus**: Metrics (optional, with `--profile monitoring`)
- **grafana**: Dashboards (optional, with `--profile monitoring`)

### 3. Start with Monitoring

```bash
docker-compose --profile monitoring up -d
```

Access:
- Gateway: http://localhost:8000
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000

## Kubernetes Deployment

### 1. Create Namespace

```bash
kubectl create namespace subzero
```

### 2. Create Secrets

```bash
kubectl create secret generic subzero-secrets \
  --from-literal=auth0-client-secret=your_secret \
  --from-literal=fga-client-secret=your_fga_secret \
  --from-literal=redis-password=your_redis_password \
  -n subzero
```

### 3. Deploy Redis

```yaml
# redis.yaml
apiVersion: v1
kind: Service
metadata:
  name: redis
  namespace: subzero
spec:
  ports:
  - port: 6379
  selector:
    app: redis
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis
  namespace: subzero
spec:
  replicas: 1
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        ports:
        - containerPort: 6379
        command: ["redis-server", "--requirepass", "$(REDIS_PASSWORD)"]
        env:
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: subzero-secrets
              key: redis-password
```

### 4. Deploy Subzero

```yaml
# subzero-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: subzero
  namespace: subzero
spec:
  replicas: 3
  selector:
    matchLabels:
      app: subzero
  template:
    metadata:
      labels:
        app: subzero
    spec:
      containers:
      - name: subzero
        image: ghcr.io/vladparakhin/subzero:latest
        ports:
        - containerPort: 8000
        env:
        - name: AUTH0_DOMAIN
          value: "your-tenant.auth0.com"
        - name: AUTH0_CLIENT_ID
          value: "your_client_id"
        - name: AUTH0_CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: subzero-secrets
              key: auth0-client-secret
        - name: FGA_CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: subzero-secrets
              key: fga-client-secret
        - name: REDIS_URL
          value: "redis://:$(REDIS_PASSWORD)@redis:6379/0"
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: subzero-secrets
              key: redis-password
        resources:
          requests:
            cpu: "500m"
            memory: "512Mi"
          limits:
            cpu: "2000m"
            memory: "2Gi"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: subzero
  namespace: subzero
spec:
  type: LoadBalancer
  ports:
  - port: 80
    targetPort: 8000
  selector:
    app: subzero
```

### 5. Apply Configuration

```bash
kubectl apply -f redis.yaml
kubectl apply -f subzero-deployment.yaml
```

### 6. Enable Horizontal Pod Autoscaling

```yaml
# hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: subzero-hpa
  namespace: subzero
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: subzero
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

```bash
kubectl apply -f hpa.yaml
```

## Production Checklist

### Security

- [ ] Use TLS/HTTPS with valid certificates
- [ ] Store secrets in secret management system (Vault, AWS Secrets Manager)
- [ ] Enable authentication on Redis
- [ ] Configure network policies/firewalls
- [ ] Set up DDoS protection
- [ ] Enable rate limiting
- [ ] Configure CORS properly (not `*`)
- [ ] Enable security headers
- [ ] Review and harden Auth0 configuration

### Performance

- [ ] Configure appropriate cache size (`CACHE_CAPACITY`)
- [ ] Enable Redis for distributed caching
- [ ] Set worker count based on CPU cores
- [ ] Configure connection pools
- [ ] Enable multiprocessing if applicable
- [ ] Set appropriate timeouts
- [ ] Monitor cache hit ratios

### Reliability

- [ ] Deploy multiple replicas (min 3 for production)
- [ ] Configure health checks (liveness and readiness)
- [ ] Set up monitoring and alerting
- [ ] Configure log aggregation
- [ ] Enable distributed tracing
- [ ] Set up backup and disaster recovery
- [ ] Test failover scenarios

### Monitoring

- [ ] Enable Prometheus metrics
- [ ] Set up dashboards (Grafana)
- [ ] Configure alerts (PagerDuty, OpsGenie, etc.)
- [ ] Monitor key metrics:
  - Request rate (RPS)
  - Latency (p50, p95, p99)
  - Error rate
  - Cache hit ratio
  - Authentication success/failure
- [ ] Set up log aggregation (ELK, Splunk, etc.)
- [ ] Enable OpenTelemetry tracing

## Cloud Provider Deployments

### AWS

#### Using ECS

1. Create ECR repository
2. Push Docker image
3. Create ECS cluster
4. Create task definition with environment variables
5. Create service with load balancer
6. Configure Auto Scaling

#### Using EKS

1. Create EKS cluster
2. Configure kubectl
3. Follow Kubernetes deployment steps above
4. Use ALB Ingress Controller

### GCP

#### Using Cloud Run

```bash
gcloud run deploy subzero \
  --image=ghcr.io/vladparakhin/subzero:latest \
  --platform=managed \
  --region=us-central1 \
  --set-env-vars="AUTH0_DOMAIN=your-tenant.auth0.com" \
  --set-secrets="AUTH0_CLIENT_SECRET=auth0-secret:latest" \
  --allow-unauthenticated
```

#### Using GKE

1. Create GKE cluster
2. Configure kubectl
3. Follow Kubernetes deployment steps above

### Azure

#### Using Container Instances

```bash
az container create \
  --resource-group myResourceGroup \
  --name subzero \
  --image ghcr.io/vladparakhin/subzero:latest \
  --dns-name-label subzero-gateway \
  --ports 8000 \
  --environment-variables \
    AUTH0_DOMAIN=your-tenant.auth0.com \
    AUTH0_CLIENT_ID=your_client_id
```

#### Using AKS

1. Create AKS cluster
2. Configure kubectl
3. Follow Kubernetes deployment steps above

## Monitoring and Observability

### Prometheus Metrics

Subzero exposes metrics at `/metrics`:

```bash
curl http://localhost:8000/metrics
```

Key metrics:
- `subzero_requests_total` - Total requests
- `subzero_request_duration_seconds` - Request latency
- `subzero_cache_hits_total` - Cache hits
- `subzero_auth_success_total` - Authentication successes
- `subzero_auth_failures_total` - Authentication failures

### Grafana Dashboard

Import the provided dashboard:

```bash
# Located in etc/grafana/dashboards/subzero.json
```

### Log Aggregation

Configure structured logging:

```bash
export LOG_FORMAT=json
export LOG_LEVEL=INFO
```

Ship logs to:
- **ELK Stack**: Elasticsearch, Logstash, Kibana
- **Splunk**: Universal Forwarder
- **CloudWatch**: AWS Logs
- **Stackdriver**: GCP Logging

## Troubleshooting

### Common Issues

**Service won't start:**
- Check environment variables are set
- Verify Auth0 configuration
- Check Redis connectivity

**High latency:**
- Check Redis is healthy
- Verify cache hit ratio
- Check Auth0 response times
- Review worker/replica count

**Authentication failures:**
- Verify AUTH0_DOMAIN is correct
- Check AUTH0_AUDIENCE matches tokens
- Review Auth0 logs

**Memory issues:**
- Reduce CACHE_CAPACITY
- Check for memory leaks
- Review resource limits

### Debugging

```bash
# Enable debug logging
export LOG_LEVEL=DEBUG

# Check health endpoint
curl http://localhost:8000/health

# Check metrics
curl http://localhost:8000/metrics

# View container logs
docker logs subzero-gateway

# Kubernetes logs
kubectl logs -f deployment/subzero -n subzero
```

## Maintenance

### Upgrades

1. Review CHANGELOG for breaking changes
2. Test in staging environment
3. Backup configuration and data
4. Perform rolling update:

```bash
# Docker
docker pull ghcr.io/vladparakhin/subzero:latest
docker-compose up -d

# Kubernetes
kubectl set image deployment/subzero \
  subzero=ghcr.io/vladparakhin/subzero:new-version \
  -n subzero
```

### Backups

- Configuration files
- Redis data (if persistence enabled)
- Auth0 configuration export
- Monitoring dashboards

## References

- [Architecture](architecture.md)
- [Configuration Guide](configuration.md)
- [Security Policy](../SECURITY.md)
- [Contributing](../CONTRIBUTING.md)

---

**Last updated:** 2025-10-02
