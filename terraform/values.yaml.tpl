replicaCount: ${replicas}

image:
  repository: ${image_repository}
  pullPolicy: IfNotPresent
  tag: "${image_tag}"

serviceAccount:
  create: true
  annotations:
    eks.amazonaws.com/role-arn: ${iam_role_arn}
  name: ${service_account}

podAnnotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "9090"

resources:
  limits:
    cpu: ${cpu_limit}
    memory: ${memory_limit}
  requests:
    cpu: ${cpu_request}
    memory: ${memory_request}

detection:
  mode: watch
  python: python3
  enginePath: /app/engines/iota/engine.py

  rules:
    repo: ${rules_repo}
    branch: ${rules_branch}
    path: ${rules_path}
    syncInterval: 5m

  eventsDir: /data/events
  stateFile: /data/state/iota.db

slack:
  enabled: ${slack_enabled}
  secretName: iota-slack-webhook
  secretKey: webhook-url

persistence:
  events:
    enabled: true
    existingClaim: ${events_pvc}
    accessMode: ReadWriteMany

  state:
    enabled: true
    storageClass: ${storage_class}
    accessMode: ReadWriteOnce
    size: ${state_pvc_size}

affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      podAffinityTerm:
        labelSelector:
          matchExpressions:
          - key: app.kubernetes.io/name
            operator: In
            values:
            - iota
        topologyKey: kubernetes.io/hostname
