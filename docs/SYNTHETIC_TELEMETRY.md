# Azure Monitor Logs Ingestion API: Synthetic Telemetry Architecture & Deployment Guide

This guide details the end-to-end architecture, Azure cloud provisioning, containerized deployment, and KQL verification workflow for injecting synthetic security telemetry into Microsoft Sentinel and Azure Log Analytics using the **Azure Monitor Logs Ingestion API**.

---

## 1. Architecture Overview

The Synthetic Telemetry Pipeline generates realistic security events (ArcSight CEF / ASIM schema compliant) and streams them directly into Azure Log Analytics via the high-throughput Azure Monitor Logs Ingestion API.

```
+-------------------------------------------------------------------------------+
|                       Synthetic Telemetry Ingestion Flow                      |
+-------------------------------------------------------------------------------+
|                                                                               |
|  +---------------------------+       HTTPS POST (OAuth2 Bearer Token)         |
|  |  ArcSight Migration Suite |----------------------------------------------+ |
|  |  (Backend Container)      |                                              | |
|  |  - Synthetic Generator    |                                              | |
|  |  - Telemetry Tuner Engine |                                              | |
|  +---------------------------+                                              | |
|                                                                             v |
|  +--------------------------------------------------------------------------+ |
|  |             Azure Data Collection Endpoint (DCE)                         | |
|  |             https://<dce-name>.<region>.ingest.monitor.azure.com         | |
|  +--------------------------------------------------------------------------+ |
|                                      |                                        |
|                                      v                                        |
|  +--------------------------------------------------------------------------+ |
|  |             Data Collection Rule (DCR)                                   | |
|  |             - Ingestion Stream: Custom-ArcSightSyntheticEvents_CL        | |
|  |             - Ingestion-time KQL Transformation                          | |
|  +--------------------------------------------------------------------------+ |
|                                      |                                        |
|                                      v                                        |
|  +--------------------------------------------------------------------------+ |
|  |             Azure Log Analytics Workspace / Microsoft Sentinel           | |
|  |             Destination Table: ArcSightSyntheticEvents_CL                | |
|  +--------------------------------------------------------------------------+ |
+-------------------------------------------------------------------------------+
```

### Key Architectural Pillars

1. **Direct Cloud Ingestion**: Utilizes the modern Azure Monitor Logs Ingestion REST API rather than legacy Log Analytics HTTP Data Collector API or Syslog forwarding agents.
2. **Schema Control & Ingestion-Time Filtering**: Data Collection Rules (DCR) parse and project raw JSON telemetry at ingestion time before indexing, lowering ingestion overhead and enabling KQL transformations.
3. **Decoupled Identity & Principle of Least Privilege**: Authenticates via Microsoft Entra ID (Service Principal) granted strictly the `Monitoring Metrics Publisher` role scoped directly to the DCR.
4. **State Decoupling**: Application and test state are isolated in a Docker named volume (`vault_data`), decoupling local filesystem paths from runtime containers across environments.

---

## 2. Azure Provisioning Steps

### Prerequisites
- Active Azure Subscription.
- Resource Group (e.g., `rg-arcsight-migration`).
- Azure Log Analytics Workspace linked to Microsoft Sentinel.
- Azure CLI (`az`) authenticated with administrative permissions.

---

### Step 1: Create Data Collection Endpoint (DCE)

The DCE serves as the public ingestion front-end for the Logs Ingestion API:

```bash
az monitor data-collection endpoint create \
  --name "dce-arcsight-synthetic" \
  --resource-group "rg-arcsight-migration" \
  --location "eastus" \
  --public-network-access "Enabled"
```

Capture the **Logs Ingestion URI** from the output (e.g., `https://dce-arcsight-synthetic-xxxx.eastus-1.ingest.monitor.azure.com`).

---

### Step 2: Create Custom Table in Log Analytics Workspace

Define the custom analytics table (suffixed with `_CL`) using the REST API or Azure CLI:

```bash
WORKSPACE_ID=$(az monitor log-analytics workspace show \
  --resource-group "rg-arcsight-migration" \
  --workspace-name "law-sentinel-core" \
  --query id -o tsv)

az rest --method put \
  --url "${WORKSPACE_ID}/tables/ArcSightSyntheticEvents_CL?api-version=2022-10-01" \
  --body '{
    "properties": {
      "schema": {
        "name": "ArcSightSyntheticEvents_CL",
        "columns": [
          { "name": "TimeGenerated", "type": "datetime" },
          { "name": "EventID", "type": "int" },
          { "name": "DeviceVendor", "type": "string" },
          { "name": "DeviceProduct", "type": "string" },
          { "name": "DeviceAction", "type": "string" },
          { "name": "SourceUserName", "type": "string" },
          { "name": "SourceIp", "type": "string" },
          { "name": "DestinationIp", "type": "string" },
          { "name": "DestinationPort", "type": "int" },
          { "name": "Severity", "type": "string" },
          { "name": "RawEvent", "type": "string" }
        ]
      },
      "retentionInDays": 30
    }
  }'
```

---

### Step 3: Create Data Collection Rule (DCR)

Create a configuration file `dcr-rule.json`:

```json
{
  "location": "eastus",
  "properties": {
    "dataCollectionEndpointId": "/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/rg-arcsight-migration/providers/Microsoft.Insights/dataCollectionEndpoints/dce-arcsight-synthetic",
    "streamDeclarations": {
      "Custom-ArcSightSyntheticEvents_CL": {
        "columns": [
          { "name": "TimeGenerated", "type": "datetime" },
          { "name": "EventID", "type": "int" },
          { "name": "DeviceVendor", "type": "string" },
          { "name": "DeviceProduct", "type": "string" },
          { "name": "DeviceAction", "type": "string" },
          { "name": "SourceUserName", "type": "string" },
          { "name": "SourceIp", "type": "string" },
          { "name": "DestinationIp", "type": "string" },
          { "name": "DestinationPort", "type": "int" },
          { "name": "Severity", "type": "string" },
          { "name": "RawEvent", "type": "string" }
        ]
      }
    },
    "destinations": {
      "logAnalytics": [
        {
          "workspaceResourceId": "/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/rg-arcsight-migration/providers/Microsoft.OperationalInsights/workspaces/law-sentinel-core",
          "name": "lawDestination"
        }
      ]
    },
    "dataFlows": [
      {
        "streams": [ "Custom-ArcSightSyntheticEvents_CL" ],
        "destinations": [ "lawDestination" ],
        "transformKql": "source",
        "outputStream": "Custom-ArcSightSyntheticEvents_CL"
      }
    ]
  }
}
```

Deploy the DCR:

```bash
az monitor data-collection rule create \
  --name "dcr-arcsight-synthetic" \
  --resource-group "rg-arcsight-migration" \
  --rule-file "dcr-rule.json"
```

Capture the **Immutable ID** from the DCR properties (`properties.immutableId`, e.g., `dcr-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`).

---

### Step 4: Register Entra Service Principal & Assign Role

Register an application in Microsoft Entra ID:

```bash
SP_OUTPUT=$(az ad sp create-for-rbac \
  --name "sp-arcsight-synthetic-ingest" \
  --skip-assignment)

APP_ID=$(echo $SP_OUTPUT | jq -r .appId)
CLIENT_SECRET=$(echo $SP_OUTPUT | jq -r .password)
TENANT_ID=$(echo $SP_OUTPUT | jq -r .tenant)
```

Assign the `Monitoring Metrics Publisher` role scoped to the DCR:

```bash
DCR_ID=$(az monitor data-collection rule show \
  --name "dcr-arcsight-synthetic" \
  --resource-group "rg-arcsight-migration" \
  --query id -o tsv)

az role assignment create \
  --assignee "$APP_ID" \
  --role "Monitoring Metrics Publisher" \
  --scope "$DCR_ID"
```

---

## 3. Container Setup & Configuration

### Environment Variables (`.env`)

Configure `.env` in the repository root (this file is excluded from git):

```env
# ==============================================================================
# ArcSight Migration Suite - Runtime Environment Secrets
# ==============================================================================

# LLM Providers
GEMINI_API_KEY=AIzaSy...
OPENAI_API_KEY=sk-...

# Application Security & Vault
VAULT_MASTER_KEY=
JWT_SECRET_KEY=<generate-a-long-random-secret>
VAULT_DB_PATH=/app/backend/data/vault.db

# Microsoft Sentinel & Azure Monitor Logs Ingestion API
AZURE_TENANT_ID=00000000-0000-0000-0000-000000000000
AZURE_CLIENT_ID=00000000-0000-0000-0000-000000000000
AZURE_CLIENT_SECRET=your_client_secret_here
SENTINEL_WORKSPACE_ID=00000000-0000-0000-0000-000000000000

# Azure Monitor Ingestion Pipeline Configuration
DCE_INGESTION_ENDPOINT=https://dce-arcsight-synthetic-xxxx.eastus-1.ingest.monitor.azure.com
DCR_IMMUTABLE_ID=dcr-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
CUSTOM_STREAM_NAME=Custom-ArcSightSyntheticEvents_CL
```

### Docker Compose Architecture

The application uses Docker named volumes (`vault_data`) to decouple SQLite database state from the host filesystem while maintaining persistence across rebuilds:

```yaml
services:
  backend:
    build:
      context: .
      dockerfile: Dockerfile.backend
    ports:
      - "8001:8001"
    env_file:
      - .env
    environment:
      - LM_STUDIO_BASE_URL=http://host.docker.internal:1234/v1
      - DEFAULT_LLM_MODEL=qwen2.5-coder-7b-instruct
      - SPLUNK_HOST=https://splunk:8089
      - SPLUNK_USER=admin
      - SPLUNK_PASSWORD=ChangeMe123!
      - AUDIT_DB_PATH=/app/backend/data/audit_history.db
      - VAULT_DB_PATH=/app/backend/data/vault.db
      - GIT_READY_OUTPUT_DIR=/app/backend/git_ready_output
    extra_hosts:
      - "host.docker.internal:host-gateway"
    volumes:
      - ./git_ready_output:/app/backend/git_ready_output
      - vault_data:/app/backend/data
    depends_on:
      - splunk
    restart: unless-stopped

  frontend:
    build:
      context: .
      dockerfile: Dockerfile.frontend
    ports:
      - "3000:3000"
    depends_on:
      - backend
    restart: unless-stopped

volumes:
  vault_data:
```

### Launch Stack

```bash
# Rebuild and start stack cleanly
docker compose down && docker compose up -d --build

# Verify container logs
docker compose logs -f backend
```

---

## 4. Ingestion Execution API Payload

When publishing synthetic events from Python, the service acquires an Entra token and dispatches to the DCE endpoint:

**Token Request**:
```http
POST https://login.microsoftonline.com/{{AZURE_TENANT_ID}}/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded

client_id={{AZURE_CLIENT_ID}}
&scope=https://monitor.azure.com//.default
&client_secret={{AZURE_CLIENT_SECRET}}
&grant_type=client_credentials
```

**Ingestion Post**:
```http
POST {{DCE_INGESTION_ENDPOINT}}/dataCollectionRules/{{DCR_IMMUTABLE_ID}}/streams/{{CUSTOM_STREAM_NAME}}?api-version=2023-01-01
Authorization: Bearer {{ACCESS_TOKEN}}
Content-Type: application/json

[
  {
    "TimeGenerated": "2026-09-10T20:30:00Z",
    "EventID": 4625,
    "DeviceVendor": "Microsoft",
    "DeviceProduct": "Windows",
    "DeviceAction": "LogonFailed",
    "SourceUserName": "svc-scanner",
    "SourceIp": "10.0.0.5",
    "DestinationIp": "10.0.0.20",
    "DestinationPort": 445,
    "Severity": "High",
    "RawEvent": "An account failed to log on. Subject: Security ID: S-1-0-0 Account Name: - Logon Type: 3"
  }
]
```

---

## 5. KQL Verification Queries

Execute the following verification queries in **Microsoft Sentinel > Logs** or the Log Analytics query workspace.

### 1. Ingestion Pipeline Heartbeat & Volume
Verify that synthetic records are arriving and indexing:

```kql
ArcSightSyntheticEvents_CL
| where TimeGenerated > ago(1h)
| summarize
    EventCount = count(),
    FirstIngested = min(TimeGenerated),
    LastIngested = max(TimeGenerated),
    SampleSources = make_set(SourceIp, 5)
  by DeviceVendor, DeviceProduct, DeviceAction
| order by EventCount desc
```

### 2. Detailed Record Schema & Sanitization Check
Ensure fields are properly extracted and dynamic expressions are preserved without syntax corruption:

```kql
ArcSightSyntheticEvents_CL
| where TimeGenerated > ago(24h)
| project TimeGenerated, EventID, SourceUserName, SourceIp, DestinationIp, DestinationPort, Severity, RawEvent
| order by TimeGenerated desc
| take 50
```

### 3. Noise Diagnostics Baseline & Exclusion Parity
Test the telemetry baselining logic used by the Telemetry Tuner:

```kql
ArcSightSyntheticEvents_CL
| where TimeGenerated > ago(7d)
| summarize TotalCount = count() by SourceUserName, SourceIp, bin(TimeGenerated, 1h)
| where TotalCount > 10
| order by TotalCount desc
```

### 4. Negative Exclusion Parity Test
Verify that negative exclusions generated by `apply_exclusions` filter noise cleanly:

```kql
ArcSightSyntheticEvents_CL
| where TimeGenerated > ago(7d)
| where SourceIp !in ('10.0.0.5', '192.168.1.100')
| where SourceUserName !in ('svc-scanner', 'healthcheck')
| summarize FilteredCount = count() by bin(TimeGenerated, 1h), DeviceAction
| order by TimeGenerated desc
```
