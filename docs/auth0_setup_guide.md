<!--
Copyright (c) Subzero Development Team.
Distributed under the terms of the Modified BSD License.
-->

# Auth0 Complete Setup Guide
## Zero Trust API Gateway Configuration

### 1. Auth0 Application Setup (Private Key JWT)

#### Step 1: Create Application
```bash
# Via Auth0 CLI (recommended)
auth0 apps create \
  --name "Zero Trust API Gateway" \
  --type "machine-to-machine" \
  --reveal-secrets

# Note the CLIENT_ID and CLIENT_SECRET (though secret won't be used)
```

#### Step 2: Configure Private Key JWT
```json
{
  "name": "Zero Trust API Gateway",
  "app_type": "non_interactive",
  "token_endpoint_auth_method": "private_key_jwt",
  "grant_types": [
    "urn:ietf:params:oauth:grant-type:jwt-bearer"
  ],
  "jsonWebKeys": {
    "keys": [
      {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": "your_client_id_rsa_key_2025",
        "n": "YOUR_PUBLIC_KEY_MODULUS",
        "e": "AQAB"
      }
    ]
  }
}
```

#### Step 3: Generate and Register Public Key
```python
# Run this to generate JWKS for Auth0 configuration
from src.auth.auth0_integration import Auth0IntegrationManager, create_auth0_config_from_env

config = create_auth0_config_from_env()
integration = Auth0IntegrationManager(config)

# Get JWKS for Auth0 configuration
jwks = integration.get_public_key_for_auth0_config()
print(json.dumps(jwks, indent=2))

# Copy this JWKS to your Auth0 application settings
```

### 2. Auth0 FGA Setup

#### Step 1: Create FGA Store
```bash
# Using FGA CLI
fga store create --name "Zero Trust Gateway Store"

# Note the STORE_ID
export AUTH0_FGA_STORE_ID="your_store_id_here"
```

#### Step 2: Create Authorization Model
```json
{
  "schema_version": "1.1",
  "type_definitions": [
    {
      "type": "user"
    },
    {
      "type": "document",
      "relations": {
        "reader": {
          "this": {}
        },
        "writer": {
          "this": {}
        },
        "owner": {
          "this": {}
        },
        "viewer": {
          "union": {
            "child": [
              {
                "this": {}
              },
              {
                "tupleToUserset": {
                  "tupleset": {
                    "relation": "reader"
                  },
                  "computedUserset": {
                    "relation": "viewer"
                  }
                }
              }
            ]
          }
        }
      },
      "metadata": {
        "relations": {
          "reader": {
            "directly_related_user_types": [
              {
                "type": "user"
              }
            ]
          },
          "writer": {
            "directly_related_user_types": [
              {
                "type": "user"
              }
            ]
          },
          "owner": {
            "directly_related_user_types": [
              {
                "type": "user"
              }
            ]
          }
        }
      }
    },
    {
      "type": "api_endpoint",
      "relations": {
        "accessor": {
          "this": {}
        },
        "admin": {
          "this": {}
        }
      },
      "metadata": {
        "relations": {
          "accessor": {
            "directly_related_user_types": [
              {
                "type": "user"
              }
            ]
          },
          "admin": {
            "directly_related_user_types": [
              {
                "type": "user"
              }
            ]
          }
        }
      }
    }
  ]
}
```

#### Step 3: Deploy Authorization Model
```bash
# Save model to file: authorization_model.json
fga model write --store-id $AUTH0_FGA_STORE_ID --file authorization_model.json

# Note the MODEL_ID
export AUTH0_FGA_MODEL_ID="your_model_id_here"
```

### 3. Auth0 Management API Setup

#### Step 1: Create Management API Application
```bash
# Create Machine-to-Machine app for Management API
auth0 apps create \
  --name "ZTAG Management API Client" \
  --type "machine-to-machine" \
  --apis "https://YOUR_DOMAIN.auth0.com/api/v2/" \
  --scopes "read:users,update:users,read:user_metadata,update:user_metadata"
```

#### Step 2: Get Management API Token
```python
import requests

def get_management_api_token():
    url = f"https://{AUTH0_DOMAIN}/oauth/token"

    payload = {
        "client_id": "MANAGEMENT_API_CLIENT_ID",
        "client_secret": "MANAGEMENT_API_CLIENT_SECRET",
        "audience": f"https://{AUTH0_DOMAIN}/api/v2/",
        "grant_type": "client_credentials"
    }

    response = requests.post(url, json=payload)
    return response.json()["access_token"]
```

### 4. Token Vault Setup (Auth for GenAI)

#### Step 1: Register for Auth for GenAI Preview
```bash
# Contact Auth0 Sales for Auth for GenAI preview access
# Expected availability: April 2025
```

#### Step 2: Configure Token Vault Endpoint
```env
AUTH0_TOKEN_VAULT_ENDPOINT=https://api.auth0.com/token-vault/v1
AUTH0_TOKEN_VAULT_API_KEY=your_token_vault_api_key
```

### 5. Complete Environment Configuration

Create `.env` file with all required settings:

```env
# Core Auth0 Configuration
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_CLIENT_ID=your_client_id
AUTH0_CLIENT_SECRET=your_client_secret  # Not used with Private Key JWT
AUTH0_AUDIENCE=https://your-api-identifier

# Management API
AUTH0_MANAGEMENT_TOKEN=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiI...

# Auth0 FGA Configuration
AUTH0_FGA_STORE_ID=01HQRK9X5P8NWF6PS3WXMQTS1R
AUTH0_FGA_CLIENT_ID=your_fga_client_id
AUTH0_FGA_CLIENT_SECRET=your_fga_client_secret
AUTH0_FGA_API_URL=https://api.us1.fga.dev
AUTH0_FGA_MODEL_ID=01HQRK9X5P8NWF6PS3WXMQTS1R

# Token Vault (Auth for GenAI)
AUTH0_TOKEN_VAULT_ENDPOINT=https://api.auth0.com/token-vault/v1
AUTH0_TOKEN_VAULT_API_KEY=your_token_vault_api_key

# Performance Settings
CACHE_CAPACITY=65536
MAX_CONNECTIONS=1000
CONNECTION_POOL_SIZE=100
```

### 6. Verification Scripts

#### Test Private Key JWT Authentication
```python
import asyncio
from src.auth.auth0_integration import Auth0IntegrationManager, create_auth0_config_from_env

async def test_private_key_jwt():
    config = create_auth0_config_from_env()
    integration = Auth0IntegrationManager(config)

    # Test authentication
    result = await integration.authenticate_with_private_key_jwt(
        user_id="test_user_123",
        scopes="openid profile email"
    )

    print("Private Key JWT Test:")
    print(f"Success: {result['success']}")
    if result['success']:
        print(f"Access Token: {result['token_data']['access_token'][:20]}...")
    else:
        print(f"Error: {result['error']}")

    await integration.close()

# Run test
asyncio.run(test_private_key_jwt())
```

#### Test FGA Integration
```python
async def test_fga_integration():
    config = create_auth0_config_from_env()
    integration = Auth0IntegrationManager(config)

    # Write a test relationship
    write_result = await integration.write_fga_relationship(
        user_id="test_user_123",
        object_type="document",
        object_id="test_doc_456",
        relation="reader"
    )

    print("FGA Write Test:")
    print(f"Success: {write_result['success']}")

    # Check the permission
    check_result = await integration.check_fga_permission(
        user_id="test_user_123",
        object_type="document",
        object_id="test_doc_456",
        relation="reader"
    )

    print("FGA Check Test:")
    print(f"Allowed: {check_result['allowed']}")

    await integration.close()

# Run test
asyncio.run(test_fga_integration())
```

#### Complete Health Check
```python
async def run_complete_health_check():
    config = create_auth0_config_from_env()
    integration = Auth0IntegrationManager(config)

    health_status = await integration.get_integration_health_status()

    print("Auth0 Integration Health Check:")
    print(f"Overall Status: {health_status['overall_status']}")

    for service, status in health_status['checks'].items():
        print(f"  {service}: {status['status']}")
        if 'error' in status:
            print(f"    Error: {status['error']}")

    await integration.close()

# Run health check
asyncio.run(run_complete_health_check())
```

### 7. Production Deployment Checklist

- [ ] Private Key JWT configured in Auth0 application
- [ ] Public key (JWKS) registered with Auth0
- [ ] FGA store created with appropriate authorization model
- [ ] Management API access configured with minimal required scopes
- [ ] Token Vault configured for AI agent credentials
- [ ] Environment variables set in production
- [ ] Health check endpoints configured
- [ ] Monitoring and alerting set up
- [ ] Rate limiting configured
- [ ] SSL/TLS certificates configured
- [ ] Backup and disaster recovery plan in place

### 8. Troubleshooting Guide

#### Common Issues

**Private Key JWT Failed:**
- Verify JWKS is correctly configured in Auth0 application
- Check JWT assertion claims (iss, aud, exp)
- Ensure key ID (kid) matches between JWT header and JWKS

**FGA Permission Check Failed:**
- Verify store ID and model ID are correct
- Check if authorization model supports the relationship
- Ensure tuple was written before checking permission

**Management API Access Denied:**
- Verify Management API token has required scopes
- Check if token has expired
- Ensure client is authorized for Management API

**Token Vault Unavailable:**
- Verify Auth for GenAI preview access
- Check Token Vault endpoint configuration
- Ensure API key is valid and has required permissions