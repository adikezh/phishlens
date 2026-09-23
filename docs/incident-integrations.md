# Incident integrations

PhishLens can create privacy-safe incidents in the configured destinations
when a verdict reaches `min_verdict`. The outbound payload contains the
submission id, verdict, score, confidence, signal IDs, domains, and attachment
hashes. It does not contain the message body or raw headers.

## Configuration

```yaml
integrations:
  iris:
    enabled: true
    api_url: https://iris.example
    api_key_env: IRIS_API_KEY
    customer_id: 1
    min_verdict: suspicious
  jira:
    enabled: true
    api_url: https://company.atlassian.net
    project_key: SOC
    issue_type: Task
    user_env: JIRA_USER
    token_env: JIRA_TOKEN
    min_verdict: suspicious
```

IRIS uses `POST /api/v2/cases` and a bearer API key. Jira uses
`POST /rest/api/3/issue`; when `user_env` is set it uses Basic authentication
with the user and token, otherwise it uses a bearer token. The configured
project and issue type must be permitted for the account.

The adapters are tested with local HTTP fixtures. A real deployment still
requires account, permission, TLS, rate-limit, and destination-specific
validation; those checks cannot be honestly replaced by unit tests.

References:

- [DFIR-IRIS API reference](https://docs.dfir-iris.org/latest/_static/iris_api_reference_v2.1.0.html)
- [DFIR-IRIS case endpoint schema](https://github.com/dfir-iris/iris-doc-src/blob/master/docs/api_reference/reference/v2.1.0/resources/api_v2_cases.yaml)
- [Jira Cloud issue REST API](https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/)
