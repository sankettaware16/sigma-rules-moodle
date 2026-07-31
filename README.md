# Sigma Rules for Moodle

Detection rules for the Moodle learning management system, written against web server access logs.

Moodle is one of the most widely deployed applications in the education sector and there is currently
no public Sigma coverage for it. This pack is a starting point: twelve rules covering credential
attacks, web service token abuse, bulk personal data collection, web shells, and reconnaissance.

## Layout

```
rules/web/moodle/      Rules intended for upstream contribution to SigmaHQ
internal/              Organisation-specific rules - NOT for upstream
pipelines/             pySigma conversion pipeline and placeholder examples
```

## Log source

All upstream rules use `logsource: category: webserver` and the W3C field names defined in the
[Sigma taxonomy appendix](https://sigmahq.io/sigma-specification/specification/sigma-appendix-taxonomy.html)
for that category:

| Sigma field     | Meaning              | ECS equivalent             |
| --------------- | -------------------- | -------------------------- |
| `c-ip`          | client address       | `source.ip`                |
| `cs-method`     | HTTP method          | `http.request.method`      |
| `cs-uri-stem`   | request path         | `url.path`                 |
| `cs-uri-query`  | query string         | `url.query`                |
| `sc-status`     | HTTP status code     | `http.response.status_code`|
| `cs-user-agent` | user agent           | `user_agent.original`      |
| `cs-referer`    | referrer             | `http.request.referrer`    |

Apache and nginx combined log formats record path and query as a single request field. If your ingest
pipeline does not split them, either split them at parse time or adjust `cs-uri-stem` matches to
`contains` before converting.

## Converting

```bash
pip install sigma-cli pysigma-backend-elasticsearch
sigma convert -t lucene -p pipelines/moodle_ecs_apache.yml rules/web/moodle/
```

Edit the `event.module` value in the pipeline's `moodle_scope_to_log_source` transformation first so
converted queries are scoped to your Moodle access logs rather than every web log you collect.

Correlation rules require a backend that supports them. At time of writing support is uneven; if your
backend does not, convert the base rules and implement the aggregation natively (an Elastic threshold
rule, a Splunk `stats` clause, and so on). The base rule and its correlation live in the same file,
separated by `---`.

## Rules

### Credential access

| Rule | Trigger |
| ---- | ------- |
| `web_moodle_login_brute_force.yml` | 15 failed logins from one source in 5 minutes |
| `web_moodle_webservice_token_brute_force.yml` | 20 requests to `/login/token.php` from one source in 10 minutes |
| `web_moodle_session_key_reuse.yml` | one `sesskey` value presented from 3+ source addresses in 30 minutes |

Two things worth knowing about Moodle's login behaviour, both of which quietly break rules written
the obvious way:

- **Failed logins return HTTP 200**, not 401 or 403. Moodle re-renders the login form with an error
  message. A successful login returns a 30x redirect. Any rule filtering `/login/index.php` on 4xx
  status codes will never fire.
- **`/login/token.php` returns HTTP 200 with a JSON error body** for bad credentials. Status codes
  cannot separate success from failure there either, so the token rule keys on request rate.

### Collection and exfiltration

| Rule | Trigger |
| ---- | ------- |
| `web_moodle_webservice_sensitive_wsfunction_call.yml` | 20 calls to bulk user/enrolment/grade `wsfunction`s in 5 minutes |
| `web_moodle_bulk_assignment_submission_download.yml` | 50 individual submission file downloads in 5 minutes |

### Execution and persistence

| Rule | Trigger |
| ---- | ------- |
| `web_moodle_php_execution_in_upload_path.yml` | 200 response for a `.php` file under a Moodle upload or static path |
| `web_moodle_executable_download_from_file_storage.yml` | executable or script served through `pluginfile.php` |
| `web_moodle_cron_endpoint_external_access.yml` | `/admin/cron.php` requested from a non-private address |

### Reconnaissance and availability

| Rule | Trigger |
| ---- | ------- |
| `web_moodle_path_enumeration.yml` | 30 404s across Moodle paths from one source in 5 minutes |
| `web_moodle_webservice_server_errors.yml` | 10 5xx responses from the web service endpoint in 5 minutes |
| `web_moodle_ajax_service_flood.yml` | 200 AJAX service requests from one source in 2 minutes |
| `web_moodle_admin_interface_external_access.yml` | successful `/admin/` access from a non-private address |

## Tuning

Every threshold in this pack is a starting value, not a recommendation. Two environment properties
dominate the false positive rate:

**Shared egress addresses.** If your users reach Moodle through campus NAT, a corporate proxy or a
carrier network, a single `c-ip` represents thousands of people. The rate-based rules — AJAX flood,
path enumeration, login brute force — will fire constantly. Either raise the thresholds substantially
or exclude those ranges and rely on other signals for internal traffic.

**Reverse proxies.** If the web server logs the proxy address rather than the true client, every
`c-ip|cidr` filter in this pack inverts: the CIDR rules will match nothing, and the geolocation rules
in `internal/` will produce no useful output. Confirm you are logging `X-Forwarded-For` before
deploying anything that keys on client address.

### Improving the session key rule

`web_moodle_session_key_reuse.yml` groups on the raw query string, which only groups requests whose
full query is byte-identical — so it under-detects. To fix it, extract the sesskey value into its own
field at ingest and change `group-by` to that field. With an Elastic ingest pipeline:

```json
{
  "grok": {
    "field": "url.query",
    "patterns": ["sesskey=%{WORD:moodle.sesskey}"],
    "ignore_missing": true,
    "ignore_failure": true
  }
}
```

Then `group-by: [moodle.sesskey]`. That change turns an approximation into a reliable session
hijacking detection.

## Coverage gaps

These rules see web access logs only, which means they cannot see anything that does not change the
URL. In particular they cannot detect role assignments, capability overrides, web service token
creation, site configuration changes, or plugin installation — all of which are the privilege
escalation steps that matter most on a Moodle site.

That activity is visible in Moodle's own event log (`\core\event\role_assigned`,
`\core\event\webservice_token_created`, `\core\event\config_log_created` and so on), which can be
shipped to a SIEM using one of the `logstore_*` plugins. Rules for those events would need a
`category: application, product: moodle` log source that does not exist in the Sigma taxonomy yet, and
adding it would need a proposal to the specification repository. It is the obvious next piece of work.

## Licence

Intended for contribution to SigmaHQ under the
[Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License).
