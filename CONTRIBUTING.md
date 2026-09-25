# Contributing

Contributions should preserve scheduled, read-only Cyble polling, private ThreatStream ingestion, replay-safe progress, and accurate documentation of coverage.

## Work on a change

1. Open a focused issue describing the behavior, or explain it in your pull request.
2. Use a branch and an isolated development environment. Obtain the Anomali SDK separately if your change needs its real model behavior.
3. Add synthetic examples and focused tests for parser, mapping, retry, checkpoint, or ingestion behavior that changes.
4. Run the checks used by [CI](.github/workflows/ci.yml), and update relevant deployment/mapping documentation.
5. Describe the user-visible change, verification performed, and remaining live-integration limits in the pull request.

Do not add the SDK wheel/source, Cyble API guide, live tenant exports, tokens, tenant identifiers, or personal data to commits, issues, pull requests, screenshots, or fixtures. Use invented values such as reserved example domains and documentation IP addresses. Redaction must happen before all output paths, including summary context and explicit IOC rules.

Run the focused suite with:

```bash
python -m unittest discover -s tests -v
```

The real SDK contract checks run when the separately installed Anomali SDK is available; otherwise they are skipped. Passing synthetic checks does not establish a live tenant delivery.

## Add service mappings

State the service slug and the shape of its fields. Separate three claims: fields preserved in report JSON, fields extracted into native Indicators, and behavior verified against a real vendor runtime. A schema taken from one service does not establish another service's schema.

Include positive and negative synthetic cases. Consider false positives, private IPs, email/credential fields, JSON strings, malformed responses, pagination, and a retry after incomplete ingestion. Do not infer maliciousness simply because a string is a domain or URL.

## Review expectations

Keep changes focused, preserve existing configuration where practical, and document migrations. Never weaken TLS, log raw payloads, advance a failed checkpoint, or claim successful tenant ingestion from an offline test. Logo changes must use authentic vendor assets, preserve their appearance, and update [source attribution](assets/README.md).

This project is community maintained. Vendor-specific account, licensing, quota, or platform issues should also be raised through the appropriate vendor support channel.
