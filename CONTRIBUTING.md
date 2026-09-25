# Contributing

Contributions should preserve the scheduled, read-only Cyble polling model and keep API keys, tenant identifiers, and alert contents out of commits, issue reports, and pull requests.

For a service-specific mapping, document the service slug and sanitized response field names. Use synthetic values only. Do not attach tenant alert exports or the proprietary Anomali wheel/source unless the owner has confirmed they may be shared.

Before enabling an additional service in a partner feed, review its payload for credentials, personal information, or other data that should not be distributed. Add explicit IOC paths to the JSON field map when a service uses nonstandard names.
