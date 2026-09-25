# Security policy

Report suspected vulnerabilities privately to the repository owner. Do not file public issues containing credentials, real IOC payloads, tenant identifiers, or Cyble alert records.

Store Cyble and ThreatStream credentials in the feed runtime's secret store. Do not put secrets in source files, `.env` files committed to Git, command-line arguments, logs, or screenshots. The connector excludes known credential and personal-data fields, keeps feed visibility private, verifies TLS, and never logs API response bodies.
