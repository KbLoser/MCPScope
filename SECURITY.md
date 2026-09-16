# Security Policy

This project is for authorized security assessments only.

Do not run it against a service unless you have written permission and a defined scope. `targets-discover` only queries public indexes and does not connect to candidate MCP services. `targets-scan` is active fingerprinting and requires an explicit authorization acknowledgement. The default `audit` command only performs MCP discovery and generates non-executing plans. A tool call requires both deterministic safety validation and a separate explicit authorization acknowledgement.

Do not report credentials, private keys, personal data, production business records, or unredacted raw responses in public GitHub issues. Use the local `data/` directory for evidence and keep it out of version control.

Report code or safety issues privately to the repository maintainers before public disclosure.
