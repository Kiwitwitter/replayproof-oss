# Security policy

## Responsible reporting

Please avoid publishing credentials or private endpoint information in issues or pull requests. Until a dedicated security contact is configured, use GitHub's private vulnerability reporting feature **if enabled**; otherwise ask maintainers in a public issue for a private reporting channel without disclosing sensitive details.

## Authorized use only

ReplayProof sends synthetic webhook-like traffic and may reset fixture state. Run it only against isolated local or staging systems you own or are expressly authorized to test. Never run it against third-party production endpoints without consent.

The remote-target safeguards are defense-in-depth, not permission to scan.

## Supported versions

This repository is an early prototype. No maintained stable release or security SLA is currently promised.
