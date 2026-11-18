# Responsible use

Network Scope sends network traffic to the targets you give it. Use it responsibly.

- **Authorized networks only.** Scan only networks and devices you own or are explicitly authorized to test. Unauthorized scanning may be illegal and may violate the terms of your network provider or employer.
- **OT and other fragile equipment.** Industrial controllers, medical devices and other embedded systems can fault under active probing, even with read-only requests. Safe Mode is the default; keep it on, prefer [passive discovery](ot-industrial.md#passive-ot-discovery), and coordinate with the people who operate the equipment. See [Safe Mode and OT safety](safe-mode-and-ot-safety.md).
- **No warranty.** Network Scope is provided "as is", without warranty of any kind, under the [MIT license](https://github.com/Sparkz400/network-scope/blob/main/LICENSE.txt). Findings and CVE entries are hints, not verified vulnerabilities.
- **Your responsibility.** You are responsible for complying with the laws, regulations and policies that apply to your use, including data protection rules for the inventory data you collect (host names, MAC addresses, captured metadata).
- **Sharing results.** Scan databases, reports and captures describe a network in detail. Store them accordingly, and redact IP addresses, MAC addresses and host names before posting them in issues.
