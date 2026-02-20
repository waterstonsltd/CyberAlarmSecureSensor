
# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in the CyberAlarm Secure Sensor, **please do not open a public GitHub issue.**

Instead, report it privately to:

**security@cyberalarm.police.uk**

To encrypt your report, use our PGP public key:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
xjMEaZhOjRYJKwYBBAHaRw8BAQdACZSNAmGtDDc3sukHQZC49A0COQpeT0Ip
Og9e1EqNiDvNPXNlY3VyaXR5QGN5YmVyYWxhcm0ucG9saWNlLnVrIDxzZWN1
cml0eUBjeWJlcmFsYXJtLnBvbGljZS51az7CwBMEExYKAIUFgmmYTo0DCwkH
CRCWnUCu11YavkUUAAAAAAAcACBzYWx0QG5vdGF0aW9ucy5vcGVucGdwanMu
b3JndHSj48sXUbVTy4jQd/NnUgwgnSqUzw3xi1LVZR7Fwd8FFQoIDgwEFgAC
AQIZAQKbAwIeARYhBOgaMgh/7phvf/e1j5adQK7XVhq+AAAiNgEAkv3v61Sk
M+rp5/juh5Xru+YTSAmOKmO8bQjO8/mx0D8BAI7mjmFI9CpDKi+7ar63OGyb
C2+ZZ3Xy1/HHXkawok0AzjgEaZhOjRIKKwYBBAGXVQEFAQEHQKMvTyu2YoML
6LgszJ8o/+7pxP8IhYM/+z0gfJiZUu8WAwEIB8K+BBgWCgBwBYJpmE6NCRCW
nUCu11YavkUUAAAAAAAcACBzYWx0QG5vdGF0aW9ucy5vcGVucGdwanMub3Jn
WM329sZxU8C3ZWsy1pV/syme/SwUWOntX+wTvfjm4wYCmwwWIQToGjIIf+6Y
b3/3tY+WnUCu11YavgAAhYMBALFsxcSSi8CvYOtjs1FAhrW/MagzeSmGmFuo
C6zjwYgdAQDowiU1F0A19TxzlQ9lGu1tIoIYjTX7iPbU93y+v4sLDw==
=xEQF
-----END PGP PUBLIC KEY BLOCK-----
```

**Fingerprint:** `E81A 3208 7FEE 986F 7FF7 B58F 969D 40AE D756 1ABE`

## What to Include

When reporting a vulnerability, please provide as much of the following as possible:

- A description of the vulnerability and its potential impact
- Steps to reproduce the issue
- Affected versions or components
- Any proof-of-concept code or screenshots

## What to Expect

| Step | Timeframe |
|------|-----------|
| Acknowledgement of your report | Within 48 hours |
| Initial assessment and severity triage | Within 5 working days |
| Regular progress updates | Throughout remediation |
| Fix deployed | Dependent on severity and complexity |

We will work with you to understand and remediate the issue, and will credit researchers appropriately in the release notes unless you prefer to remain anonymous.

## Scope

This policy covers the CyberAlarm Secure Sensor container image and the source code published in this repository. The central PCA platform, member portal, and other CyberAlarm infrastructure are out of scope for this repository — please report any issues with those systems directly to security@cyberalarm.police.uk.

## Guidelines

We ask that you:

- Give us reasonable time to investigate and address the issue before making any public disclosure
- Make a good faith effort to avoid accessing or modifying data that does not belong to you
- Do not exploit the vulnerability beyond what is necessary to demonstrate the issue
- Do not use the vulnerability to access, modify, or delete data belonging to other organisations

We will not pursue legal action against researchers who follow this policy in good faith.

## Supported Versions

Security updates are provided for the latest published release only. We strongly recommend enabling automatic updates or regularly pulling the latest container image.