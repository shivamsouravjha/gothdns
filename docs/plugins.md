This documentation is auto-generated. Each plugin own its part of documentation based on [PluginSelfDescribing](internal/plugin.go) and [RegisteredDNSViolations](internal/plugin.go) interfaces.

## echo
This plugin reply the exact same bytes it receives.
#### Examples:
`dig @localhost echo.foo.com`

## edns-formerr
This plugin reply FORMERR with QUESTION section.
#### Examples:
`dig @localhost ednsformerr.foo.com +edns`
#### DNS Violation: [DVE-2020-0001](https://github.com/dns-violations/dns-violations/blob/master/2020/DVE-2020-0001.md)

## empty-response
This plugin reply an empty message.
#### Examples:
`dig @localhost empty-response.foo.com`

## header-only
This plugin truncates the response to the header only. The original response had 1 RR in ANSWER section.
#### Examples:
`dig @localhost header-only.foo.com`

## header-question
This plugin truncates the response to the header + question only. The original response had 1 RR in ANSWER section.
#### Examples:
`dig @localhost header-question.foo.com`

## no-edns-support
This plugin discard any packet that comes with OPT record.
#### Examples:
`dig @localhost no-edns-support.foo.com +edns`
#### DNS Violation: [DVE-2020-0004](https://github.com/dns-violations/dns-violations/blob/master/2020/DVE-2020-0004.md)

## null-bytes
This plugin responds with only NULL bytes.
#### Examples:
`dig @localhost null-bytes.foo.com` with 1 NULL byte or `dig @localhost null-bytes.20.foo.com` for 20 NULL bytes

## soa-wrong-section
This plugin reply to SOA query by setting up the SOA in AUTHORITY section rather than ANSWER.
#### Examples:
`dig @localhost soa-wrong-section.foo.com`
#### DNS Violation: [DVE-2020-0002](https://github.com/dns-violations/dns-violations/blob/master/2020/DVE-2020-0002.md)

## static-ip
This plugin allow you to get returned a static IP (by default `127.0.0.1`) or define your own from the query.
Only support A record for now.
#### Examples:
`dig @localhost static-ip.foo.com` or `dig @localhost static-ip.1.2.3.4.foo.com` to get `1.2.3.4` back in the ANSWER section.

## wrong-id
This plugin answer with a transaction ID mismatch
#### Examples:
`dig @localhost wrong-id.foo.com`

