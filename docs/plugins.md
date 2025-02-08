This documentation is auto-generated. Each plugin own its part of documentation based on [PluginSelfDescribing](internal/plugin.go) and [RegisteredDNSViolations](internal/plugin.go) interfaces.


## echo
This plugin reply the exact same bytes it receives.


#### Examples
`dig @localhost echo.foo.com`


## ednsformerr
This plugin reply FORMERR for any query with EDNS and a valid IP for query without EDNS.
Support for A record only.


#### Examples
`dig @localhost ednsformerr.foo.com +edns`

#### DNS Violation: [DVE-2020-0001](https://github.com/dns-violations/dns-violations/blob/master/2020/DVE-2020-0001.md)
## emptyresponse
This plugin reply an empty message.


#### Examples
`dig @localhost emptyresponse.foo.com`


## headeronly
This plugin truncates the response to the header only. The original response had 1 RR in ANSWER section.


#### Examples
`dig @localhost headeronly.foo.com`


## headerquestion
This plugin truncates the response to the header + question only. The original response had 1 RR in ANSWER section.


#### Examples
`dig @localhost headerquestion.foo.com`


## no-dobit-support
This plugin discard any packet that comes with EDNS0 DO bit to zero. Packet with DO to 1 will give a proper IP.
Support for A record only.


#### Examples
`dig @localhost no-dobit-support.foo.com +edns +nodnssec`

#### DNS Violation: [DVE-2018-0001](https://github.com/dns-violations/dns-violations/blob/master/2018/DVE-2018-0001.md)
## noednssupport
This plugin discard any packet that comes with OPT record.
Support for A record only.


#### Examples
`dig @localhost noednssupport.foo.com +edns`

#### DNS Violation: [DVE-2020-0004](https://github.com/dns-violations/dns-violations/blob/master/2020/DVE-2020-0004.md)
## nullbytes
This plugin responds with only NULL bytes.


#### Examples
`dig @localhost nullbytes.foo.com` with 1 NULL byte or `dig @localhost nullbytes.20.foo.com` for 20 NULL bytes


## soawrongsection
This plugin reply to SOA query by setting up the SOA in AUTHORITY section rather than ANSWER.
Support for SOA record only.


#### Examples
`dig @localhost soawrongsection.foo.com`

#### DNS Violation: [DVE-2020-0002](https://github.com/dns-violations/dns-violations/blob/master/2020/DVE-2020-0002.md)
## staticip
This plugin allow you to get returned a static IP (by default `127.0.0.1`) or define your own from the query.
Only support A record for now.


#### Examples
`dig @localhost staticip.foo.com` or `dig @localhost staticip.1.2.3.4.foo.com` to get `1.2.3.4` back in the ANSWER section.


## mismatchid
This plugin answer with a transaction ID mismatch


#### Examples
`dig @localhost mismatchid.foo.com`

