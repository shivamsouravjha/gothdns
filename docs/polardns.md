If you are familiar with [PolarDNS](https://github.com/oryxlabs/PolarDNS), this page will highlight
the differences for you to understand this product.

Here is a list of difference with [PolarDNS](https://github.com/oryxlabs/PolarDNS):
- 100% Go code.
- subdomain used to select a feature have been changed.

Some modules have been kept from [PolarDNS](https://github.com/oryxlabs/PolarDNS):
- `static-ip` is very similar than `always`
- `empty-response` is the same than `empty1`
- `null-bytes` is the same than `empty2`
- `header-only` is similar than `empty5`. Contrary to PolarDNS, this sent a header only with ANCOUNT > 1 for A record to make the packet invalid. 
- `header-question` is very similar than `empty6`. Contrary to [PolarDNS](https://github.com/oryxlabs/PolarDNS), this sent a header only with ANCOUNT > 1 for A record to make the packet invalid.
- `echo` is very similar than `queryback1`. `echo` guarantee a similar response than the bytes received. no changed, not even the QR flag.
- `wrong-id` is similar than `newid` but focus on ID mismatch and guarantee a mismatch
