If you are familiar with [PolarDNS](https://github.com/oryxlabs/PolarDNS), this page will highlight
the differences for you to understand this product.

Here is a list of difference with [PolarDNS](https://github.com/oryxlabs/PolarDNS):
- 100% Go code.
- subdomain used to select a feature have been changed.

Some modules have been kept from [PolarDNS](https://github.com/oryxlabs/PolarDNS):
- `staticip` is very similar than `always`
- `emptyresponse` is the same than `empty1`
- `nullbytes` is the same than `empty2`
- `headeronly` is similar than `empty5`. Contrary to PolarDNS, this sent a header only with ANCOUNT > 1 for A record to make the packet invalid. 
- `headerquestion` is very similar than `empty6`. Contrary to [PolarDNS](https://github.com/oryxlabs/PolarDNS), this sent a header only with ANCOUNT > 1 for A record to make the packet invalid.
- `echo` is very similar than `queryback1`. `echo` guarantee a similar response than the bytes received. no changed, not even the QR flag.
- `mismatchid` is similar than `newid` but focus on ID mismatch and guarantee a mismatch
