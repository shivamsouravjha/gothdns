`gothDNS` (short version of Go Authoritative DNS) is a DNS authoritative server written in Go able to re-play a list of
DNS unusual cases in order to test the resilience of DNS resolvers.

`gothDNS` is highly inspired from [PolarDNS](https://github.com/oryxlabs/PolarDNS).

## What the difference with PolarDNS?

### A tool by developers for developers

[PolarDNS](https://github.com/oryxlabs/PolarDNS) is more oriented research with a python code and a lot of customisable 
options of the DNS packet. `gothDNS` focus on scenarios that would act as end-to-end & resilience tests.

`gothDNS` also offers a very clear API and testing framework that allows to write quickly any modules by any Go developers.

### New features
- Docker image is publicly available
- entirely fully tested, along with the proper CI
- DNS violations as a new feature
- a clear SDK to write custom modules. It can manipulate whole messages thanks to [miekg/dns](https://github.com/miekg/dns)
or raw bytes of DNS packet with the [PacketParser](packet/parser.go)

### What is coming soon?
- GitHub workflow to integrated gothDNS easily

## How to run it?

```
docker run -d -p 53:53/udp -p 53:53/tcp --name gothdns blanchonvincent/go-polardns:main

dig @127.0.0.1 -p 53 static-ip.foo.com
```

## Documentation

1. [Difference with PolarDNS](docs/polardns.md)
2. [Plugins](docs/plugins.md)


