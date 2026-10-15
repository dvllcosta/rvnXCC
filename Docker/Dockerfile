FROM golang:1.22-bookworm AS base

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
		git curl jq python3 python3-pip whois dnsutils ca-certificates \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /rvnXC
COPY . /rvnXC

RUN chmod +x install.sh rvnxc.sh \
	&& ./install.sh || true

ENV PATH="/root/go/bin:${PATH}"
ENTRYPOINT ["/rvnXC/rvnxc.sh"]
CMD ["-h"]
