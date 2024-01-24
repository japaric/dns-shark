FROM rust:1.75

WORKDIR /usrc/src/dns-shark
COPY . .

RUN apt-get update && apt-get install -y bind9-dnsutils tshark
