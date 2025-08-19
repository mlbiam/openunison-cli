# Produce the CA bundle
FROM debian:bookworm-slim AS certs
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && update-ca-certificates \
 && rm -rf /var/lib/apt/lists/*

FROM scratch
ADD openunison-cli /openunison-cli

# CA bundle expected by most TLS libs (incl. Go's net/http)
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ENTRYPOINT ["/openunison-cli"]