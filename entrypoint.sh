#!/bin/bash
set -e

if [ "${HTTPS}" = "true" ]; then
    CERT=/data/cert.pem
    KEY=/data/key.pem
    if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
        echo "Generating self-signed certificate..."
        openssl req -x509 -newkey rsa:4096 \
            -keyout "$KEY" -out "$CERT" \
            -days 3650 -nodes \
            -subj "/CN=cyberready" \
            -addext "subjectAltName=IP:127.0.0.1" 2>/dev/null
        echo "Certificate generated at $CERT"
    fi
    exec uvicorn main:app --host 0.0.0.0 --port 8443 \
        --ssl-keyfile "$KEY" --ssl-certfile "$CERT"
else
    exec uvicorn main:app --host 0.0.0.0 --port 8080
fi
