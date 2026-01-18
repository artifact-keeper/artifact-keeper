# Test Docker image for E2E native client testing
FROM alpine:3.19

LABEL maintainer="test@artifact-keeper.local"
LABEL version="VERSION_PLACEHOLDER"
LABEL description="Test image for E2E native client testing"

RUN apk add --no-cache bash

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["--help"]
