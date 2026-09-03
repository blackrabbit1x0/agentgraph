FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/agentgraph ./cmd/agentgraph

FROM alpine:3.20
RUN adduser -D -u 10001 agentgraph
COPY --from=build /out/agentgraph /usr/local/bin/agentgraph
USER agentgraph
EXPOSE 8080
ENTRYPOINT ["agentgraph"]
CMD ["demo", "serve", "--addr", "0.0.0.0:8080"]
