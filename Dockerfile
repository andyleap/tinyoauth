FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/tinyoauth ./cmd/tinyoauth

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/tinyoauth /tinyoauth
USER nonroot:nonroot
EXPOSE 4180
ENTRYPOINT ["/tinyoauth"]
