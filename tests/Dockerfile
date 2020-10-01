# base stage
FROM golang:1.13-alpine3.11 AS base

RUN apk add --no-cache git ca-certificates

WORKDIR $GOPATH/src/github.com/shellhub-io/shellhub

COPY ./go.mod ./

WORKDIR $GOPATH/src/github.com/shellhub-io/shellhub/tests

COPY ./go.mod ./go.sum ./

RUN go mod download

# builder stage
FROM base AS builder

#COPY ./pkg $GOPATH/src/github.com/shellhub-io/shellhub/pkg
COPY ./tests . 

WORKDIR $GOPATH/src/github.com/shellhub-io/shellhub

RUN go mod download

WORKDIR $GOPATH/src/github.com/shellhub-io/shellhub/tests

RUN go mod download

RUN CGO_ENABLED=0 go test -c

# development stage
FROM base AS development

RUN apk add --update openssl build-base docker-cli
RUN go get github.com/markbates/refresh && go get github.com/mgechev/revive


RUN go mod download

WORKDIR $GOPATH/src/github.com/shellhub-io/shellhub/tests
COPY  --from=builder /go/src/github.com/shellhub-io/shellhub/tests/tests.test  /tests.test 
ENTRYPOINT /tests.test



# production stage
FROM alpine:3.11 AS production

COPY --from=builder /go/src/github.com/shellhub-io/shellhub/tests/tests /tests

ENTRYPOINT /tests


