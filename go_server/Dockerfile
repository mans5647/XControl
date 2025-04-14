FROM golang:latest

WORKDIR /x-server

COPY go.mod go.sum ./
RUN go mod download

COPY . .

CMD ["/bin/sh","-c", "/x-server/rungo.sh"]