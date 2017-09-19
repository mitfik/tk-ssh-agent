LDFLAGS="-w -s"

all: build

install:
	install -m 0755 tk-ssh-agent /usr/local/bin/tk-ssh-agent

install-deps:
	env GOPATH=`pwd`/go go get -d ./...

build:
	env CGO_ENABLED=0 GOPATH=`pwd`/go go build -ldflags $(LDFLAGS)

clean:
	rm -f tk-ssh-agent
