LDFLAGS="-w -s"
BUILD_DIR=`pwd`
GOPATH=`pwd`/vendor

all: build

install:
	install -m 0755 tk-ssh-agent /usr/local/bin/tk-ssh-agent

build:
	env CGO_ENABLED=0 GOPATH=$(GOPATH) go build -asmflags="-trimpath=$(BUILD_DIR)" -gcflags="-trimpath=$(BUILD_DIR)" -ldflags $(LDFLAGS) -o tk-ssh-agent

compress:
	upx tk-ssh-agent

clean:
	rm -f tk-ssh-agent
