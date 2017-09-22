LDFLAGS="-w -s"
BUILD_DIR=`pwd`
GOPATH=/home/adisbladis/sauce/verifiedid/tk-ssh-agent/vendor

all: build

build:
	env CGO_ENABLED=0 GOPATH=$(GOPATH) go build -asmflags="-trimpath=$(BUILD_DIR)" -gcflags="-trimpath=$(BUILD_DIR)" -ldflags $(LDFLAGS)

clean:
	rm -f tk-ssh-agent
