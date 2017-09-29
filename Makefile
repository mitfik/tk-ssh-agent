LDFLAGS="-w -s"
BUILD_DIR=`pwd`
GOPATH=`pwd`/vendor

CHECK_PKGNAME="tk-ssh-agent"
CHECK_MAINTAINER="adam@trustedkey.com"
CHECK_LICENSE="Unknown"
CHECK_VERSION=`cat VERSION`

all: build

install:
	install -m 0755 tk-ssh-agent $(PREFIX)/bin/tk-ssh-agent

build:
	env CGO_ENABLED=0 GOPATH=$(GOPATH) go build -asmflags="-trimpath=$(BUILD_DIR)" -gcflags="-trimpath=$(BUILD_DIR)" -ldflags $(LDFLAGS) -o tk-ssh-agent

deb: build compress
	env PREFIX=/usr checkinstall -D -y --install=no --backup=no --nodoc --pkgname=$(CHECK_PKGNAME) --maintainer=$(CHECK_MAINTAINER) --pkglicense=$(CHECK_LICENSE) --pkgversion=$(CHECK_VERSION) -A amd64

compress:
	upx tk-ssh-agent

clean:
	rm -f tk-ssh-agent
