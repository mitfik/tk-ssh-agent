LDFLAGS="-w -s"
BUILD_DIR=`pwd`
GOPATH=`pwd`/vendor

PKG_NAME="tk-ssh-agent"
PKG_MAINTAINER="adam@trustedkey.com"
PKG_DESCRIPTION="Trusted Key SSH agent"
PKG_LICENSE="GPL3"
PKG_VERSION=`git describe --tags --abbrev=0`

all: build

install:
	install -m 0755 tk-ssh-agent $(PREFIX)/bin/tk-ssh-agent

build:
	env CGO_ENABLED=0 GOPATH=$(GOPATH) go build -asmflags="-trimpath=$(BUILD_DIR)" -gcflags="-trimpath=$(BUILD_DIR)" -ldflags $(LDFLAGS) -o tk-ssh-agent

deb: build
	mkdir -p pkg/usr/bin/
	mkdir -p pkg/usr/lib/systemd/user/
	cp -a tk-ssh-agent pkg/usr/bin/
	cp -a systemd/* pkg/usr/lib/systemd/user/
	fpm -f -s dir -t deb -v $(PKG_VERSION) -n $(PKG_NAME) --license=$(PKG_LICENSE) --maintainer=$(PKG_MAINTAINER) --description=$(PKG_DESCRIPTION) -a native -C pkg/
	./scripts/sign_deb.py --deb tk-ssh-agent_$(PKG_VERSION)_amd64.deb

rpm: build
	mkdir -p pkg/usr/bin/
	cp -a tk-ssh-agent pkg/usr/bin/
	fpm -f -s dir -t rpm -v $(PKG_VERSION) -n $(PKG_NAME) --license=$(PKG_LICENSE) --maintainer=$(PKG_MAINTAINER) --description=$(PKG_DESCRIPTION) -a native --rpm-sign -C pkg/

clean:
	rm -rf pkg
	rm -f tk-ssh-agent
