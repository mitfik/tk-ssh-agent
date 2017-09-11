LDFLAGS="-w -s"

all: build

build:
	go build -ldflags $(LDFLAGS)
	# upx --brute ./tk-ssh-agent

clean:
	rm -f /tmp/tk-ssh-auth.sock
	rm -f tk-ssh-agent
