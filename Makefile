LDFLAGS="-w -s"

all: build

build:
	go build

clean:
	rm -f /tmp/tk-ssh-auth.sock
	rm -f tk-ssh-agent
