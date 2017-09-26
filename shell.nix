with import (builtins.fetchTarball "https://d3g5gsiof5omrk.cloudfront.net/nixpkgs/nixpkgs-18.03pre116369.14cbeaa892/nixexprs.tar.xz") {};

stdenv.mkDerivation rec {
  name = "tk-ssh-agent-env";
  env = buildEnv { name = name; paths = buildInputs; };

  buildInputs = [
    go
    upx
    gocode
    golint
    libnotify
  ];
}
