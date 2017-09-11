with import (builtins.fetchTarball "https://d3g5gsiof5omrk.cloudfront.net/nixos/unstable-small/nixos-17.09pre113137.1eb48d3b08/nixexprs.tar.xz") {};

stdenv.mkDerivation rec {
  name = "tk-ssh-agent-env";
  env = buildEnv { name = name; paths = buildInputs; };

  buildInputs = [
    go
    upx
    gocode
    golint
  ];
}
