let
  inherit (builtins)
    fetchTarball
  ;
  inherit (pkgs)
    writeScript
    stdenv
  ;

  config = {};
  pkgs = import <nixpkgs> { inherit config; };

  shellWrapper = writeScript "shell-wrapper" ''
    #! ${stdenv.shell}
    set -e

    exec -a shell ${pkgs.fish}/bin/fish --login --interactive "$@"
  '';
in stdenv.mkDerivation rec {
  name = "nix-shell";
  buildInputs = with pkgs; [
    glibcLocales bashInteractive man
    nix cacert curl utillinux coreutils
    git jq yq-go tmux findutils gnumake

    skopeo
    go gopls golangci-lint delve
  ];
  hardeningDisable = [ "fortify" ];
  shellHook = ''
    export root=$(pwd)

    export LANG="en_US.UTF-8"

    if [ -f .env ]
    then
      source .env
    fi

    if [ ! -z "$PS1" ]
    then
      export SHELL="${shellWrapper}"
      exec "$SHELL"
    fi
  '';
}
