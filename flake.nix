{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    gomod2nix = {
      url = "github:nix-community/gomod2nix";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
      };
    };
  };

  outputs = inputs:
    with inputs; let
      inherit (self) outputs;
    in
      flake-utils.lib.eachDefaultSystem (
        system: let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [
              gomod2nix.overlays.default
              overlay
            ];
          };
          overlay = final: prev: {
            ebpf-netem = final.buildGoApplication rec {
              name = "ebpf-netem";
              version = "1.0.0";
              pwd = ./.;
              src = ./.;
              modules = ./gomod2nix.toml;
              nativeBuildInputs = with prev; [
                buildPackages.clang
                buildPackages.llvm
                glibc_multi
                libbpf
              ];
              buildInputs = with prev; [
                glibc_multi
                libbpf
              ];

              preBuild = ''
                go generate ./cmd/...
              '';
            };
          };
          goEnv = pkgs.mkGoEnv {pwd = ./.;};
        in {
          formatter = pkgs.alejandra;
          devShells.default = pkgs.mkShell {
            packages =
              (with pkgs; [
                gomod2nix
                goEnv
                gopls
              ])
              ++ pkgs.ebpf-netem.buildInputs
              ++ pkgs.ebpf-netem.nativeBuildInputs;
          };
          packages = {
            inherit (pkgs) ebpf-netem;
          };
          overlays.default = overlay;
        }
      );
}
