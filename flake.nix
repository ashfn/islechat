{
  description = "Islechat - Chat server powered by SSH.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    flake-parts,
    ...
  } @ inputs:
    flake-parts.lib.mkFlake {
      inherit inputs;
    } {
      systems = flake-utils.lib.allSystems;
      perSystem = {
        config,
        self,
        pkgs,
        system,
        ...
      }: let
        pkgs = import nixpkgs {
          inherit system;
        };
        specialArgs = {
          inherit inputs;
        };
      in {
        devShells.default = pkgs.callPackage ./shell.nix {};

        packages = {
          default = pkgs.callPackage ./package.nix {};
        };
      };
    };
}
