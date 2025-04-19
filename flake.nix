{
  description = "devshell for github:lavafroth/publik";

  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.default = pkgs.pkgsStatic.rustPlatform.buildRustPackage {
          pname = "publik";
          version = "0.2.1";

          src = ./.;
          cargoLock = {
            lockFile = ./Cargo.lock;
          };
        };

        devShells.default = pkgs.mkShell rec {
          packages = with pkgs; [
            stdenv.cc.cc.lib
          ];

          LD_LIBRARY_PATH = "${nixpkgs.lib.makeLibraryPath packages}";
        };
      }
    );
}
