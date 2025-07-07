{
  description = "devshell for github:lavafroth/publicly";
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs =
    {
      nixpkgs,
      ...
    }:
    let
      forAllSystems =
        f:
        nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: {
        default = pkgs.pkgsStatic.rustPlatform.buildRustPackage {
          pname = "publicly";
          version = "1.0.0";

          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
        };
      });

      devShells = forAllSystems (pkgs: {

        default = pkgs.mkShell rec {
          packages = with pkgs; [
            stdenv.cc.cc.lib
          ];

          LD_LIBRARY_PATH = "${nixpkgs.lib.makeLibraryPath packages}";
        };

      });
    };
}
