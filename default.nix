{ pkgs ? import <nixpkgs> {} }:
let
  libraries = {
    hugo = import ./nix/hugo.nix {};
  };

  # Pull out values from the set
  libraryBins = builtins.attrValues libraries;

in pkgs.mkShell {
  name = "hugo-box";
  buildInputs = libraryBins;
}
