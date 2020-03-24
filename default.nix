{ pkgs ? import <nixpkgs> {} }:
let
  libraries = with pkgs.elmPackages; {
    hugo = import ./nix/hugo.nix {};
    elm = elm;
    elm-format = elm-format;
  };

  # Pull out values from the set
  libraryBins = builtins.attrValues libraries;

in pkgs.mkShell {
  name = "hugo-box";
  buildInputs = libraryBins;
}
