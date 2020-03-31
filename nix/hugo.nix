{ pkgs ? import <nixpkgs> {} }:
let
  stdenv = pkgs.stdenv;
  fetchurl = pkgs.fetchurl;
in
stdenv.mkDerivation {
  name = "hugo-0.68.3";
  src = fetchurl {
    url = https://github.com/gohugoio/hugo/releases/download/v0.68.3/hugo_extended_0.68.3_Linux-64bit.tar.gz;
    sha256 = "d93d0deac782a4dd8afc2bbc5d96b30590ce47e8afb9810bbe7551eb3acf9189";
  };

  # Since hugo tarball hasn't a folder, I need to unpack it myself
  unpackPhase = ''
    mkdir -p $out/bin
    tar xf $src -C $out/bin
  '';

  dontInstall = true;
}
