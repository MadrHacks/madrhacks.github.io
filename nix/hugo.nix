{ pkgs ? import <nixpkgs> {} }:
let
  stdenv = pkgs.stdenv;
  fetchurl = pkgs.fetchurl;
in
stdenv.mkDerivation {
  name = "hugo-0.67";
  src = fetchurl {
    url = https://github.com/gohugoio/hugo/releases/download/v0.67.1/hugo_0.67.1_Linux-64bit.tar.gz;
    sha256 = "3076ecd5426f4f1e46a4ca4242bde22c9a137199e5ab93fbbefb0271d25bc52a";
  };

  # Since hugo tarball hasn't a folder, I need to unpack it myself
  unpackPhase = ''
    mkdir -p $out/bin
    tar xf $src -C $out/bin
  '';

  dontInstall = true;
}
