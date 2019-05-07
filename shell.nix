with import <nixpkgs> {}; 

stdenv.mkDerivation {
	name = "http_client";
	buildInputs = [ pkgs.libressl ];
}
