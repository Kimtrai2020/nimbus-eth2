{ pkgs ? import <nixpkgs> { } }: with pkgs;
mkShell {
  buildInputs = [
    figlet
    git
    gnumake
  ];

  shellHook = ''
    figlet "Welcome  to Nimbus-eth2"
  '';
}
