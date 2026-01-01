{
  pkgs ? import <nixpkgs> {},
  lib,
  ...
}:
pkgs.buildGoModule rec {
  pname = "islechat";
  version = "0.0.1";

  meta = with lib; {
    description = "Chat sever powerd by SSH";
    mainProgram = "islechat";
    homepage = "https://github.com/ashfn/islechat";
    license = licenses.mit;
    maintainers = [
      "ashfn"
    ];
  };

  src = ./.;

  # disable tests
  checkType = "debug";
  doCheck = false;

  nativeBuildInputs = with pkgs; [
    installShellFiles
    pkg-config

    llvmPackages.clang
    clang
  ];
  buildInputs = with pkgs; [
    openssl
    pkg-config
  ];
  LIBCLANG_PATH = lib.makeLibraryPath [pkgs.llvmPackages.libclang.lib];
}
