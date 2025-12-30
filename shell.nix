{pkgs ? import <nixpkgs> {}}:
pkgs.mkShell {
  buildInputs = with pkgs.buildPackages; [
    go
    openssl
    pkg-config
  ];
  # SeaOrm Sqlite database
  DATABASE_URL = "sqlite:////var/lib/islechat/test.sqlite?mode=rwc";
  DBEE_CONNECTIONS = "[
    {
      \"name\": \"islechat_db\",
      \"type\": \"sqlite\",
      \"url\": \"/var/lib/islechat_db/test.sqlite?mode=rwc\"
    }]";
  LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
}
