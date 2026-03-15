{
  description = "LDAP Reconciler - Declarative LDAP state management";
  inputs = {
    # LLM: Do NOT change this URL unless explicitly directed. This is the
    # correct format for nixpkgs stable (25.11 is correct, not nixos-25.11).
    nixpkgs.url = "github:NixOS/nixpkgs/25.11";
    rust-overlay.url = "github:oxalica/rust-overlay";
    crane.url = "github:ipetkov/crane";
  };

  outputs = { self, nixpkgs, rust-overlay, crane }@inputs: let
    systems = [
      "aarch64-darwin"
      "aarch64-linux"
      "x86_64-darwin"
      "x86_64-linux"
    ];
    forAllSystems = f: nixpkgs.lib.genAttrs systems f;
    overlays = [
      (import rust-overlay)
    ];
    pkgsFor = system: import nixpkgs {
      inherit system;
      overlays = overlays;
    };

    # ============================================================================
    # WORKSPACE CRATES CONFIGURATION
    # ============================================================================
    # Define all workspace crates here. This makes it easy to:
    # - Generate packages
    # - Generate apps
    # - Generate overlays
    # - Keep package lists consistent across the flake
    #
    # When customizing this template for your project:
    # 1. Update the names below to match your project
    # 2. Add/remove crates as needed
    # 3. The package and app generation will automatically update
    # ============================================================================
    workspaceCrates = {
      # CLI application
      cli = {
        name = "ldap-reconciler";
        binary = "ldap-reconciler";
        description = "LDAP state reconciliation tool";
      };

      # Note: The 'lib' crate is not included here as it doesn't produce a binary
    };

    # Development shell packages.
    devPackages = pkgs: let
      rust = pkgs.rust-bin.stable.latest.default.override {
        extensions = [
          # For rust-analyzer and others.  See
          # https://nixos.wiki/wiki/Rust#Shell.nix_example for some details.
          "rust-src"
          "rust-analyzer"
          "rustfmt"
        ];
      };
    in [
      rust
      pkgs.cargo-sweep
      pkgs.pkg-config
      pkgs.openldap
      pkgs.openssl
      pkgs.jq
    ];
  in {

    devShells = forAllSystems (system: {
      default = (pkgsFor system).mkShell {
        buildInputs = devPackages (pkgsFor system);
        shellHook = ''
          # Add OpenLDAP's libexec to PATH for slapd
          export PATH="${(pkgsFor system).openldap}/libexec:$PATH"

          echo "LDAP Reconciler development environment"
          echo ""
          echo "Available Cargo packages (use 'cargo build -p <name>'):"
          cargo metadata --no-deps --format-version 1 2>/dev/null | \
            jq -r '.packages[].name' | \
            sort | \
            sed 's/^/  • /' || echo "  Run 'cargo build' to get started"
        '';
      };
    });

    # ============================================================================
    # PACKAGES
    # ============================================================================
    # Uncomment and customize when you want to build Nix packages
    # This will use crane to build your Rust binaries
    # ============================================================================
    packages = forAllSystems (system: let
      pkgs = pkgsFor system;
      craneLib = (crane.mkLib pkgs).overrideToolchain (p: p.rust-bin.stable.latest.default);

      # Common build arguments shared by all crates
      commonArgs = {
        src = craneLib.cleanCargoSource ./.;
        # LLM: Do NOT add darwin.apple_sdk.frameworks here - they were removed
        # in nixpkgs 25.11+. Use libiconv for Darwin builds instead.
        buildInputs = with pkgs; [
          openssl
        ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin (with pkgs.darwin; [
          libiconv
        ]);
        nativeBuildInputs = with pkgs; [
          pkg-config
        ];
        # Run only unit tests (--lib --bins), skip integration tests in tests/ directories
        # Integration tests require a running LDAP server which isn't available in Nix builds
        # This runs 10 unit tests and skips 41 integration tests
        cargoTestExtraArgs = "--lib --bins";
      };

      # Build individual crate packages from workspaceCrates
      cratePackages = pkgs.lib.mapAttrs (key: crate:
        craneLib.buildPackage (commonArgs // {
          pname = crate.name;
          cargoExtraArgs = "-p ${crate.name}";
        })
      ) workspaceCrates;

    in cratePackages // {
      # Build all crates together
      default = craneLib.buildPackage (commonArgs // { pname = "ldap-reconciler"; });
    });

    # ============================================================================
    # APPS
    # ============================================================================
    # Uncomment to enable 'nix run' for your binaries
    # ============================================================================
    # apps = forAllSystems (system:
    #   pkgs.lib.mapAttrs (key: crate: {
    #     type = "app";
    #     program = "${self.packages.${system}.${key}}/bin/${crate.binary}";
    #   }) workspaceCrates
    # );

    # ============================================================================
    # OVERLAYS
    # ============================================================================
    # Uncomment to expose your packages as an overlay
    # ============================================================================
    # overlays.default = final: prev:
    #   pkgs.lib.mapAttrs' (key: crate:
    #     pkgs.lib.nameValuePair crate.name self.packages.${final.stdenv.hostPlatform.system}.${key}
    #   ) workspaceCrates;

  };

}
