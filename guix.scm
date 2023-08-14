(use-modules (guix git-download)
             (guix utils)
             (guix download)
             (guix packages)
             (guix gexp)
             (guix build-system cargo)
             (guix licenses)
             (gnu packages crates-io)
             )

(define vcs-file?
  (or (git-predicate (current-source-directory))
      (const #t)))

(define-public irl
  (package
   (name "irl")
   (version "0.1.0-git")
   (source (local-file "." "irl-checkout" #:recursive? #t #:select? vcs-file?))
   (build-system cargo-build-system)
   (inputs (list rust-anyhow-1
                 rust-byteorder-1
                 rust-serde-1
                 rust-toml-0.7
                 rust-serde-derive-1
                 rust-serde-spanned-0.6
                 rust-toml-datetime-0.6
                 rust-toml-edit-0.19
                 rust-proc-macro2-1
                 rust-quote-1
                 rust-syn-2
                 rust-indexmap-1
                 rust-winnow-0.4
                 rust-hashbrown-0.12
                 rust-autocfg-1
                 rust-memchr-2))
   (synopsis "Image Re-Linker")
   (description synopsis)
   (home-page "")
   (license expat)))

irl
