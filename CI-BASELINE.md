# CI baseline

This branch is upstream master (c6e6ca4) plus this file only. It exists so
the fork runs the unchanged CI matrix once, to tell environment failures
(runner images, vcpkg, BoringSSL download) from the vendored-4 change.
Never merged.
