set(VCPKG_TARGET_ARCHITECTURE arm64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)

# MSVC 14.51 (Visual Studio 2026) for ARM64 emits `bl __chkstk` before the
# link register is saved in some prologues. OpenSSL compiles with /Gs0, so
# every function probes the stack; tls_parse_all_extensions then returns
# into its own prologue and every TLS handshake crashes with
# STATUS_ACCESS_VIOLATION. Build OpenSSL with the 14.44 toolset that the
# windows-11-arm image still ships until a fixed MSVC is available.
# See actions/runner-images#14602 and ruby/ruby#19135.
set(VCPKG_PLATFORM_TOOLSET_VERSION 14.44)
