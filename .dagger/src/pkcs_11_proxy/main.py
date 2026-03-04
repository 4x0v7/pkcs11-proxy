import dagger
from dagger import function, object_type

TRIVY_IMAGE = "aquasec/trivy:latest"
LINT_IMAGE = "ubuntu:24.04"

# C source directories to lint (relative to repo root)
C_SRC_DIRS = ["src/", "include/"]
C_SRC_GLOBS = ["src/**/*.c", "src/**/*.h", "include/**/*.h"]


@object_type
class Pkcs11Proxy:
    """pkcs11-proxy CI pipeline — build, test, lint, and security scan."""

    def _build_test_image(self, src: dagger.Directory) -> dagger.Container:
        """Build the test image from docker/Dockerfile.test (layer-cached)."""
        return src.docker_build(dockerfile="docker/Dockerfile.test")

    def _build_server_image(self, src: dagger.Directory) -> dagger.Container:
        """Build the production server image from docker/Dockerfile.server."""
        return src.docker_build(dockerfile="docker/Dockerfile.server")

    @function(cache="never")
    async def test(self, src: dagger.Directory) -> str:
        """Run the unit test suite (26 tests). Always re-runs."""
        return await (
            self._build_test_image(src).with_exec(["tests/run-all.sh"]).stdout()
        )

    def _generate_pki(self, src: dagger.Directory) -> dagger.Directory:
        """Generate ephemeral PKI certs and return the /pki directory."""
        return (
            self._build_test_image(src)
            .with_env_variable("STEPPATH", "/tmp/step")
            .with_exec(["mkdir", "-p", "/tmp/step", "/pki"])
            .with_exec(
                ["bash", "/build/pkcs11-proxy/docker/integration/generate-pki.sh"]
            )
            .directory("/pki")
        )

    def _daemon_service(
        self, src: dagger.Directory, pki: dagger.Directory
    ) -> dagger.Service:
        """Start pkcs11-daemon as a Dagger service on port 2345."""
        return (
            self._build_test_image(src)
            .with_directory("/pki", pki)
            # TLS config
            .with_env_variable("PKCS11_PROXY_TLS_CERT", "/pki/server.crt")
            .with_env_variable("PKCS11_PROXY_TLS_KEY", "/pki/server.key")
            .with_env_variable("PKCS11_PROXY_TLS_CA", "/pki/ca.crt")
            .with_env_variable("PKCS11_PROXY_TLS_REQUIRE_MTLS", "true")
            # OID policy config
            .with_env_variable("PKCS11_PROXY_TLS_POLICY_REPO", "org/repo")
            .with_env_variable("PKCS11_PROXY_TLS_POLICY_KEYSET", "cosign-v1")
            .with_exposed_port(2345)
            .as_service(
                args=[
                    "bash",
                    "-c",
                    "mkdir -p /var/lib/softhsm/tokens && "
                    "softhsm2-util --init-token --slot 0 --label cosign "
                    '--pin "$(cat /etc/softhsm/pin)" '
                    '--so-pin "$(cat /etc/softhsm/so-pin)" '
                    "2>/dev/null || true && "
                    "exec /build/pkcs11-proxy/pkcs11-daemon "
                    "/usr/lib/softhsm/libsofthsm2.so tls://0.0.0.0:2345",
                ]
            )
        )

    @function(cache="never")
    async def integration_test(self, src: dagger.Directory) -> str:
        """Run Docker-based integration tests (PKI + daemon + client + sslscan)."""
        pki = self._generate_pki(src)
        daemon = self._daemon_service(src, pki)

        return await (
            self._build_test_image(src)
            .with_directory("/pki", pki)
            .with_service_binding("server", daemon)
            .with_env_variable("PKCS11_PROXY_TLS_SERVER_NAME", "server")
            .with_exec(
                [
                    "bash",
                    "/build/pkcs11-proxy/docker/integration/entrypoint-client.sh",
                ]
            )
            .stdout()
        )

    @function(cache="never")
    async def sslscan(self, src: dagger.Directory) -> str:
        """Run sslscan against the daemon to audit TLS configuration."""
        pki = self._generate_pki(src)
        daemon = self._daemon_service(src, pki)

        return await (
            dagger.dag.container()
            .from_("cmoore1776/sslscan:latest")
            .with_service_binding("server", daemon)
            .with_exec(["sslscan", "server:2345"])
            .stdout()
        )

    @function(cache="never")
    async def trivy_scan(self, src: dagger.Directory) -> str:
        """Scan the production server image with Trivy for vulnerabilities."""
        tarball = self._build_server_image(src).as_tarball()

        return await (
            dagger.dag.container()
            .from_(TRIVY_IMAGE)
            .with_mounted_file("/image.tar", tarball)
            .with_exec(
                [
                    "trivy",
                    "image",
                    "--input",
                    "/image.tar",
                    "--severity",
                    "CRITICAL,HIGH",
                    "--exit-code",
                    "1",
                ]
            )
            .stdout()
        )

    def _lint_container(self, src: dagger.Directory) -> dagger.Container:
        """Ubuntu container with clang-format, clang-tidy, cppcheck, and build deps."""
        return (
            dagger.dag.container()
            .from_(LINT_IMAGE)
            .with_exec(
                [
                    "bash",
                    "-c",
                    "apt-get update -qq && "
                    "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
                    "clang-format clang-tidy cppcheck "
                    "cmake build-essential pkg-config libssl-dev libseccomp-dev "
                    "> /dev/null 2>&1",
                ]
            )
            .with_directory("/src", src)
            .with_workdir("/src")
        )

    @function
    async def lint(self, src: dagger.Directory) -> str:
        """Run all C linters: clang-format check, cppcheck, clang-tidy."""
        ctr = self._lint_container(src)

        # clang-format --dry-run --Werror
        fmt_result = await ctr.with_exec(
            [
                "bash",
                "-c",
                "find src/ include/ -name '*.c' -o -name '*.h' "
                "| grep -v ext/ "
                "| xargs clang-format --dry-run --Werror 2>&1 || true",
            ]
        ).stdout()

        # cppcheck
        cppcheck_result = await ctr.with_exec(
            [
                "bash",
                "-c",
                "cppcheck --enable=warning,style,performance "
                "--suppress=missingIncludeSystem "
                "--suppress=unusedFunction "
                "-Iinclude -I. "
                "src/ include/ 2>&1",
            ]
        ).stdout()

        # clang-tidy (needs compile_commands.json)
        tidy_result = await (
            ctr.with_exec(
                ["bash", "-c", "cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -B build ."]
            )
            .with_exec(
                [
                    "bash",
                    "-c",
                    "find src/ -name '*.c' "
                    "| grep -v ext/ "
                    "| xargs clang-tidy -p build "
                    "--config-file=.clang-tidy 2>&1 || true",
                ]
            )
            .stdout()
        )

        return (
            "=== clang-format ===\n"
            + (fmt_result.strip() or "(clean)")
            + "\n\n=== cppcheck ===\n"
            + (cppcheck_result.strip() or "(clean)")
            + "\n\n=== clang-tidy ===\n"
            + (tidy_result.strip() or "(clean)")
            + "\n"
        )

    @function
    async def lint_format(self, src: dagger.Directory) -> str:
        """Check C code formatting with clang-format (dry-run)."""
        return await (
            self._lint_container(src)
            .with_exec(
                [
                    "bash",
                    "-c",
                    "find src/ include/ -name '*.c' -o -name '*.h' "
                    "| grep -v ext/ "
                    "| xargs clang-format --dry-run --Werror 2>&1; "
                    'echo "exit: $?"',
                ]
            )
            .stdout()
        )

    @function
    async def lint_cppcheck(self, src: dagger.Directory) -> str:
        """Run cppcheck static analysis on C source."""
        return await (
            self._lint_container(src)
            .with_exec(
                [
                    "bash",
                    "-c",
                    "cppcheck --enable=warning,style,performance "
                    "--suppress=missingIncludeSystem "
                    "--suppress=unusedFunction "
                    "--error-exitcode=1 "
                    "-Iinclude -I. "
                    "src/ include/ 2>&1",
                ]
            )
            .stdout()
        )

    @function
    async def lint_tidy(self, src: dagger.Directory) -> str:
        """Run clang-tidy static analysis on C source."""
        return await (
            self._lint_container(src)
            .with_exec(
                ["bash", "-c", "cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -B build ."]
            )
            .with_exec(
                [
                    "bash",
                    "-c",
                    "find src/ -name '*.c' "
                    "| grep -v ext/ "
                    "| xargs clang-tidy -p build "
                    "--config-file=.clang-tidy 2>&1; "
                    'echo "exit: $?"',
                ]
            )
            .stdout()
        )

    @function(cache="never")
    async def trivy_report(self, src: dagger.Directory) -> dagger.File:
        """Scan the production image and return a JSON vulnerability report."""
        tarball = self._build_server_image(src).as_tarball()

        return (
            dagger.dag.container()
            .from_(TRIVY_IMAGE)
            .with_mounted_file("/image.tar", tarball)
            .with_exec(
                [
                    "trivy",
                    "image",
                    "--input",
                    "/image.tar",
                    "--format",
                    "json",
                    "--output",
                    "/report.json",
                ]
            )
            .file("/report.json")
        )
