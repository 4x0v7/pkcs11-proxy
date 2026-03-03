import dagger
from dagger import function, object_type

TRIVY_IMAGE = "aquasec/trivy:latest"


@object_type
class Pkcs11Proxy:
    """pkcs11-proxy CI pipeline — build, unit test, and integration test."""

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
