"""Tests for DockerManager's compose-hardening validators.

The project doesn't have a separate compose_validator module -- the reject
logic lives directly on `DockerManager` as
`_validate_compose_security` (top-level networks/volumes/secrets/configs)
and `_validate_service_security` (per-service privileged/cap_add/network_mode/
bind mounts/etc), both called from `_enforce_resource_limits` before a
challenge's compose file is used to spawn containers.

These tests call the validators directly (they're `@staticmethod`/
`@classmethod` and don't touch Docker), feeding known-bad and known-good
parsed compose dicts -- no real compose file or Docker daemon involved.
"""
import yaml
import pytest

from app.docker_manager import DockerManager


def compose(services_yaml: str) -> dict:
    """Helper: parse a YAML snippet representing the `services:` section (and
    optionally top-level sections) of a docker-compose file."""
    return yaml.safe_load(services_yaml)


GOOD_MINIMAL_COMPOSE = """
services:
  web:
    build: .
    ports:
      - "8080:8080"
    environment:
      - FOO=bar
"""


class TestKnownGoodCompose:
    def test_minimal_compose_passes_top_level_validation(self):
        data = compose(GOOD_MINIMAL_COMPOSE)
        # Should not raise.
        DockerManager._validate_compose_security(data)

    def test_minimal_compose_passes_service_validation(self):
        data = compose(GOOD_MINIMAL_COMPOSE)
        for name, svc in data["services"].items():
            DockerManager._validate_service_security(name, svc)


# --- Per-service reject cases -------------------------------------------------

BAD_SERVICE_SNIPPETS = {
    "privileged_true": """
        web:
          image: nginx
          privileged: true
    """,
    "privileged_true_string": """
        web:
          image: nginx
          privileged: "true"
    """,
    "cap_add_sys_admin": """
        web:
          image: nginx
          cap_add:
            - SYS_ADMIN
    """,
    "volumes_from": """
        web:
          image: nginx
          volumes_from:
            - other_service
    """,
    "devices": """
        web:
          image: nginx
          devices:
            - "/dev/sda:/dev/sda"
    """,
    "device_cgroup_rules": """
        web:
          image: nginx
          device_cgroup_rules:
            - "c 1:3 mr"
    """,
    "network_mode_host": """
        web:
          image: nginx
          network_mode: host
    """,
    "network_mode_container": """
        web:
          image: nginx
          network_mode: "container:other"
    """,
    "network_mode_bridge_still_rejected": """
        web:
          image: nginx
          network_mode: bridge
    """,
    "pid_host": """
        web:
          image: nginx
          pid: host
    """,
    "ipc_host": """
        web:
          image: nginx
          ipc: host
    """,
    "userns_mode_host": """
        web:
          image: nginx
          userns_mode: host
    """,
    "uts_host": """
        web:
          image: nginx
          uts: host
    """,
    "security_opt_disallowed": """
        web:
          image: nginx
          security_opt:
            - seccomp:unconfined
    """,
    "security_opt_not_a_list_or_str": """
        web:
          image: nginx
          security_opt: 12345
    """,
    "bind_mount_docker_sock": """
        web:
          image: nginx
          volumes:
            - "/var/run/docker.sock:/var/run/docker.sock"
    """,
    "bind_mount_root": """
        web:
          image: nginx
          volumes:
            - "/:/hostroot"
    """,
    "bind_mount_etc": """
        web:
          image: nginx
          volumes:
            - "/etc:/etc"
    """,
    "bind_mount_dict_form_absolute": """
        web:
          image: nginx
          volumes:
            - type: bind
              source: /etc/passwd
              target: /etc/passwd
    """,
    "bind_mount_windows_path": """
        web:
          image: nginx
          volumes:
            - "C:\\\\Windows:/mnt/win"
    """,
    "bind_mount_env_expansion": """
        web:
          image: nginx
          volumes:
            - "${HOME}:/mnt/home"
    """,
    "bind_mount_home_dir": """
        web:
          image: nginx
          volumes:
            - "~/secrets:/mnt/secrets"
    """,
    "bind_mount_parent_traversal": """
        web:
          image: nginx
          volumes:
            - "../../etc:/mnt/etc"
    """,
    "build_context_absolute_path": """
        web:
          build:
            context: /etc
            dockerfile: Dockerfile
    """,
    "build_context_remote_url": """
        web:
          build:
            context: "https://example.com/repo.git"
    """,
    "build_string_absolute_path": """
        web:
          build: /etc
    """,
    "env_file_absolute_path": """
        web:
          image: nginx
          env_file:
            - /etc/secrets.env
    """,
}


@pytest.mark.parametrize("name", sorted(BAD_SERVICE_SNIPPETS))
def test_rejects_known_bad_service_directive(name):
    snippet = BAD_SERVICE_SNIPPETS[name]
    data = yaml.safe_load(snippet)
    service_name, service_config = next(iter(data.items()))

    with pytest.raises(ValueError):
        DockerManager._validate_service_security(service_name, service_config)


class TestSecurityOptAllowsSafeValue:
    def test_no_new_privileges_is_allowed(self):
        data = yaml.safe_load(
            """
            web:
              image: nginx
              security_opt:
                - "no-new-privileges:true"
            """
        )
        name, svc = next(iter(data.items()))
        # Must not raise -- this is the one allow-listed security_opt value.
        DockerManager._validate_service_security(name, svc)


# --- Top-level (compose-wide) reject cases ------------------------------------

BAD_TOP_LEVEL_SNIPPETS = {
    "external_network": """
        services:
          web:
            image: nginx
        networks:
          mynet:
            external: true
    """,
    "external_volume": """
        services:
          web:
            image: nginx
        volumes:
          myvol:
            external: true
    """,
    "volume_driver_opts": """
        services:
          web:
            image: nginx
        volumes:
          myvol:
            driver_opts:
              type: nfs
    """,
    "volume_nonlocal_driver": """
        services:
          web:
            image: nginx
        volumes:
          myvol:
            driver: some-remote-driver
    """,
    "external_secret": """
        services:
          web:
            image: nginx
        secrets:
          mysecret:
            external: true
    """,
    "external_config": """
        services:
          web:
            image: nginx
        configs:
          myconfig:
            external: true
    """,
    "secret_file_absolute_path": """
        services:
          web:
            image: nginx
        secrets:
          mysecret:
            file: /etc/secrets/mysecret
    """,
}


@pytest.mark.parametrize("name", sorted(BAD_TOP_LEVEL_SNIPPETS))
def test_rejects_known_bad_top_level_directive(name):
    data = yaml.safe_load(BAD_TOP_LEVEL_SNIPPETS[name])
    with pytest.raises(ValueError):
        DockerManager._validate_compose_security(data)


class TestLocalPathReferenceHelper:
    def test_rejects_env_expanded_path(self):
        with pytest.raises(ValueError):
            DockerManager._validate_local_path_reference("Thing", "field", "${FOO}/bar")

    def test_rejects_home_dir_path(self):
        with pytest.raises(ValueError):
            DockerManager._validate_local_path_reference("Thing", "field", "~/bar")

    def test_rejects_absolute_posix_path(self):
        with pytest.raises(ValueError):
            DockerManager._validate_local_path_reference("Thing", "field", "/etc/passwd")

    def test_rejects_parent_traversal(self):
        with pytest.raises(ValueError):
            DockerManager._validate_local_path_reference("Thing", "field", "../../etc/passwd")

    def test_rejects_remote_url_when_requested(self):
        with pytest.raises(ValueError):
            DockerManager._validate_local_path_reference(
                "Thing", "field", "https://example.com/x", reject_urls=True
            )

    def test_allows_relative_path(self):
        # Must not raise.
        DockerManager._validate_local_path_reference("Thing", "field", "subdir/Dockerfile")

    def test_allows_empty_value(self):
        DockerManager._validate_local_path_reference("Thing", "field", "")
        DockerManager._validate_local_path_reference("Thing", "field", None)
