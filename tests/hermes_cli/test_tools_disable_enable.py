"""Tests for hermes tools disable/enable/list command (backend)."""
from argparse import Namespace
from unittest.mock import patch

from hermes_cli.tools_config import tools_disable_enable_command


# ── Built-in toolset disable ────────────────────────────────────────────────


class TestToolsDisableBuiltin:

    def test_disable_removes_toolset_from_platform(self):
        config = {"platform_toolsets": {"cli": ["web", "memory", "terminal"]}}
        with patch("hermes_cli.tools_config.load_config", return_value=config), \
             patch("hermes_cli.tools_config.save_config") as mock_save:
            tools_disable_enable_command(Namespace(tools_action="disable", names=["web"], platform="cli"))
        saved = mock_save.call_args[0][0]
        assert "web" not in saved["platform_toolsets"]["cli"]
        assert "memory" in saved["platform_toolsets"]["cli"]


# ── Built-in toolset enable ─────────────────────────────────────────────────


# ── MCP tool disable ────────────────────────────────────────────────────────


class TestToolsDisableMcp:


    def test_disable_unknown_server_prints_error(self, capsys):
        config = {"mcp_servers": {}}
        with patch("hermes_cli.tools_config.load_config", return_value=config), \
             patch("hermes_cli.tools_config.save_config"):
            tools_disable_enable_command(
                Namespace(tools_action="disable", names=["unknown:tool"], platform="cli")
            )
        out = capsys.readouterr().out
        assert "MCP server 'unknown' not found in config" in out


# ── MCP tool enable ──────────────────────────────────────────────────────────


# ── MCP server platform exposure ─────────────────────────────────────────────


class TestToolsMcpServerPlatformExposure:

    def test_enable_configured_server_adds_it_to_platform(self):
        config = {
            "platform_toolsets": {"cli": ["web"]},
            "mcp_servers": {"membrane-integrate-anything": {"url": "https://example.test/mcp"}},
        }
        with patch("hermes_cli.tools_config.load_config", return_value=config), \
             patch("hermes_cli.tools_config.save_config") as mock_save:
            tools_disable_enable_command(
                Namespace(
                    tools_action="enable",
                    names=["membrane-integrate-anything"],
                    platform="cli",
                )
            )
        saved = mock_save.call_args[0][0]
        assert "web" in saved["platform_toolsets"]["cli"]
        assert "membrane-integrate-anything" in saved["platform_toolsets"]["cli"]

    def test_disable_configured_server_removes_it_from_platform(self):
        config = {
            "platform_toolsets": {"telegram": ["memory", "membrane-integrate-anything"]},
            "mcp_servers": {"membrane-integrate-anything": {"url": "https://example.test/mcp"}},
        }
        with patch("hermes_cli.tools_config.load_config", return_value=config), \
             patch("hermes_cli.tools_config.save_config") as mock_save:
            tools_disable_enable_command(
                Namespace(
                    tools_action="disable",
                    names=["membrane-integrate-anything"],
                    platform="telegram",
                )
            )
        saved = mock_save.call_args[0][0]
        assert "memory" in saved["platform_toolsets"]["telegram"]
        assert "membrane-integrate-anything" not in saved["platform_toolsets"]["telegram"]

    def test_mixed_builtin_server_and_server_tool_targets(self):
        config = {
            "platform_toolsets": {"cli": ["memory"]},
            "mcp_servers": {"github": {"tools": {"exclude": ["list_issues"]}}},
        }
        with patch("hermes_cli.tools_config.load_config", return_value=config), \
             patch("hermes_cli.tools_config.save_config") as mock_save:
            tools_disable_enable_command(
                Namespace(
                    tools_action="enable",
                    names=["web", "github", "github:list_issues"],
                    platform="cli",
                )
            )
        saved = mock_save.call_args[0][0]
        assert {"memory", "web", "github"}.issubset(saved["platform_toolsets"]["cli"])
        assert "list_issues" not in saved["mcp_servers"]["github"]["tools"]["exclude"]


# ── Mixed targets ────────────────────────────────────────────────────────────


# ── List output ──────────────────────────────────────────────────────────────


class TestToolsList:


    def test_list_shows_mcp_excluded_tools(self, capsys):
        config = {
            "mcp_servers": {"github": {"tools": {"exclude": ["create_issue"]}}},
        }
        with patch("hermes_cli.tools_config.load_config", return_value=config):
            tools_disable_enable_command(Namespace(tools_action="list", platform="cli"))
        out = capsys.readouterr().out
        assert "github" in out
        assert "create_issue" in out

    def test_list_shows_mcp_server_platform_enablement(self, capsys):
        config = {
            "platform_toolsets": {"cli": ["github"]},
            "mcp_servers": {
                "github": {},
                "membrane-integrate-anything": {},
            },
        }
        with patch("hermes_cli.tools_config.load_config", return_value=config):
            tools_disable_enable_command(Namespace(tools_action="list", platform="cli"))
        out = capsys.readouterr().out
        github_line = next(line for line in out.splitlines() if "github" in line)
        membrane_line = next(
            line for line in out.splitlines() if "membrane-integrate-anything" in line
        )
        assert "enabled" in github_line
        assert "disabled" in membrane_line


# ── Validation ───────────────────────────────────────────────────────────────


class TestToolsValidation:


    def test_mixed_valid_and_invalid_applies_valid_only(self):
        config = {"platform_toolsets": {"cli": ["web", "memory"]}}
        with patch("hermes_cli.tools_config.load_config", return_value=config), \
             patch("hermes_cli.tools_config.save_config") as mock_save:
            tools_disable_enable_command(
                Namespace(tools_action="disable", names=["web", "bad_toolset"], platform="cli")
            )
        saved = mock_save.call_args[0][0]
        assert "web" not in saved["platform_toolsets"]["cli"]
        assert "memory" in saved["platform_toolsets"]["cli"]
