from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

import pathlib
import shutil
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
STATIC = ROOT / "src" / "agentdecompile_recovery" / "corpus" / "dashboard" / "static"
CSS = STATIC / "dashboard.css"
JS = STATIC / "dashboard.js"
ACTIONS_JS = STATIC / "actions.js"


class DashboardStaticAssetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.css = CSS.read_text()
        cls.js = JS.read_text()
        cls.actions_js = ACTIONS_JS.read_text()

    def test_assets_exist_outside_dashboard_module(self):
        self.assertTrue(CSS.is_file())
        self.assertTrue(JS.is_file())
        self.assertNotIn("scripts/dashboard.py", str(CSS))

    def test_css_has_keyboard_and_motion_safety_contracts(self):
        for marker in (
            ".skip-link",
            ".sr-only",
            ":focus-visible",
            "prefers-reduced-motion",
            "outline: 3px solid var(--focus)",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.css)

    def test_css_has_compact_responsive_shell_and_safe_overflow(self):
        for marker in (
            ".topbar",
            ".nav-toggle",
            "max-width: 900px",
            "max-width: 560px",
            ".tablewrap",
            "overflow-x: auto",
            "grid-template-columns: repeat(2, minmax(0, 1fr))",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.css)

    def test_css_covers_existing_status_and_surface_classes(self):
        for selector in (
            ".chip",
            ".tag",
            ".pill",
            ".panel",
            ".block",
            ".sec",
            ".callout",
            ".st-done",
            ".st-partial",
            ".st-failed",
            ".action-bar",
            "#action-dock",
            ".workspace-nav",
            ".search-form",
        ):
            with self.subTest(selector=selector):
                self.assertIn(selector, self.css)

    def test_javascript_installs_accessibility_helpers(self):
        for marker in (
            "Skip to main content",
            'setAttribute("aria-current", "page")',
            'setAttribute("aria-expanded"',
            'setAttribute("aria-live", "polite")',
            'setAttribute("aria-busy"',
            "enhanceRepeatedActions",
            "Open call graph for ",
            "window.KotorXidUI",
            "installLiveBrowse",
            "data-live-search",
            "installWorkspaceNav",
            "installFunctionCombo",
            "installGraphStage",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.js)

    def test_javascript_is_syntactically_valid(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not installed")
        result = subprocess.run(
            [node, "--check", str(JS)],
            text=True,
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        actions = subprocess.run(
            [node, "--check", str(ACTIONS_JS)],
            text=True,
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(actions.returncode, 0, actions.stderr)


