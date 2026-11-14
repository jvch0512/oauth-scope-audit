import datetime
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from oauth_scope_audit import audit as A  # noqa: E402
from oauth_scope_audit.__main__ import main  # noqa: E402

TODAY = datetime.date(2026, 11, 14)
ROOT = os.path.join(os.path.dirname(__file__), "..")


def g(**kw):
    base = {"app": "X", "publisher_verified": True, "admin_consent": False, "users": 5, "last_used": "2026-11-01", "scopes": ["User.Read"]}
    base.update(kw)
    return base


def rules(grant):
    return sorted(r for _, r, _ in A.audit_grant(grant, TODAY))


class Classification(unittest.TestCase):
    def test_high_risk(self):
        for s in ["Files.ReadWrite.All", "Mail.Send", "Mail.ReadWrite", "full_access_as_app", "Directory.ReadWrite.All",
                  "Directory.AccessAsUser.All", "RoleManagement.ReadWrite.Directory", "Application.ReadWrite.All", "User.ReadWrite.All",
                  "https://mail.google.com/", "https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/gmail.modify",
                  "https://www.googleapis.com/auth/admin.directory.user", "https://www.googleapis.com/auth/cloud-platform"]:
            self.assertTrue(A.is_high_risk(s), s)

    def test_not_high_risk(self):
        for s in ["User.Read", "Mail.Read", "Calendars.Read", "openid", "https://www.googleapis.com/auth/drive.readonly",
                  "https://www.googleapis.com/auth/admin.directory.user.readonly", "https://www.googleapis.com/auth/drive.file"]:
            self.assertFalse(A.is_high_risk(s), s)

    def test_broad_read(self):
        for s in ["Mail.Read.All", "Files.Read.All", "Mail.Read", "https://www.googleapis.com/auth/gmail.readonly"]:
            self.assertTrue(A.is_broad_read(s), s)
        self.assertFalse(A.is_broad_read("Calendars.Read"))

    def test_benign_case_insensitive(self):
        self.assertTrue(A.is_benign("OpenID"))
        self.assertTrue(A.is_benign("user.read"))
        self.assertFalse(A.is_benign("Mail.Read"))

    def test_dates(self):
        self.assertEqual(A.parse_date("2026-01-02"), datetime.date(2026, 1, 2))
        self.assertEqual(A.parse_date("2026-01-02T10:00:00Z"), datetime.date(2026, 1, 2))
        for bad in [None, "", "yesterday", "2026-13-01"]:
            self.assertIsNone(A.parse_date(bad))


class Rules(unittest.TestCase):
    def test_clean(self):
        self.assertEqual(rules(g()), [])

    def test_oa001(self):
        self.assertEqual(rules(g(publisher_verified=False, admin_consent=True, scopes=["Mail.Send"])), ["OA001"])

    def test_oa001_requires_admin_consent(self):
        self.assertEqual(rules(g(publisher_verified=False, admin_consent=False, scopes=["Mail.Send"])), ["OA002"])

    def test_oa002_verified(self):
        r = A.audit_grant(g(admin_consent=True, scopes=["Files.ReadWrite.All"]), TODAY)
        self.assertEqual([x[:2] for x in r], [("high", "OA002")])

    def test_oa002_plural(self):
        r = A.audit_grant(g(scopes=["Mail.Send", "Mail.ReadWrite"]), TODAY)
        self.assertIn("high-risk scopes:", r[0][2])

    def test_oa003(self):
        self.assertEqual(rules(g(publisher_verified=False, scopes=["Calendars.Read"])), ["OA003"])
        self.assertEqual(rules(g(publisher_verified=False, scopes=["openid", "profile", "User.Read", "offline_access"])), [])

    def test_oa004_boundary(self):
        self.assertEqual(rules(g(last_used="2026-05-18")), ["OA004"])      # 180 days
        self.assertEqual(rules(g(last_used="2026-05-19")), [])            # 179 days
        self.assertEqual(rules(g(last_used=None)), [])
        self.assertEqual(rules(g(last_used="garbage")), [])

    def test_oa005(self):
        self.assertEqual(rules(g(scopes=["Mail.Read.All", "offline_access"])), ["OA005"])
        self.assertEqual(rules(g(scopes=["Mail.Read.All"])), [])
        self.assertEqual(rules(g(scopes=["Calendars.Read", "offline_access"])), [])

    def test_oa005_not_duplicated_with_high_risk(self):
        self.assertEqual(rules(g(scopes=["Files.ReadWrite.All", "offline_access"])), ["OA002"])

    def test_missing_fields(self):
        self.assertEqual(rules({"app": "bare"}), [])
        self.assertEqual(rules({"scopes": ["Mail.Send"]}), ["OA002"])
        self.assertEqual(rules({"scopes": ["Mail.Send"], "admin_consent": True}), ["OA001"])

    def test_unknown_users(self):
        r = A.audit_grant({"app": "x", "scopes": ["Mail.Send"]}, TODAY)
        self.assertIn("unknown users", r[0][2])

    def test_singular_user(self):
        r = A.audit_grant(g(users=1, scopes=["Mail.Send"]), TODAY)
        self.assertIn("(1 user)", r[0][2])


class Whole(unittest.TestCase):
    def test_sorting_and_summary(self):
        fs, n = A.audit([g(app="b", scopes=["Mail.Send"]), g(app="a", publisher_verified=False, admin_consent=True, scopes=["Mail.Send"])], TODAY)
        self.assertEqual(n, 2)
        self.assertEqual([f["rule"] for f in fs], ["OA001", "OA002", "OA006"])
        self.assertIn("2 grants, 1 from unverified", fs[-1]["message"])

    def test_bad_input(self):
        with self.assertRaises(ValueError):
            A.audit({"a": 1}, TODAY)
        with self.assertRaises(ValueError):
            A.audit(["string"], TODAY)

    def test_empty(self):
        fs, n = A.audit([], TODAY)
        self.assertEqual((n, len(fs)), (0, 1))

    def test_unnamed_app(self):
        fs, _ = A.audit([{"scopes": ["Mail.Send"]}], TODAY)
        self.assertEqual(fs[0]["where"], "grant #1")


class Cli(unittest.TestCase):
    SAMPLE = os.path.join(ROOT, "examples", "grants.json")

    def run_cli(self, *args, stdin=None):
        p = subprocess.run([sys.executable, "-m", "oauth_scope_audit", *args], cwd=ROOT, input=stdin, capture_output=True, text=True)
        return p.returncode, p.stdout

    def test_codes(self):
        self.assertEqual(self.run_cli(self.SAMPLE, "--today", "2026-11-14")[0], 0)
        self.assertEqual(self.run_cli(self.SAMPLE, "--today", "2026-11-14", "--fail-on", "critical")[0], 1)
        self.assertEqual(self.run_cli(self.SAMPLE, "--today", "2026-11-14", "--fail-on", "high")[0], 1)
        self.assertEqual(self.run_cli("/no/such/file")[0], 2)
        self.assertEqual(self.run_cli()[0], 2)
        self.assertEqual(self.run_cli(self.SAMPLE, "--bogus")[0], 2)
        self.assertEqual(self.run_cli(self.SAMPLE, "--today", "nope")[0], 2)
        self.assertEqual(self.run_cli(self.SAMPLE, "--fail-on", "nope")[0], 2)

    def test_invalid_json(self):
        self.assertEqual(self.run_cli("-", stdin="{not json")[0], 2)
        self.assertEqual(self.run_cli("-", stdin='{"a":1}')[0], 2)

    def test_stdin_tsv(self):
        code, out = self.run_cli("-", "--tsv", "--today", "2026-11-14", "--fail-on", "high", stdin=json.dumps([g(scopes=["Mail.Send"])]))
        self.assertEqual(code, 1)
        self.assertTrue(out.startswith("# 1 grants, 1 findings\nhigh\tOA002\tX\t"))

    def test_clean_passes(self):
        self.assertEqual(self.run_cli("-", "--fail-on", "medium", "--today", "2026-11-14", stdin=json.dumps([g()]))[0], 0)

    def test_main_function_usage_error(self):
        self.assertEqual(main(["--nope"]), 2)


if __name__ == "__main__":
    unittest.main()
