"""Behavior tests for the supported grammar, deliberately not a mkifs conformance suite."""
from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from qnx_inspector import Inspector, html_report


class InspectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, text):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        return p

    def inspect(self, text, **kwargs):
        p = self.write("main.build", text)
        return Inspector(cwd=self.root, project_root=self.root, **kwargs).run(p)

    def codes(self, result):
        return {finding["code"] for finding in result["findings"]}

    def test_documentation_fragment_is_parsed_as_bootstrap_and_script(self):
        project = Path(__file__).resolve().parents[1]
        result = Inspector(cwd=project, project_root=project).run(project / "examples/documented_fragment.buildfile")
        self.assertEqual([e["kind"] for e in result["entries"]], ["bootstrap", "script"])
        self.assertEqual([launch["command"] for launch in result["launches"]], ["devc-ser8250", "sh"])
        self.assertFalse(any(code.startswith("P") for code in self.codes(result)))

    def test_include_is_in_place_and_global_changes_flow_back_to_parent(self):
        self.write("child.build", "[uid=17]\n[uid=23] /child=payload\n")
        result = self.inspect("[uid=9]\n[+include] child.build\n/parent=payload\n")
        self.assertEqual([e["attributes"]["uid"] for e in result["entries"]], ["23", "17"])
        self.assertEqual(result["entries"][0]["position"]["file"], "child.build")
        self.assertEqual(result["entries"][1]["position"]["line"], 3)

    def test_include_uses_mkifs_cwd_not_including_file_parent(self):
        self.write("sub/main.build", "[+include] child.build\n")
        self.write("sub/child.build", "/must_not_be_read=payload\n")
        self.write("child.build", "/correct=payload\n")
        result = Inspector(cwd=self.root, project_root=self.root).run(self.root / "sub/main.build")
        self.assertEqual([e["target"] for e in result["entries"]], ["/correct"])

    def test_include_search_and_cycle_vs_repeated_include(self):
        self.write("parts/child.build", "[+include] main.build\n/x=payload\n")
        result = self.inspect("[search=parts]\n[+include] child.build\n[+include] child.build\n")
        self.assertTrue({"I201", "I202"}.issubset(self.codes(result)))
        self.assertEqual(len(result["entries"]), 1)

    def test_optional_missing_include_is_warning_and_unresolved_variable_is_not_claimed_missing(self):
        result = self.inspect("[+include +optional] absent\n[+include] ${UNSET}/part\n")
        findings = {f["code"]: f for f in result["findings"]}
        self.assertEqual(findings["I204"]["severity"], "warning")
        self.assertEqual(findings["C202"]["confidence"], "limited")

    def test_include_trust_boundary_does_not_expose_outside_file(self):
        with tempfile.TemporaryDirectory() as other:
            outside = Path(other) / "secret.build"
            outside.write_text("/secret=payload\n", encoding="utf-8")
            result = self.inspect(f'[+include] "{outside.as_posix()}"\n')
            self.assertIn("C203", self.codes(result))
            self.assertNotIn("secret.build", result["sources"])

    def test_include_depth_limit_is_reported(self):
        for i in range(34):
            self.write(f"p{i}.build", f"[+include] p{i + 1}.build\n")
        result = self.inspect("[+include] p0.build\n")
        self.assertIn("C201", self.codes(result))

    def test_local_attribute_does_not_leak_and_conditional_respects_explicit_setting(self):
        result = self.inspect("[uid=4]\n[?uid=8] /one=src\n[uid=7] /two=src\n/three=src\n")
        self.assertEqual([e["attributes"]["uid"] for e in result["entries"]], ["4", "7", "4"])

    def test_double_quotes_escaped_dollar_comments_and_continuation(self):
        result = self.inspect('[prefix="a b"]\n"name #1" = "host file" # ignored\n[uid=\\\n9] /continued=src\n/literal=\\${SECRET}\n')
        self.assertEqual(result["entries"][0]["target"], "/a b/name #1")
        self.assertEqual(result["entries"][0]["source"], "host file")
        self.assertEqual(result["entries"][1]["attributes"]["uid"], "9")
        self.assertNotIn("C204", self.codes(result))
        self.assertEqual(result["entries"][2]["source"], "${SECRET}")

    def test_inline_data_keeps_hash_quotes_and_escaped_braces(self):
        result = self.inspect('/etc/data={\n# data, not a buildfile comment\n"value": \\{123\\}\n}\n/after=src\n')
        self.assertEqual(result["entries"][0]["content"][0][1], "# data, not a buildfile comment")
        self.assertEqual(result["entries"][0]["content"][1][1], '"value": {123}')
        self.assertEqual(result["entries"][1]["position"]["line"], 5)

    def test_unclosed_inline_does_not_parse_fake_file_entries_inside(self):
        result = self.inspect("/data={\n/looks_like_a_file=host\n")
        self.assertIn("P106", self.codes(result))
        self.assertEqual(len(result["entries"]), 1)

    def test_invalid_brackets_quote_and_multiple_groups_recover_next_lines(self):
        result = self.inspect('[uid=1\n[uid=0] [gid=0] /bad=host\n"bad\n/okay=host\n')
        self.assertEqual(sum(f["code"] == "P103" for f in result["findings"]), 3)
        self.assertEqual(result["entries"][0]["target"], "/okay")

    def test_host_absolute_plain_path_is_basename_but_alias_is_absolute_target(self):
        result = self.inspect('[virtual=x86_64,bios] boot={\nstartup-x86\nprocnto-smp-instr\n}\n/etc/hosts\n/etc/hosts=/fake/hosts\n')
        self.assertEqual([e["target"] for e in result["entries"]][1:], ["/proc/boot/hosts", "/etc/hosts"])

    def test_dupignore_selection_all_documented_cases(self):
        cases = [(False, False, "one", "D201"), (True, False, "two", "D202"),
                 (False, True, "one", "D202"), (True, True, "one", "D202")]
        for old, new, expected, code in cases:
            with self.subTest(old=old, new=new):
                result = self.inspect(f'[{"+" if old else "-"}dupignore] /same=one\n[{"+" if new else "-"}dupignore] /same=two\n')
                self.assertIn(code, self.codes(result))
                selected = [e["source"] for e in result["entries"] if e["selected"]]
                # Two unignored definitions are an error; the report retains both.
                self.assertEqual(selected, ["one", "two"] if code == "D201" else [expected])

    def test_file_ancestor_conflict_symlink_cycle_and_directory_parent(self):
        result = self.inspect('[type=link] /a=/b\n[type=link] /b=/a\n/a/child=src\n[type=dir] /real\n/real/child=src\n')
        self.assertIn("D203", self.codes(result))
        self.assertIn("D204", self.codes(result))
        self.assertEqual(sum(f["code"] == "D203" for f in result["findings"]), 1)

    def test_uid_is_file_ownership_not_a_script_modifier_or_runtime_identity(self):
        result = self.inspect('[uid=100] /bin/service=stub\n[+script] run={\n[uid=100] /bin/service &\non -u 0:0 /bin/service &\non -u100:100 /bin/service &\n}\n')
        self.assertIn("S301", self.codes(result))
        self.assertIn("S402", self.codes(result))
        services = [launch for launch in result["launches"] if launch["command"] == "/bin/service"]
        self.assertEqual([launch["identity"] for launch in services], ["inherited/unknown", "requested:0:0", "requested:100:100"])

    def test_script_modifiers_persist_only_when_standalone(self):
        result = self.inspect('[+script] run={\n[cpu=2]\n[+critical] /a &\n/b &\n}\n')
        self.assertEqual(result["launches"][0]["modifiers"], {"cpu": "2", "critical": True})
        self.assertEqual(result["launches"][1]["modifiers"], {"cpu": "2"})

    def test_internal_command_and_external_modifier_have_different_dependencies(self):
        result = self.inspect('[+script] run={\nwaitfor /dev/disk\n[+external] waitfor /dev/disk\n}\n')
        self.assertEqual(len(result["launches"]), 1)
        self.assertEqual(result["launches"][0]["command"], "waitfor")

    def test_bootstrap_path_local_script_path_and_process_manager_symlink(self):
        result = self.inspect('[virtual=x86_64,bios] boot={\nstartup-x86\nPATH=/proc/boot\nprocnto-smp-instr\n}\n[+script] run={\nPATH=/else task &\ntask &\nprocmgr_symlink /proc/boot/task /usr/bin/linked\n/usr/bin/linked &\n}\ntask=stub\n')
        self.assertEqual([l["resolution"] for l in result["launches"]], ["not-listed", "listed", "listed"])
        missing = next(f for f in result["findings"] if f["code"] == "L201")
        self.assertEqual(missing["confidence"], "heuristic")
        self.assertIn("filesystem", missing["remedy"])

    def test_shell_operator_and_quoted_argument_are_distinguished(self):
        result = self.inspect('[+script] run={\n/bin/tool | /bin/other\n/bin/tool "|" &\n}\n')
        self.assertEqual(sum(f["code"] == "S302" for f in result["findings"]), 1)
        self.assertEqual(len(result["launches"]), 1)

    def test_unknown_environment_changes_do_not_create_false_nested_launches(self):
        result = self.inspect('[+script] run={\non -E -u100 app &\non -e PATH=/else app &\non --invented app &\n}\n')
        self.assertEqual([l["command"] for l in result["launches"]], ["on", "on", "on"])
        self.assertTrue({"C401", "C402"}.issubset(self.codes(result)))

    def test_nondefault_mount_and_unset_target_variable_are_explicitly_partial(self):
        result = self.inspect('[mount=/ifs] /a=src\n${UNKNOWN}=src\n')
        self.assertEqual([e["target"] for e in result["entries"]], [None, None])
        self.assertIn("C204", result["coverage_limits"])

    def test_host_file_search_is_opt_in_and_explicit(self):
        self.write("assets/payload", "fixture only")
        text = f'[search=assets]\n/a=payload\n[+optional] /b=missing\n'
        unchecked = self.inspect(text)
        checked = self.inspect(text, check_host_files=True)
        self.assertNotIn("H201", self.codes(unchecked))
        self.assertEqual([d["resolved"] for d in checked["dependencies"]], ["assets/payload", None])
        self.assertEqual(next(f for f in checked["findings"] if f["code"] == "H201")["severity"], "warning")

    def test_basename_host_file_uses_search_not_accidental_cwd_match(self):
        self.write("payload", "wrong CWD file")
        self.write("assets/payload", "correct search file")
        result = self.inspect('[search=assets]\n/a=payload\n', check_host_files=True)
        self.assertEqual(result["dependencies"][0]["resolved"], "assets/payload")

    def test_inline_backslash_newline_does_not_join_script_commands(self):
        result = self.inspect('[+script] run={\n/bin/one &\\\n/bin/two &\n}\n')
        self.assertEqual([l["command"] for l in result["launches"]], ["/bin/one", "/bin/two"])
        self.assertTrue(all(l["background"] for l in result["launches"]))

    def test_ambient_environment_is_not_read_or_executed(self):
        os.environ["QNX_INSPECTOR_TEST_SECRET"] = "/private"
        self.addCleanup(os.environ.pop, "QNX_INSPECTOR_TEST_SECRET", None)
        result = self.inspect('${QNX_INSPECTOR_TEST_SECRET}/x=payload\n')
        self.assertIsNone(result["entries"][0]["target"])
        self.assertIn("C204", self.codes(result))

    def test_permission_review_and_invalid_numeric_owner(self):
        result = self.inspect('[perms=04777 uid=root] /app=stub\n')
        self.assertTrue({"F201", "F202"}.issubset(self.codes(result)))

    def test_known_missing_optional_source_is_not_a_listed_launch_dependency(self):
        result = self.inspect('[+optional] /bin/optional=absent\n[+script] run={\n/bin/optional &\n}\n', check_host_files=True)
        self.assertFalse(result["entries"][0]["selected"])
        self.assertEqual(result["launches"][0]["resolution"], "not-listed")

    def test_invalid_modifier_value_forms_are_reported(self):
        result = self.inspect('[+script] run={\n[+cpu session=1] /bin/app &\n}\n')
        self.assertEqual(sum(f["code"] == "S305" for f in result["findings"]), 2)

    def test_html_escapes_untrusted_source_and_has_no_remote_dependencies(self):
        result = self.inspect('/etc/test={\n<script>alert("x")</script>\n}\n')
        rendered = html_report(result)
        self.assertIn('&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;', rendered)
        self.assertNotIn('<script>alert("x")</script>', rendered)
        self.assertNotIn('<script src=', rendered)
        self.assertIn("default-src 'none'", rendered)

    def test_cli_exit_codes_json_and_html_files_are_reproducible(self):
        script = Path(__file__).resolve().parents[1] / "qnx_inspector.py"
        self.write("bad.build", "/x=one\n/x=two\n")
        command = [sys.executable, str(script), str(self.root / "bad.build"), "--json", str(self.root / "out.json"), "--html", str(self.root / "out.html")]
        process = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(process.returncode, 1, process.stderr)
        report = json.loads((self.root / "out.json").read_text(encoding="utf-8"))
        self.assertFalse(report["compiler_or_runtime_validation"])
        self.assertEqual(report["summary"]["error"], 1)
        self.assertIn("D201", process.stdout)
        process = subprocess.run(command + ["--fail-on", "never"], capture_output=True, text=True)
        self.assertEqual(process.returncode, 0)


if __name__ == "__main__":
    unittest.main()
