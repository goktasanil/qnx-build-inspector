# QNX Build Inspector

Find image-path conflicts and startup dependency mistakes before invoking `mkifs`.

QNX Build Inspector is an offline, host-side static analyzer for a documented subset of **QNX OS 8.0 IFS buildfiles**. It reads a buildfile tree, models explicit image entries, traces inline startup launches, and produces source-linked human, JSON and standalone HTML reports. It runs with **Python 3.10+ and the standard library** on Windows, Linux or macOS. There are no pip dependencies, network requests, SDK binaries or paid services.

The project is independent work by **Anıl Göktaş**. It is not QNX certified or endorsed.

## Run the demonstration

From this directory, using an installed Python interpreter:

```sh
python qnx_inspector.py examples/demo/broken.buildfile --cwd examples/demo --html reports/broken.html --json reports/broken.json
python qnx_inspector.py examples/demo/corrected.buildfile --cwd examples/demo --html reports/corrected.html --json reports/corrected.json
python -m unittest discover -s tests -v
```

Open `reports/broken.html` in a browser. Filter the findings and follow a location link to the exact source line. Compare `reports/corrected.html`. Both reports work offline, without a server. Generated reports and JSON include the analyzed source text, so review their contents before sharing your own inputs.

The broken example deliberately contains a duplicated configuration target, a file under an IFS symlink, an explicit world-writable set-ID permission, a mistaken `uid=` script modifier, an explicit root launch and missing launch references. The corrected example fixes these configuration issues in the modeled subset.

**The payloads are synthetic text fixtures, not executables. The examples are not bootable QNX images.** A clean report demonstrates that the modeled checks found no issues; it does not establish that the configuration builds, boots or is secure.

### Configure a real project

```sh
python qnx_inspector.py path/to/image.buildfile --cwd path/to/build-directory --project-root path/to/trusted-project --define QNX_TARGET=/path/to/qnx/target --define PROCESSOR=x86_64 --define MKIFS_PATH=/explicit/search/path --check-host-files --json inspection.json --html inspection.html
```

Use the build's actual CWD. Include lookup uses that CWD, then the explicit `search` list. Ordinary basename-only host sources use `search`; relative host sources containing a directory separator try CWD first. Repeat `--include-dir` for additional root/SDK `boot/build` directories; this version does not infer the SDK's implicit lookup expansion. Included files must resolve inside `--project-root` (default: top buildfile directory). Symlinks are resolved before that boundary check. Analysis stops at 32 include levels, 128 files or 4 MiB combined input.

Ambient environment values are not imported. Repeat `--define NAME=VALUE` for values you want analyzed. `${NAME}` supports one explicit expansion pass from these definitions. Bootstrap/script assignments model runtime PATH; build-time substitution from variables assigned inside those bodies is not modeled, so supply needed values explicitly. `PFS` defaults to the current host's path-list separator; use `--define PFS=:` when modeling a Linux-host search list on Windows. No shell, substitutions, macros or commands are executed.

`--check-host-files` checks source existence, not contents or executable validity. Missing required files are errors; absent optional files are notes/warnings and are excluded from the selected inventory. This check is optional because many developers review buildfiles without the target SDK installed.

Exit codes: `0` means the configured failure threshold was not reached, `1` means findings met the threshold, and `2` means CLI usage/report writing failed. The default threshold is `error`; use `--fail-on warning` in stricter CI or `--fail-on never` when collecting a report without failing a pipeline. An exit code of zero is not a compiler acceptance claim.

## What the analyzer models

- One bracket group per line; boolean/value/conditional attributes; local versus persistent defaults; double-quoted fields; documented escape forms; outside-inline line continuations.
- Inline file boundaries and opaque data; explicit aliases and basename placement; in-place buildfile includes, cycles and repeated includes; global settings carried back from included files.
- Duplicate target selection with `+dupignore`; file/link ancestors; direct symbolic-link cycles; numeric file ownership and explicit octal permission review.
- Inline script modifiers, environment-only lines and per-command PATH overrides; internal commands and `+external`; background markers; ordinary launch candidates; direct IFS/process-manager symlink resolution.
- The documented `on -u` wrapper, including a separate nested dependency and requested identity. The identity remains a request, not verified process credentials.

`uid=` on a **file** changes ownership. It is not a documented mkifs **script modifier**. The tool reports this common confusion explicitly, instead of assuming a process runs as the file owner. Direct launches retain `inherited/unknown` identity; explicit root requests are review warnings, not assertions that root is inherently wrong for a driver.

## Confidence and limits

Every finding has a source position, remedy, official documentation link and confidence label. High-confidence findings concern explicit declarations, such as duplicate targets. Launch inventory gaps and foreground sequencing use heuristic confidence: external filesystems may provide commands, and a foreground program may exit normally. Unsupported syntax/settings produce coverage markers and the report always identifies itself as **partial static analysis**.

This is not a complete `mkifs` grammar or compatibility implementation. Advanced nested attribute expressions, filters, `cd`/`drop` semantics, recursive directory imports, external script/bootstrap bodies and non-default IFS mount mapping are not modeled. Non-default mounts and unresolved target variables skip path-dependent checks for the affected entries. `on -E`/`-e` and unknown wrapper options skip the nested inference. Only direct symlink chains are followed; symlinked parent-directory launch resolution is not inferred. Quoting/continuations that cross unusual inline boundaries can require manual review.

It does not inspect ELF/SONAME dependencies, expand `autoso`, validate architecture/ABI/toolchain output, evaluate security policy/abilities, derive effective UID from runtime behavior or set-ID bits, check device readiness, run `mkifs`, build an IFS, or boot QNX. Use the QNX SDK, `mkifs`, `dumpifs` and target tests to resolve those questions.

## Why this is QNX developer tooling

The analysis is specific to QNX 8 `mkifs` semantics: image aliases, bootstrap/script sections, persistent attributes and includes, `dupignore` precedence, process-manager internal commands, script modifiers, and QNX's `on` utility. The output helps a developer analyze software/configuration targeting QNX 8 before an SDK build. It is a working host tool rather than a general diagram or a renamed shell linter.

The [QNX Global Hackathon rules](https://qnx.devpost.com/rules) include host tools that support building, testing or analyzing QNX 8 software. This project targets its **Developer Tooling & Host Tools** category. Eligibility acceptance and judging remain the organizer's decision; no competition submission is included in this repository.

## Development and attribution

Run the tests with the command above. Tests cover scoped includes, attribute propagation, malformed input recovery, escaped inline text, duplicate precedence, target alias behavior, launch/environment inference, ownership confusion, HTML escaping, trust/resource boundaries and CLI exit/report behavior. They are behavioral checks of this implementation, not a QNX compiler conformance suite.

Source code and original synthetic fixtures use the [MIT license](LICENSE). [Official technical sources and excerpt attribution](docs/SOURCES.md) record the QNX 8 documentation consulted **before implementation on 9 November 2026**. The small documentation excerpt retains its original attribution; no QNX SDK source or binaries are distributed.

This implementation was created with AI coding assistance at Anıl Göktaş's direction. AI assistance is disclosed; there is no claim that QNX or a compiler validated the generated code. See [validation results](docs/VALIDATION.md) and [demo guide](docs/DEMO.md).
