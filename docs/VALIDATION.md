# Validation record

Executed on **9 November 2026**, Windows host, existing **CPython 3.11.15**, without installing packages.

| Check | Observed result |
|---|---|
| `python -m unittest discover -s tests -v` | **31 tests passed**. The captured output is in `test-results.txt`. |
| Broken synthetic example | Exit **1**; **2 files**, **9 entries**, **7 launch records**, **3 errors**, **5 warnings**, **1 review note**. |
| Corrected synthetic example | Exit **0**; **2 files**, **8 entries**, **3 launch records**, **0 errors/warnings/notes**. |
| Human / JSON / HTML export | Both examples generated all three formats in `reports/`. |
| Report source handling | Tests verified untrusted HTML source is escaped, no remote script dependency is introduced, and report filtering/source links are generated. |
| Include and input boundaries | Tests verified outside-project includes are not read, cycles/repeated includes are distinguished, and the depth limit is reported. |
| Environment and launch inference | Tests covered scoped PATH assignments, internal/external commands, explicit `on -u` requests, unknown wrapper environment changes, and no ambient environment import. |

Example commands are in the README. The generated text reports are `reports/broken.txt` and `reports/corrected.txt`; corresponding JSON and HTML use the same stem. The configured error threshold explains the broken example's intentional nonzero status.

These checks validate this tool's documented behavior against synthetic fixtures and a small attributed documentation excerpt. They do **not** establish conformance to every `mkifs` grammar production. No QNX SDK, compiler, linker, ELF inspection, `mkifs`, IFS build, QEMU image or QNX target execution was available or run. The corrected fixture contains placeholder text payloads, so it is deliberately not a runnable target image.

Version 0.1.0 remains a partial static-analysis prototype. Important limits include non-default mount layouts, external script bodies, advanced attributes, directory imports, dynamic loader dependencies, security policies, and build-time variables assigned inside bootstrap/script bodies. The README explains each limit and the intended SDK follow-up.
