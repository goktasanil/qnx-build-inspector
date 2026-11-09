# Technical source record

Primary QNX SDP **8.0** documentation was read before implementation on **9 November 2026**. The tool links findings back to these official pages. These links describe language semantics; they do not certify this independent implementation.

| Source | Implementation decision |
|---|---|
| [Buildfile syntax](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.building/topic/buildfiles/buildfile_syntax.html) | Bracket grouping, local/persistent scope, separate inline boundary lines and escaping. |
| [mkifs reference](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.utilities/topic/m/mkifs.html) | Attribute categories, conditional settings, include stream ordering/cycles, `dupignore` precedence, file types and explicit permissions. Advanced unsupported semantics are surfaced as coverage limits. |
| [Script file](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.building/topic/buildfiles/nto_script.html) | Inline startup modifiers; internal commands; foreground/background sequencing; external filesystem caveat for launch dependencies. |
| [Environment variables](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.building/topic/buildfiles/nto_buildfile_envars.html) | Bootstrap PATH seeding and global versus command-local startup environment assignments. |
| [Including files](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.building/topic/buildfiles/nto_files_default_paths.html) | Explicit CWD/search lookup. The CLI requires additional SDK include directories rather than pretending it knows an installed SDK layout. |
| [Target file locations](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.building/topic/buildfiles/nto_files_target.html) | A plain host path contributes a basename at the prefix; an explicit target alias preserves the specified image location. |
| [on utility](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.utilities/topic/o/on.html) | Numeric/named `-u` credential requests; supported option shapes; detached launches and environment-inference limits. |

## Small attributed documentation fixture

`examples/documented_fragment.buildfile` contains a **23-token excerpt** of the bootstrap/startup portion of QNX's [Minimal configuration](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.building/topic/config/minimal_configuration.html), page dated 11 June 2026. Source publisher: QNX / BlackBerry Limited. It is used to test parsing of documented syntax, omitting other image contents. It is not a complete buildfile, and it is not represented as our original sample or covered by our MIT grant.

All `examples/demo` configurations and placeholder payloads are original synthetic test material. They contain no copied BSP, driver, SDK implementation or executable. Generic command/attribute names are used to exercise publicly documented interfaces.

## Interpretation notes

- A missing launch means “not listed at modeled image paths,” not “cannot run”: a previously mounted filesystem can provide it.
- `uid=` file attributes cannot establish process identity. The script modifier set and `on -u` are separate documented interfaces.
- Non-default mount layouts, expanded directory trees, dynamic loader behavior and security policy are intentionally left to the SDK/target workflow.
- The tool's JSON field `compiler_or_runtime_validation` is always false. The listed source SHA-256 hashes cover the original input bytes, including their original newline encoding.
