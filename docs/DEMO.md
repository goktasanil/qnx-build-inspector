# Three-minute demonstration guide

This is a suggested narration and sequence for recording the actual working host tool. No video, public upload or hackathon submission has been made by this project.

1. **Problem (20 seconds).** A QNX IFS buildfile combines host-file mapping, image paths and a restricted startup command language. A duplicated alias or a file-ownership/process-identity mix-up can hide in a long buildfile tree.
2. **Run the CLI (25 seconds).** Run the broken example from the README. Show the nonzero exit code and the report's explicit partial-analysis statement. The tool runs on the development host without a QNX SDK or network.
3. **Inspect evidence (60 seconds).** Open the generated broken HTML report. Filter Errors. Select the duplicate target finding and jump to both source positions. Show the file under a declared symlink. Then show the invalid `uid=` script modifier and explain the distinction from the `on -u` wrapper.
4. **Dependency review (30 seconds).** Show the launch map: commands represented in the image versus a missing auditor. Explain that external filesystems are a valid reason for a missing image reference and that identity is a requested configuration, not a verified process credential.
5. **Correction and verification (35 seconds).** Open the corrected report and run the tests. Say exactly how many tests passed in the current run. Explain that the examples use text placeholders; no bootable image or SDK/compiler validation is claimed.
6. **Scope (10 seconds).** Point to the official QNX 8 source links and limitations in README. The project supports QNX development by analyzing build configuration on the host; target validation remains a separate engineering step.

For the recording, keep both report tabs already open. Use a real terminal run, avoid fabricated output, and keep the video under the contest's three-minute limit. Public source/video URLs must be added by the submitting user workflow after publication.
