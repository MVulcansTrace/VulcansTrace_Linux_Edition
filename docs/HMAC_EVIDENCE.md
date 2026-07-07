# HMAC evidence signing key flow

This app generates an HMAC signing key after each completed analysis.
The key is tied to that analysis session so repeated exports of the same result
can be verified with the same key.

## How to get the signing key

1. Paste a log and click Analyze.
2. After analysis completes, the session signing key is generated and masked in the UI.
3. Click Export Evidence and save the ZIP file.
4. Click Copy signing key to place the key on the clipboard.

## Why the Copy signing key button is disabled at first

The key does not exist until analysis has completed. Once analysis runs and the
key is generated, the button enables so you can copy the key.

## Notes

- The key displayed in the UI is masked (asterisks). The full hex key is placed on the clipboard when you click **Copy signing key**.
- If you re-run analysis and export again, a new key is generated for that analysis session.

## Verify a bundle from the CLI

The optional `tools/TestAnalysis` runner can verify a bundle with the copied key:

```bash
dotnet run --project tools/TestAnalysis -- --verify evidence.zip --key <64-character-hex-key>
```

Verification fails if the manifest HMAC does not match, if any manifest-listed file is missing, or if a file hash no longer matches the manifest.

## Trace Map files

When findings are present, the evidence bundle also includes:

- `incident-story.md` — flowing attack narrative with time-ordered beats, likely chain summary, and recommended responses (matches the Incident Story tab)

When correlated edges are detected, the evidence bundle also includes:

- `trace-map.md` — technical edge-list Markdown showing correlated findings, per-edge narratives, and CIS mappings
- `trace-map.json` — Cytoscape.js-compatible graph with findings as nodes and correlations as edges

These files are listed in `manifest.json` and covered by the same HMAC signature as all other evidence files.
