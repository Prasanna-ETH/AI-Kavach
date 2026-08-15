# Scanner Payload Library

This directory contains YAML payload packs used by LLM Sentinel to execute single-turn and multi-turn security scans against target LLM API endpoints.

## Included Payload Packs

- `jailbreak.yaml`: Hand-curated single-turn jailbreak and persona bypass payloads.
- `prompt_injection.yaml`: System prompt override and direct prompt injection payloads.
- `sensitive_data_leak.yaml`: PII, API key, and credential harvesting payloads.
- `multiturn_jailbreak.yaml`: Multi-turn red-teaming dialogue scenarios.
- `jbb_harmful.yaml`: JailbreakBench harmful behaviors payload pack (imported from `harmful-behaviors.csv`).
- `jbb_benign.yaml`: JailbreakBench benign behaviors payload pack (imported from `benign-behaviors.csv`).

## Regenerating JailbreakBench Payload Packs

To regenerate the JailbreakBench YAML packs from raw CSV dataset files:

```bash
# Import harmful behaviors dataset
python -m scanner.cli dataset import-behaviors --csv dataset/harmful-behaviors.csv --output scanner/payloads/jbb_harmful.yaml --label harmful

# Import benign behaviors dataset
python -m scanner.cli dataset import-behaviors --csv dataset/benign-behaviors.csv --output scanner/payloads/jbb_benign.yaml --label benign
```

## Dataset Policy

Raw CSV research datasets (such as JailbreakBench source CSV files) should remain gitignored under `dataset/` or kept in external raw data storage. The generated YAML payload packs under `scanner/payloads/` are committed to the repository as part of the core payload library.
