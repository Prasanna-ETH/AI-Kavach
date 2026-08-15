# Scanner Payload Library

This directory contains YAML payload packs used by LLM Sentinel to execute single-turn and multi-turn security scans against target LLM API endpoints.

## Payload Library Structure

```
scanner/payloads/
├── handwritten/                  # Hand-authored security payload packs
│   ├── jailbreak.yaml           # Single-turn jailbreak & persona bypass prompts
│   ├── prompt_injection.yaml    # System prompt override & direct injection prompts
│   ├── sensitive_data_leak.yaml # Credential, API key & PII harvesting prompts
│   └── multiturn_jailbreak.yaml # Multi-turn red-teaming dialogue scenarios
├── jbb_derived/                  # Benchmark dataset-derived YAML packs
│   ├── jbb_harmful.yaml         # JailbreakBench harmful behaviors pack
│   └── jbb_benign.yaml          # JailbreakBench benign behaviors pack
└── README.md
```

## Regenerating JailbreakBench Payload Packs

To regenerate the JailbreakBench YAML packs from raw CSV dataset files:

```bash
# Import harmful behaviors dataset
python -m scanner.cli dataset import-behaviors --csv dataset/harmful-behaviors.csv --output scanner/payloads/jbb_derived/jbb_harmful.yaml --label harmful

# Import benign behaviors dataset
python -m scanner.cli dataset import-behaviors --csv dataset/benign-behaviors.csv --output scanner/payloads/jbb_derived/jbb_benign.yaml --label benign
```

## Dataset Policy

Raw CSV research datasets (such as JailbreakBench source CSV files) should remain gitignored under `dataset/` or kept in external raw data storage. The generated YAML payload packs under `scanner/payloads/` are committed to the repository as part of the core payload library.
