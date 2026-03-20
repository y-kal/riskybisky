# riskybisky

## ATT&CK mapping pipeline

Generate ATT&CK mappings and a technique summary from scored vulnerabilities:

```bash
python -m sbom_tool.map_attack --scan-dir artifacts/<artifact_key>
```

This writes:

- `artifacts/<artifact_key>/attack_mapping.json`
- `artifacts/<artifact_key>/attack_summary.json`

Export the technique summary as an ATT&CK Navigator layer:

```bash
python -m sbom_tool.export_navigator --scan-dir artifacts/<artifact_key>
```

This writes:

- `artifacts/<artifact_key>/attack_navigator_layer.json`
