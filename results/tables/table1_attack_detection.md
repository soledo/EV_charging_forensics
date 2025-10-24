# Table 1: Attack Start Detection Results

| Scenario | Layer | Detection Time (s) | Confidence | Method |
| --- | --- | --- | --- | --- |
| DoS | Host | 182.3 | High | 2σ |
| DoS | Network | 1703188986.0 | High | First packet |
| DoS | Power | 75060.0 | Medium | First packet |
| Recon | Host | 340.2 | High | 2σ |
| Recon | Network | 1703187884.4 | High | First packet |
| Recon | Power | 23580.0 | Medium | First packet |
| Cryptojacking | Host | 5.0 | High | 2σ |
| Cryptojacking | Power | 164760.0 | Medium | First packet |

**Notes**:
- Detection Time: Relative to dataset start (not attack-relative)
- 2σ: Anomaly detection using benign baseline + 2 standard deviations
- Confidence: High (confirmed), Medium (threshold crossing), Low (fallback)
