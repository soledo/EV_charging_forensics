# Table 3: Time-Lagged Cross-Layer Correlation

| Scenario | Layer Pair | Optimal Lag (s) | r | p-value | Interpretation |
| --- | --- | --- | --- | --- | --- |
| DoS | Network → Host | -6 | 0.642 | <0.0001 | NETWORK leads HOST by 6 seconds |
| DoS | Host → Power | -4 | 1.000 | <0.0001 | HOST leads POWER by 4 seconds |
| DoS | Network → Power | -7 | 1.000 | <0.0001 | NETWORK leads POWER by 7 seconds |
| Recon | Network → Host | -1 | 0.825 | <0.0001 | NETWORK leads HOST by 1 seconds |
| Recon | Host → Power | -6 | 1.000 | <0.0001 | HOST leads POWER by 6 seconds |
| Recon | Network → Power | -7 | 1.000 | 0.0003 | NETWORK leads POWER by 7 seconds |
| Cryptojacking | Host → Power | -6 | 0.997 | 0.0002 | HOST leads POWER by 6 seconds |

**Notes**:
- Optimal Lag: Time shift (seconds) that maximizes |r|
- Negative lag: First layer leads second layer
- Positive lag: Second layer leads first layer
- r: Pearson correlation coefficient (-1 to +1)
- p-value: Statistical significance (α=0.05)
- Interpretation: Temporal relationship between layers
