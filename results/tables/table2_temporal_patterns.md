# Table 2: Temporal Pattern Summary

| Scenario | Phase | Layer | Mean | Std | Max | Trend |
| --- | --- | --- | --- | --- | --- | --- |
| DoS | Initiation | Host | 0.1223 | 0.0276 | 6.5648 | -0.000752 |
| DoS | Initiation | Network | 13341670.8250 | 17920324.4385 | 215556236.0000 | -5223719.651818 |
| DoS | Initiation | Power | 0.3301 | 0.0000 | 0.7966 | +0.000000 |
| DoS | Peak | Host | 0.0561 | 0.0407 | 5.7402 | -0.004242 |
| DoS | Peak | Network | 0.6500 | 1.1551 | 12.4000 | -0.048872 |
| DoS | Peak | Power | 0.0000 | 0.0000 | 0.0000 | +0.000000 |
| DoS | Sustained | Host | 0.0403 | 0.0281 | 4.4962 | +0.000115 |
| DoS | Sustained | Network | 0.0000 | 0.0000 | 0.0000 | +0.000000 |
| DoS | Sustained | Power | 0.3188 | 0.0000 | 0.8126 | +0.000000 |
| Recon | Initiation | Host | 0.6569 | 0.4830 | 77.8703 | -0.131293 |
| Recon | Initiation | Network | 46585.4570 | 66581.9462 | 873355.0000 | -17952.532788 |
| Recon | Initiation | Power | 0.3421 | 0.0000 | 0.7724 | +0.000000 |
| Recon | Peak | Host | 0.2275 | 0.2252 | 51.9679 | -0.018504 |
| Recon | Peak | Network | 5773.3040 | 1992.3945 | 52585.6000 | -156.385925 |
| Recon | Peak | Power | 0.0000 | 0.0000 | 0.0000 | +0.000000 |
| Recon | Sustained | Host | 0.0733 | 0.0520 | 9.1674 | -0.002428 |
| Recon | Sustained | Network | 4896.3603 | 2580.3809 | 52790.2000 | +165.201577 |
| Recon | Sustained | Power | 0.3331 | 0.0000 | 0.7793 | +0.000000 |
| Cryptojacking | Initiation | Host | 0.0637 | 0.0146 | 2.3241 | +0.003492 |
| Cryptojacking | Initiation | Power | 0.5263 | 0.0000 | 0.6482 | +0.000000 |
| Cryptojacking | Peak | Host | 0.0773 | 0.0064 | 2.6536 | +0.000164 |
| Cryptojacking | Peak | Power | 0.0000 | 0.0000 | 0.0000 | +0.000000 |
| Cryptojacking | Sustained | Host | 0.0727 | 0.0125 | 2.4674 | +0.000225 |
| Cryptojacking | Sustained | Power | 0.5331 | 0.0000 | 0.6561 | +0.000000 |

**Notes**:
- Mean/Std/Max: Normalized intensity values (0-1 scale)
- Trend: Linear slope (OLS) across phase duration
- Positive trend = increasing, negative = decreasing
- Phases: Initiation (0-10s), Peak (10-30s), Sustained (30-60s)
