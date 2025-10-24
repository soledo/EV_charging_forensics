# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains the **CICEVSE2024 Dataset** for EV charging station forensics research. It implements a Multi-Layer Cyber Event Reconstruction (MLCER) framework for detecting and analyzing cyberattacks on Electric Vehicle Supply Equipment (EVSE).

The project analyzes attacks across three data layers:
- **Network Traffic**: PCAP files and extracted network flow features
- **Host Events**: Hardware Performance Counters (HPC) and kernel events from Raspberry Pi
- **Power Consumption**: Electrical power measurements during charging operations

## Dataset Structure

```
CICEVSE2024_Dataset/
├── Network Traffic/
│   ├── EVSE-B/
│   │   ├── pcaps/          # Raw network captures (.pcap files)
│   │   └── csv/            # Extracted network flows (NFStream features)
│   ├── pcap2csv.py         # Script to extract features from PCAPs
│   └── Readme.txt
├── Host Events/
│   ├── EVSE-B-HPC-Kernel-Events-Combined.csv  # Preprocessed labeled data
│   ├── Individual Files/   # Raw session files
│   └── Readme.txt
├── Power Consumption/
│   ├── EVSE-B-PowerCombined.csv  # Timestamped power logs
│   └── readme.txt
└── CICEVSE2024_Dataset_Attacks.pdf  # Attack scenario documentation
```

## Attack Scenarios

The dataset includes both benign and attack scenarios:

**Attack Types:**
- **Reconnaissance**: tcp-port-scan, service-version-detection, os-fingerprinting, aggressive-scan, syn-stealth-scan, vulnerability-scan
- **DoS Attacks**: slowloris-scan, udp-flood, icmp-flood, psh-ack-flood, icmp-fragmentation, tcp-flood, syn-flood, synonymous-ip-flood
- **Cryptojacking**: Unauthorized cryptocurrency mining
- **Backdoor**: Persistent unauthorized access

**Communication Protocols:**
- OCPP (Open Charge Point Protocol) - Wifi interface
- ISO15118 (V2G) - Ethernet interface

## Device Topology

| Device | Role | Interface | MAC/IP |
|--------|------|-----------|--------|
| EVSE-A (Grizzl-E) | OCPP Client | Wifi | oc:8b:95:09:c6:08 |
| EVSE-B (RPi) | OCPP Client | Wifi | dc:a6:32:c9:e5:5f |
| EVSE-B (RPi) | V2G Server | Eth0 | dc:a6:32:c9:e5:5e |
| EVCC (RPi) | V2G Client | Eth0 | dc:a6:32:c9:e6:9f |
| Local CSMS (RPi) | OCPP Server | Wifi | dc:a6:32:c9:e5:3e |
| Attacker (RPi/Kali) | Attacker | Wifi | dc:a6:32:dc:25:d5 / a8:6b:ad:1f:9b:e5 |
| Remote CSMS | OCPP Server | - | 162.159.140.98 |

## Data Processing Workflow

The research follows a 7-stage pipeline documented in `plan.md`:

1. **Stage 0-1**: Data exploration and understanding
2. **Stage 2**: Preprocessing and data cleaning
3. **Stage 3**: Time anchor extraction for synchronization
4. **Stage 4**: Multi-layer timeline integration
5. **Stage 5**: Cross-layer correlation and causal analysis
6. **Stage 6**: Baseline comparison (MLCER vs single-layer methods)
7. **Stage 7**: Evaluation and visualization

## Key Data Characteristics

**Host Events:**
- 86 Hardware Performance Counters (HPC) - See Host Events/Readme.txt lines 7-31
- 600+ Kernel events (see lines 34+)
- Sampling rate: ~5 seconds
- Source: Raspberry Pi running EVSE-B

**Network Traffic:**
- Extracted using NFStream library
- First 1000 packets per PCAP available in CSV format
- Statistical flow analysis enabled
- To extract more: modify `pcap2csv.py` max_packets parameter

**Power Consumption:**
- Features: shunt_voltage (mV), bus_voltage (V), current_mA, power_mW
- Sampling rate: 1 second
- Source: I2C Wattmeter on EVSE-B
- Labels: State (Idle/Charging), Scenario, Attack type, Interface

## Working with Network Data

**Extract features from PCAP files:**
```python
# Modify pcap2csv.py paths:
input_directory = 'CICEVSE2024_Dataset/Network Traffic/EVSE-B/pcaps/'
output_folder = 'output/csv_files/'
max_packets = 1000  # Increase as needed

# Run the script
python CICEVSE2024_Dataset/Network\ Traffic/pcap2csv.py
```

**Dependencies:** Requires `nfstream` package for PCAP processing

## Time Synchronization

Critical challenge: The three data layers have different sampling rates and timestamps:
- Network: Variable (packet arrival times)
- Host: ~5 second intervals
- Power: 1 second intervals

The MLCER framework uses **anchor-based alignment** to synchronize layers:
1. Identify common events across layers (e.g., charging session start)
2. Use these anchors to align timestamps
3. Validate alignment error < 2-5 seconds

## Analysis Approaches

**Single-Layer Baselines:**
- Host-only: Anomaly detection using HPC features
- Network-only: Traffic pattern classification
- Power-only: Consumption pattern matching

**MLCER (Multi-Layer):**
- Combined features from all three layers
- Causal relationship features (cross-layer dependencies)
- Protocol violation flags (OCPP/ISO15118 state machine deviations)
- Expected improvement: ~15% F1-score over best single-layer method

## Machine Learning Pipeline

**Feature Engineering:**
- Multi-layer feature extraction
- Lag features for causal analysis
- Protocol semantic features
- Statistical aggregates per session

**Model Training:**
- Session-based train/test split (not random - prevents data leakage)
- Recommended models: Random Forest, XGBoost, SVM
- Evaluation: Accuracy, Precision, Recall, F1-score (macro-average)
- Validation: 5-fold cross-validation, McNemar's test for significance

## Research Questions

The project addresses:
1. **RQ1**: Does MLCER outperform single-layer methods in attack reconstruction?
2. **RQ2**: Is anchor-based time alignment superior to naive alignment?
3. **RQ3**: Does physical layer (power) validation improve tampering detection?
4. **RQ4**: Do protocol semantic features improve attack classification?

## Important Considerations

**Data Integrity:**
- Check for missing timestamps
- Validate session boundaries
- Handle sampling rate differences
- Detect and handle outliers

**Session-Based Analysis:**
- Sessions should not be split across train/test sets
- Maintain scenario stratification
- Track session IDs for reproducibility

**Reproducibility:**
- Set random seeds for ML models
- Document all hyperparameters
- Save intermediate outputs at each stage
- Version control dependencies (requirements.txt)

## Label Schema

**Power Consumption Labels:**
- State: Idle, Charging
- Scenario: Benign, Recon, DoS, Cryptojacking, Backdoor
- Attack: Specific attack type or "None" for benign
- Label: Binary (Attack/Benign)
- Interface: OCPP, ISO15118

**Host Events Labels:**
- Combined CSV includes preprocessed labels
- Individual files contain raw session data

## Expected Outputs

**Intermediate Artifacts:**
- `multilayer_features.csv` - Combined feature set
- `time_anchors.csv` - Synchronization points
- `causal_lag_analysis.csv` - Cross-layer dependencies
- `attack_signatures.json` - Multi-layer attack profiles
- `protocol_violations.csv` - State machine deviations

**Models:**
- Trained classifiers for each baseline and MLCER
- Feature importance rankings
- Confusion matrices

**Visualizations:**
- Attack propagation timelines
- Cross-layer correlation heatmaps
- Performance comparison charts
- Protocol state transition diagrams

## Computing Requirements

**Minimum Specifications:**
- RAM: 16GB (32GB recommended for large-scale analysis)
- CPU: Multi-core (8+ cores recommended)
- Storage: 50GB free space
- Python environment with pandas, sklearn, nfstream

**Estimated Processing Time:**
- Full pipeline: 34-54 hours
- Individual stages: 2-12 hours depending on complexity
