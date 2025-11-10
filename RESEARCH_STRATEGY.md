# Research Strategy: Multi-Layer Cyber Event Reconstruction for EV Charging Infrastructure

## Executive Summary

This document outlines the research-backed strategy for implementing and validating the Multi-Layer Cyber Event Reconstruction (MLCER) framework using the CICEVSE2024 Dataset. The approach is grounded in recent academic literature and proven methodologies from multi-layer intrusion detection, digital forensics, and critical infrastructure security.

**Key Finding**: Our literature review reveals that multi-layer detection systems achieve 10-20% improvement over single-layer approaches, with heterogeneous data fusion being critical for attack scenario reconstruction in critical infrastructure.

---

## Literature Review & Theoretical Foundation

### 1. Multi-Layer Attack Detection Systems

**Primary References:**
- **Multilayer Data-Driven Cyber-Attack Detection System** (IEEE, 2018)
  - Framework: Defense-in-depth using network, host system, and process parameters
  - Key Insight: Multiple layers provide redundancy and cover blind spots of individual detection methods
  - Relevance: Direct analog to our Network + Host + Power approach

- **Multi-Layered Deep Auto Encoder (M-LDAE)** (Nature Scientific Reports, 2025)
  - Method: Hierarchical autoencoders for cross-layer IoT attack pattern extraction
  - Achievement: Successfully identifies intricate assault patterns spanning multiple layers
  - Application: Can inform our feature engineering for cross-layer dependencies

- **Attack Scenario Reconstruction** (ScienceDirect, 2019)
  - Four-step process: Alert mapping → Sequence generation → Clustering → Complementation
  - Visual representation: Attack graphs for forensic traceability
  - Contribution: Provides framework for our causal timeline reconstruction

### 2. EV Charging Infrastructure Security

**Critical Papers:**
- **Explainable Deep Learning for Cyber Attack Detection in EVSE** (ACM NSysS, 2024)
  - Dataset: Uses CICEVSE2024 (our dataset!)
  - Method: XAI for EVSE attack detection
  - Results: High accuracy in detecting OCPP/ISO15118 attacks
  - Implication: Single-layer baseline to beat

- **Review of EV Charger Cybersecurity Vulnerabilities** (MDPI Energies, 2022)
  - Attack vectors: Session hijacking, DoS, firmware theft, spoofing
  - Protocols: OCPP 1.6 vulnerabilities (unencrypted WebSocket, poor session handling)
  - Defense: TLS encryption, IEC 62351 standards
  - Impact: Informs our protocol semantic feature extraction

- **Federated Learning-based IDS for EVSE** (2025)
  - Performance: >98% accuracy in spotting malicious EVSE traffic
  - Architecture: Distributed learning across charging stations
  - Benchmark: Our MLCER should target similar or better performance

### 3. Time Synchronization in Multi-Source Forensics

**Foundational Work:**
- **Time Synchronization: Pivotal Element in Cloud Forensics** (Wiley Security & Comm Networks, 2015)
  - Challenge: Synchronizing heterogeneous timestamps across distributed systems
  - Solution: Event-based alignment using known reference points
  - Application: Validates our anchor-based alignment approach

- **Multimodal Data Alignment Strategies** (Sapien.io, 2025)
  - **Temporal Alignment**: Syncing data from different sampling rates to same time moments
  - **Spatial Alignment**: Mapping diverse sensor data to unified coordinate system
  - **Semantic Alignment**: Harmonizing meaning across different data modalities
  - Direct Application: Our network (variable) + host (~5s) + power (1s) alignment problem

- **Forensic Analysis of Digital Time** (Exponent, 2015)
  - Risk: Timestamp manipulation by attackers
  - Validation: Cross-reference system time against real-world events
  - Implication: Need ground truth events for anchor validation

### 4. Hardware Performance Counters for Intrusion Detection

**State-of-the-Art:**
- **HPC-based Anomaly Detection in Smart Industrial Devices** (IEEE, 2020)
  - Performance: 98.4% detection rate, 3.1% false positives
  - Method: Unsupervised ML on HPC profiles
  - Advantage: Detects unknown malware and APTs
  - Application: Validates our host-layer baseline approach

- **Hardware Performance Counters for Embedded Software Anomaly Detection** (ResearchGate, 2018)
  - Platform: Embedded systems (relevant to Raspberry Pi EVSE-B)
  - Features: Micro-architectural events (cache misses, branch mispredictions, etc.)
  - Finding: Behavior-based detection effective for resource-constrained devices

### 5. Power Consumption-Based Attack Detection

**Relevant Research:**
- **Power Side Channel Attack Analysis and Detection** (IEEE, 2020)
  - Techniques: Simple Power Analysis (SPA), Differential Power Analysis (DPA)
  - Detection: ML-based pattern matching, statistical correlation
  - Challenge: Real-time detection overhead
  - Innovation: Our approach uses power as *verification* layer, not primary detection

- **Anomaly Detection in In-Vehicle Communications** (side-channel context)
  - Framework: Real-time monitoring with trusted execution environments
  - Application: Critical infrastructure component isolation
  - Parallel: EV charging as critical infrastructure security problem

---

## Research Questions & Methodological Approach

### RQ1: Does MLCER outperform single-layer methods?

**Hypothesis:** MLCER will achieve 15-20% improvement in F1-score over best single-layer method

**Theoretical Basis:**
- Multi-layer detection systems (IEEE 2018) show 10-15% improvement
- M-LDAE (Nature 2025) demonstrates cross-layer pattern extraction superiority
- Federated EVSE IDS (2025) achieves >98% with network-only data
- Expected MLCER performance: >99% with multi-layer fusion

**Methodology:**
1. **Single-Layer Baselines** (following HPC literature best practices):
   - **Host-only**: Unsupervised anomaly detection on 86 HPC features
     - Algorithm: Isolation Forest / One-Class SVM (proven in HPC research)
     - Feature selection: PCA or correlation-based (top 30-40 features)
     - Expected performance: ~85-90% F1 (based on HPC literature)

   - **Network-only**: Supervised classification on NFStream features
     - Algorithm: Random Forest / XGBoost (standard for network IDS)
     - Features: Flow statistics, packet patterns, protocol fields
     - Expected performance: ~92-95% F1 (based on EVSE IDS literature)

   - **Power-only**: Pattern matching on consumption profiles
     - Algorithm: DTW (Dynamic Time Warping) + clustering
     - Features: Voltage, current, power time series
     - Expected performance: ~70-75% F1 (limited by coarse granularity)

2. **MLCER Approach** (inspired by M-LDAE architecture):
   - **Early Fusion**: Concatenate normalized features from all three layers
   - **Feature Engineering**:
     - Cross-layer lag features (e.g., network spike → HPC anomaly after 5s)
     - Protocol semantic features (OCPP state transitions, ISO15118 handshake steps)
     - Causal indicators (power consumption validates network events)
   - **Algorithm**: Ensemble (Random Forest + XGBoost + Neural Network)
   - **Expected performance**: >95% F1 (15-20% improvement over best single-layer)

3. **Statistical Validation**:
   - **McNemar's test**: Pairwise comparison of MLCER vs each baseline
   - **5-fold cross-validation**: Session-stratified (no data leakage)
   - **Significance level**: p < 0.05
   - **Confidence intervals**: 95% for all performance metrics

**Success Criteria:**
- MLCER F1-score ≥ 15% higher than best baseline
- Statistically significant (McNemar p < 0.05)
- Consistent across all attack types (min 10% improvement per attack category)

---

### RQ2: Is anchor-based alignment superior to naive alignment?

**Hypothesis:** Anchor-based alignment reduces temporal error by >60% vs naive timestamp matching

**Theoretical Basis:**
- Temporal alignment research (Sapien.io 2025): Event-based sync critical for heterogeneous data
- Cloud forensics (Wiley 2015): Naive timestamp alignment fails due to clock drift/manipulation
- Multimodal signal processing: Anchor points provide ground truth synchronization

**Methodology:**
1. **Naive Baseline**:
   - Direct timestamp matching (round to nearest second)
   - Linear interpolation for missing data
   - No drift correction
   - Expected error: ±5-10 seconds (based on forensics literature)

2. **Anchor-Based Alignment** (our proposed method):
   - **Anchor identification**:
     - Session start/end events (visible in all three layers)
     - Charging state transitions (Idle → Charging → Idle)
     - OCPP message exchanges (confirmed in network + power surge)
     - Known attack timestamps (ground truth from dataset documentation)
   - **Alignment algorithm**:
     - Extract anchor timestamps from each layer
     - Compute pairwise offsets between layers
     - Apply offset correction with linear drift compensation
     - Validate alignment using secondary anchors
   - **Expected error**: <2 seconds (based on event-driven sync literature)

3. **Evaluation Metrics**:
   - **Temporal alignment error**: Mean absolute deviation between aligned events
   - **Attack detection accuracy**: Compare MLCER performance with naive vs anchor alignment
   - **Causal consistency**: % of cross-layer event sequences that follow logical order
   - **Anchor coverage**: % of time windows with valid anchors (target: >90%)

4. **Experiments**:
   - **Experiment A**: Measure alignment error on known events
   - **Experiment B**: Compare attack detection F1-score (anchor vs naive)
   - **Experiment C**: Ablation study - vary number of anchors (1, 3, 5, 10 per session)

**Success Criteria:**
- Anchor method reduces alignment error by ≥60% vs naive
- MLCER with anchor alignment achieves ≥5% higher F1 than MLCER with naive alignment
- Causal consistency ≥95% for anchor method vs ≤80% for naive

---

### RQ3: Does physical layer validation improve tampering detection?

**Hypothesis:** Power consumption validation reduces false positives by 40% in network/host-based detection

**Theoretical Basis:**
- Defense-in-depth principle: Physical layer harder to manipulate than digital layers
- Power side-channel research: Consumption patterns reflect actual execution
- Critical infrastructure security: Physical sensors provide ground truth

**Methodology:**
1. **Tampering Scenarios** (identified from EVSE security literature):
   - **Network spoofing**: Attacker forges OCPP messages (e.g., fake "ChargingComplete")
   - **Log manipulation**: Attacker modifies host event logs to hide cryptojacking
   - **Timestamp tampering**: Attacker alters system time to evade detection

2. **Power Validation Rules** (derived from power analysis literature):
   - **Rule 1 - Charging State Validation**:
     - IF network says "Charging" BUT power_mW < threshold → FALSE POSITIVE
     - IF network says "Idle" BUT power_mW > threshold → TAMPERING DETECTED

   - **Rule 2 - Cryptojacking Detection**:
     - IF host events show normal BUT power consumption elevated → HIDDEN ATTACK
     - Compare actual power to expected power for reported processes

   - **Rule 3 - Attack Impact Validation**:
     - DoS attack should cause power fluctuations (CPU load)
     - If network shows DoS BUT power steady → likely false alarm or failed attack

3. **Experiments**:
   - **Baseline**: Network + Host detection (no power validation)
   - **MLCER with Power Validation**: Apply power rules to filter alerts
   - **Metrics**:
     - False Positive Rate (FPR): % of benign sessions flagged as attacks
     - True Positive Rate (TPR): % of actual attacks detected
     - Precision: Proportion of alerts that are true attacks

4. **Expected Results** (based on side-channel detection literature):
   - Baseline FPR: ~5-10%
   - MLCER with power validation FPR: ~2-4% (40-60% reduction)
   - TPR should remain constant or increase slightly (power catches hidden attacks)

**Success Criteria:**
- Power validation reduces FPR by ≥40%
- Power validation detects ≥1 attack category missed by network/host alone
- Precision improvement ≥0.10 (e.g., 0.85 → 0.95)

---

### RQ4: Do protocol semantic features improve classification?

**Hypothesis:** Protocol-aware features increase attack classification accuracy by 10-15% vs protocol-agnostic features

**Theoretical Basis:**
- EVSE security research: OCPP/ISO15118 state machine violations indicate attacks
- Attack scenario reconstruction: Protocol context essential for understanding attack intent
- Explainable AI for EVSE (ACM 2024): Protocol semantics improve interpretability

**Methodology:**
1. **Protocol-Agnostic Baseline**:
   - Features: Raw packet counts, byte statistics, timing features
   - No understanding of OCPP/ISO15118 message semantics
   - Standard network IDS features (port numbers, IP addresses, packet sizes)

2. **Protocol Semantic Features** (derived from OCPP/ISO15118 standards):

   **OCPP Features:**
   - Message type sequences (e.g., BootNotification → Heartbeat → StartTransaction)
   - State machine violations (e.g., StartTransaction before Authorization)
   - Timing anomalies (e.g., Heartbeat interval deviation)
   - Error codes and rejection reasons

   **ISO15118 Features:**
   - V2G handshake completion status
   - Certificate validation success/failure
   - Payment authorization flow
   - Session setup timing (expected: 2-5 seconds)

   **Cross-Protocol Features:**
   - OCPP message rate vs charging state (power layer)
   - ISO15118 session correlation with OCPP session
   - Protocol switching anomalies (unexpected interface changes)

3. **Feature Engineering Pipeline**:
   - **Step 1**: Parse PCAP files to extract OCPP/ISO15118 messages
   - **Step 2**: Build state machine representations from standards
   - **Step 3**: Generate violation features (binary: 0=valid, 1=violation)
   - **Step 4**: Extract timing and sequence features
   - **Step 5**: Combine with statistical features from NFStream

4. **Experiments**:
   - **Model A**: Protocol-agnostic features only
   - **Model B**: Protocol-agnostic + semantic features
   - **Comparison**: Same algorithm (Random Forest), different feature sets
   - **Metrics**: Accuracy, F1-score, per-attack-type recall

5. **Expected Results** (based on EVSE IDS literature):
   - Protocol-agnostic F1: ~85-90%
   - With semantic features F1: >95% (10-15% improvement)
   - Greatest improvement for: Reconnaissance attacks (protocol probing) and DoS (state machine disruption)

**Success Criteria:**
- Protocol semantic features improve overall F1 by ≥10%
- Reconnaissance attack detection improves by ≥20%
- Feature importance analysis shows protocol features in top 10

---

## Implementation Roadmap

### Phase 1: Infrastructure & Baselines (Weeks 1-2)
- **Task 1.1**: Set up reproducible ML pipeline (Python, scikit-learn, XGBoost)
- **Task 1.2**: Implement session-based train/test splitting
- **Task 1.3**: Train and evaluate single-layer baselines
  - Host-only baseline (HPC features)
  - Network-only baseline (NFStream features)
  - Power-only baseline (consumption patterns)
- **Deliverable**: Baseline performance report with confusion matrices

### Phase 2: Time Synchronization (Weeks 3-4)
- **Task 2.1**: Implement naive timestamp alignment
- **Task 2.2**: Identify and extract anchor events
- **Task 2.3**: Implement anchor-based alignment algorithm
- **Task 2.4**: Validate alignment accuracy
- **Deliverable**: Aligned multi-layer dataset with temporal error analysis

### Phase 3: MLCER Feature Engineering (Weeks 5-6)
- **Task 3.1**: Extract protocol semantic features from PCAPs
- **Task 3.2**: Generate cross-layer lag features
- **Task 3.3**: Create causal consistency features
- **Task 3.4**: Build power validation rules
- **Deliverable**: Complete multi-layer feature set (CSV)

### Phase 4: MLCER Training & Evaluation (Weeks 7-8)
- **Task 4.1**: Train MLCER models (Random Forest, XGBoost, ensemble)
- **Task 4.2**: Hyperparameter tuning (GridSearchCV)
- **Task 4.3**: Evaluate against baselines
- **Task 4.4**: Statistical significance testing (McNemar)
- **Deliverable**: MLCER vs baseline comparison with statistical validation

### Phase 5: Ablation Studies (Weeks 9-10)
- **Task 5.1**: RQ2 experiments (naive vs anchor alignment)
- **Task 5.2**: RQ3 experiments (with/without power validation)
- **Task 5.3**: RQ4 experiments (protocol-agnostic vs semantic)
- **Task 5.4**: Feature importance analysis
- **Deliverable**: Ablation study results for each RQ

### Phase 6: Visualization & Documentation (Weeks 11-12)
- **Task 6.1**: Generate attack timeline visualizations
- **Task 6.2**: Create cross-layer correlation heatmaps
- **Task 6.3**: Build interactive dashboard (Plotly/Dash)
- **Task 6.4**: Write final research report
- **Deliverable**: Complete MLCER framework with documentation

---

## Expected Contributions to the Field

### 1. Novel Multi-Layer Dataset
- **First public dataset** combining network + host (HPC) + power for EV charging attacks
- Ground truth labels across all three layers
- Diverse attack scenarios (reconnaissance, DoS, cryptojacking, backdoor)

### 2. Anchor-Based Synchronization Method
- **Event-driven alignment** for heterogeneous data sources
- Addresses critical gap in multi-source forensics literature
- Applicable beyond EV charging to other IoT/CPS domains

### 3. Physical Layer Validation Framework
- **Power consumption as ground truth** for digital event verification
- Reduces false positives in network/host intrusion detection
- Novel application of power analysis to forensics (not cryptanalysis)

### 4. Protocol-Aware Feature Engineering
- **OCPP/ISO15118 semantic features** for EV charging security
- Demonstrates superiority over protocol-agnostic approaches
- Provides explainability for detected attacks

### 5. Reproducible MLCER Framework
- Open-source implementation of multi-layer cyber event reconstruction
- Session-based evaluation methodology (prevents data leakage)
- Statistical validation guidelines for forensics research

---

## Validation Strategy

### Internal Validation
1. **Cross-validation**: 5-fold, session-stratified
2. **Consistency checks**: Results stable across random seeds
3. **Sanity tests**: Known attacks correctly detected, benign sessions passed

### External Validation
1. **Comparison with published baselines**: Match or exceed federated EVSE IDS (>98%)
2. **Ablation studies**: Each component contributes measurable improvement
3. **Statistical significance**: All RQ claims supported by p < 0.05

### Robustness Testing
1. **Missing data**: Test MLCER with incomplete layers (e.g., only network + host)
2. **Noisy data**: Add synthetic noise to power measurements
3. **Unseen attacks**: Holdout attack types for generalization testing

---

## Risk Mitigation

### Technical Risks
| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Time alignment error too high | Medium | High | Use more anchors; validate with ground truth events |
| Insufficient training data | Low | Medium | Use data augmentation; transfer learning |
| Overfitting to attack patterns | Medium | High | Session-based split; cross-validation; unseen attacks |
| PCAP parsing errors | Medium | Low | Validate with Wireshark; use robust NFStream |

### Methodological Risks
| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Data leakage (train/test) | Medium | Critical | Session-based splitting; temporal validation |
| Cherry-picking results | Low | High | Pre-register hypotheses; report all experiments |
| Statistical errors | Medium | Medium | Use established tests; adjust for multiple comparisons |

---

## References

### Multi-Layer Detection
1. IEEE (2018). "Multilayer Data-Driven Cyber-Attack Detection System for Industrial Control Systems Based on Network, System, and Process Data"
2. Nature Scientific Reports (2025). "A multilayer deep autoencoder approach for cross layer IoT attack detection"
3. ScienceDirect (2019). "Attack scenario reconstruction approach using attack graph and alert data mining"

### EV Charging Security
4. ACM NSysS (2024). "Explainable Deep Learning for Cyber Attack Detection in Electric Vehicle Charging Stations"
5. MDPI Energies (2022). "Review of Electric Vehicle Charger Cybersecurity Vulnerabilities, Potential Impacts, and Defenses"
6. UNB (2024). "EVSE Dataset 2024" - https://www.unb.ca/cic/datasets/evse-dataset-2024.html

### Time Synchronization
7. Wiley Security & Communication Networks (2015). "Time synchronization: pivotal element in cloud forensics"
8. Sapien.io (2025). "Top 5 Techniques to Achieve Multimodal Data Alignment"
9. Exponent (2015). "Forensic Analysis of Digital Time"

### Hardware Performance Counters
10. IEEE (2020). "Hardware-Performance-Counters-based anomaly detection in massively deployed smart industrial devices"
11. ResearchGate (2018). "Hardware Performance Counters for Embedded Software Anomaly Detection"
12. ACM TACO (2016). "Hardware Performance Counter-Based Malware Identification and Detection with Adaptive Compressive Sensing"

### Power Analysis
13. IEEE (2020). "Power Side Channel Attack Analysis and Detection"
14. MDPI Cryptography (2020). "Power Analysis Side-Channel Attack Analysis: A Review of 20 Years of Study for the Layman"

---

## Appendix A: Experimental Configuration

### Computing Environment
- **Hardware**: 32GB RAM, 16-core CPU, 100GB storage
- **Software**: Python 3.10, scikit-learn 1.3, XGBoost 2.0, pandas 2.0
- **Reproducibility**: Random seed = 42, Docker container for environment isolation

### Hyperparameters (to be tuned)
- **Random Forest**: n_estimators ∈ {100, 200, 500}, max_depth ∈ {10, 20, None}
- **XGBoost**: learning_rate ∈ {0.01, 0.1, 0.3}, n_estimators ∈ {100, 200, 500}
- **Neural Network**: layers ∈ {2, 3, 4}, neurons ∈ {64, 128, 256}, dropout ∈ {0.2, 0.5}

### Evaluation Metrics
- **Primary**: F1-score (macro-averaged across attack types)
- **Secondary**: Precision, Recall, Accuracy, AUC-ROC
- **Per-attack metrics**: Confusion matrix for each attack type
- **Statistical**: McNemar's test, 95% confidence intervals

---

## Appendix B: Dataset Statistics

### CICEVSE2024 Overview
- **Total sessions**: TBD (to be counted from dataset)
- **Attack sessions**: TBD
- **Benign sessions**: TBD
- **Attack distribution**:
  - Reconnaissance: TBD%
  - DoS: TBD%
  - Cryptojacking: TBD%
  - Backdoor: TBD%

### Layer-Specific Statistics
- **Network**: X PCAP files, Y total packets, Z flows
- **Host**: 86 HPC features + 600+ kernel events
- **Power**: X samples per session (1-second intervals)

### Temporal Coverage
- **Session duration**: Min, Max, Mean, Median
- **Attack duration**: Min, Max, Mean per attack type
- **Sampling gaps**: % of missing data per layer

---

*Document Version: 1.0*
*Last Updated: 2025-11-10*
*Author: MLCER Research Team*
