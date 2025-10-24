{
    "Cryptojacking_session3": {
      "start_time": "2024-03-15 10:00:00",
      "propagation_sequence": [
        {"layer": "Network", "event": "SSH_connection", "time_offset": 0},
        {"layer": "Host", "event": "CPU_spike", "time_offset": 5},
        {"layer": "Power", "event": "Power_increase", "time_offset": 10}
      ],
      "total_propagation_time": 10
    }
  }
```

---

### Task 4-4: Protocol-level Semantic Analysis

**목적:** OCPP/ISO15118 프로토콜의 정상 흐름과 비교

**Step 1: 정상 State Machine 정의**
```
ISO15118 Normal Sequence:
State 0 → State 1 (SessionSetup) → State 2 (ServiceDiscovery) → 
State 3 (Authorization) → State 4 (PowerDelivery) → 
State 5 (ChargingLoop) → State 6 (SessionStop)

Timing Constraints:
- State 1 → State 2: < 5초
- State 5 loop: 60초 주기
```

**Step 2: 실제 데이터에서 State Sequence 추출**
```
From network_data:
1. message_type 컬럼에서 각 메시지의 state 추론
2. 시간순으로 정렬
3. State transition sequence 생성
```

**Step 3: Deviation Detection**
```
Anomaly patterns:
- Missing state (예: State 3 건너뛰기 → Authorization bypass?)
- Out-of-order state
- Timing violation (예: State 5 loop가 10초 → 비정상)
- Unexpected state repetition
```

**출력:**
- `protocol_violations.csv`
```
  session_id, violation_type, expected_state, actual_state, 
  timestamp, severity
  DoS_session2, timing_violation, ChargingLoop_60s, ChargingLoop_10s,
  2024-03-15 10:05:30, high
```

---

### Task 4-5: Multi-layer Attack Signature Extraction

**목적:** 각 공격 유형의 다층 특징 프로파일 생성

**Algorithm:**

**Step 1: 시나리오별 Feature Aggregation**
```
For each attack type:
1. 해당 시나리오의 모든 샘플 추출
2. 각 feature의 통계 계산: mean, std, min, max, percentiles

Example for Cryptojacking:
{
  "Host": {
    "cpu_cycles": {"mean": 2.8M, "std": 0.4M, ...},
    "instructions": {"mean": 1.9M, "std": 0.3M, ...}
  },
  "Network": {
    "packet_rate": {"mean": 15, "std": 5, ...}
  },
  "Power": {
    "power_mW": {"mean": 3500, "std": 450, ...}
  }
}
```

**Step 2: Discriminative Feature Selection**
```
목표: 공격 간 구별력이 높은 feature 찾기

Method: ANOVA or Kruskal-Wallis test
- H0: 모든 시나리오에서 feature 분포가 동일
- p-value < 0.05 → 구별력 있음

Ranking by p-value (낮을수록 중요)
```

**Step 3: Signature Definition**
```
Cryptojacking signature:
- High CPU (> 2.5M cycles)
- Sustained high power (> 3000mW for > 60s)
- Low network activity (< 20 packets/min)

DoS signature:
- High network (> 100 packets/min)
- High CPU (syscall intensive)
- Fluctuating power

Reconnaissance signature:
- Sporadic network spikes
- Low CPU baseline with periodic increases
- Power mostly normal
```

**출력:**
- `attack_signatures.json`
- 각 공격 유형의 multi-layer 프로파일

---

### Stage 4 최종 산출물

**Deliverables:**
1. `multilayer_features.csv`
2. `causal_lag_analysis.csv`
3. `granger_causality_results.csv`
4. `attack_propagation_paths.json`
5. `protocol_violations.csv`
6. `attack_signatures.json`
7. `figures/`
   - `propagation_timeline.png` (공격 전파 시각화)
   - `correlation_heatmap.png`
   - `causal_network_graph.png` (계층 간 인과 관계를 네트워크 그래프로)

**검증 기준:**
- [ ] 인과관계가 물리적으로 타당한가? (예: CPU → Power는 OK, Power → Network는 이상)
- [ ] 각 공격 유형의 signature가 구별 가능한가?
- [ ] Protocol violation이 실제 공격과 연관되는가?

---

## Stage 5: Baseline Comparison (베이스라인 비교)

### 목표
MLCER(Multi-layer) 방법이 단일 계층 방법보다 우수함을 정량적으로 입증합니다.

### Task 5-1: Baseline Methods 구현

**Method A: Host-only (HPC Anomaly Detection)**

**Algorithm:**
```
1. Training: Benign 데이터로 정상 범위 학습
   - 각 HPC feature의 mean, std 계산
   - Threshold = mean ± 3*std
2. Testing: 테스트 샘플이 threshold 벗어나면 anomaly
3. Classification: Anomaly → Attack, Normal → Benign
```

**Method B: Network-only (Traffic Pattern Analysis)**

**Algorithm:**
```
1. Feature extraction: packet_rate, protocol distribution
2. Machine Learning:
   - Train classifier (Random Forest, SVM, etc.)
   - Input: network features only
   - Output: 4-class (Benign/Crypto/DoS/Recon)
```

**Method C: Power-only (Consumption Pattern Matching)**

**Algorithm:**
```
1. Feature extraction: mean_power, std_power, power_trend
2. Similar ML approach as Method B
```

**Method D: MLCER (Proposed)**

**Algorithm:**
```
1. Feature extraction: multilayer_features.csv (from Stage 4)
2. Machine Learning:
   - Input: Host + Network + Power features
   - Plus: causal relationship features
   - Plus: protocol violation flags
   - Output: 4-class classification
```

---

### Task 5-2: 데이터 분할

**Train-Test Split:**
```
Strategy: Session-based split (not random)
이유: 동일 세션의 데이터가 train/test에 섞이면 data leakage

Procedure:
1. 모든 세션 리스트 추출
2. 세션을 7:3 비율로 train/test 분할
3. 시나리오별 비율 유지 (stratified)

Example:
Train sessions: 70% of Benign, 70% of Crypto, ...
Test sessions: 30% of Benign, 30% of Crypto, ...
```

**출력:**
- `train_sessions.txt`
- `test_sessions.txt`

---

### Task 5-3: Model Training

**각 Method별로:**

**Step 1: Feature Preparation**
```
Method A (Host-only):
- Features: 86 HPC features
- Samples: host_timeline_aligned.csv의 train sessions

Method D (MLCER):
- Features: multilayer_features.csv의 모든 컬럼
- Plus: lag features, protocol flags
- Samples: train sessions
```

**Step 2: 모델 선택 및 하이퍼파라미터 튜닝**
```
권장 모델:
- Random Forest (해석 가능, 성능 좋음)
- XGBoost (최고 성능)
- SVM (baseline)

Hyperparameter tuning:
- Grid search with cross-validation (5-fold)
- Metrics: F1-score (macro average)
```

**Step 3: 학습**
```
For each method:
model.fit(X_train, y_train)
```

**출력:**
- `models/`
  - `model_host_only.pkl`
  - `model_network_only.pkl`
  - `model_power_only.pkl`
  - `model_mlcer.pkl`

---

### Task 5-4: Evaluation on Test Set

**Metrics to Calculate:**

**1. Classification Accuracy**
```
Overall Accuracy = (TP + TN) / Total
Per-class Accuracy for each of 4 scenarios
```

**2. Precision, Recall, F1-score**
```
For each scenario:
Precision = TP / (TP + FP)
Recall = TP / (TP + FN)
F1 = 2 * (Precision * Recall) / (Precision + Recall)

Macro-average (모든 클래스 평균)
Weighted-average (클래스 비율 고려)
```

**3. Confusion Matrix**
```
4x4 matrix:
Rows = True label
Cols = Predicted label

Example:
              Pred_Benign  Pred_Crypto  Pred_DoS  Pred_Recon
True_Benign        450          20         10         5
True_Crypto         15         380         25        15
...
```

**4. ROC-AUC (Binary 문제로 변환)**
```
Benign vs Attack (3개 공격 통합)
각 공격 유형 vs Rest
```

---

### Task 5-5: Statistical Significance Testing

**목적:** MLCER이 통계적으로 유의미하게 더 좋은지 검증

**Method: McNemar's Test**

**Procedure:**
```
1. Method A와 Method D의 예측 결과 비교
2. 2x2 contingency table 생성:
   
            D_correct  D_wrong
   A_correct     a         b
   A_wrong       c         d

3. McNemar statistic = (b - c)^2 / (b + c)
4. p-value < 0.05 → 유의미한 차이
```

**모든 조합에 대해 반복:**
- A vs D
- B vs D
- C vs D

**출력:**
- `statistical_tests.csv`
```
  method_1, method_2, mcnemar_stat, p_value, significant
  Host-only, MLCER, 25.3, 0.0001, True
  ...
```

---

### Task 5-6: Ablation Study

**목적:** MLCER의 어떤 구성 요소가 성능에 기여하는지 분석

**실험 설계:**
```
MLCER_full: All features (Host + Network + Power + Causal + Protocol)
MLCER_no_causal: Without causal lag features
MLCER_no_protocol: Without protocol violation flags
MLCER_no_power: Without Power features (= Host + Network)
...
```

**각 변형에 대해:**
1. 모델 재학습
2. 성능 측정
3. MLCER_full과 비교

**출력:**
- `ablation_study_results.csv`
```
  configuration, accuracy, f1_macro, delta_from_full
  MLCER_full, 0.94, 0.93, 0.00
  MLCER_no_causal, 0.91, 0.90, -0.03
  MLCER_no_protocol, 0.92, 0.91, -0.02
  ...
```

**Interpretation:**
- Delta가 큰 구성 요소 = 중요한 기여
- 논문에서 각 요소의 중요성 주장 근거

---

### Task 5-7: Error Analysis

**목적:** MLCER이 여전히 실패하는 케이스 분석

**Procedure:**

**Step 1: False Negative Analysis**
```
실제 공격인데 Benign으로 오분류된 케이스:
1. 해당 샘플들의 feature 값 확인
2. 공통 패턴 찾기
   예: 공격 초기 단계라 신호가 약함
       또는 매우 정교한 공격으로 정상과 유사
```

**Step 2: False Positive Analysis**
```
Benign인데 공격으로 오분류:
1. 어떤 feature가 threshold 넘었는지
2. 정상 동작 중 특이 케이스인지
   예: 펌웨어 업데이트 중 CPU 급증 → Cryptojacking으로 오인
```

**Step 3: Inter-class Confusion**
```
Cryptojacking과 DoS를 혼동한 케이스:
- 두 공격의 유사점 분석
- 구별을 위한 추가 feature 제안
```

**출력:**
- `error_analysis_report.txt`
- 각 오류 유형별 사례와 원인 분석

---

### Stage 5 최종 산출물

**Deliverables:**
1. `models/` (학습된 모델 파일들)
2. `train_test_split/`
   - `train_sessions.txt`
   - `test_sessions.txt`
3. `evaluation_results.csv`
```
   method, accuracy, precision_macro, recall_macro, f1_macro, roc_auc
   Host-only, 0.78, 0.75, 0.76, 0.75, 0.82
   Network-only, 0.82, 0.80, 0.81, 0.80, 0.85
   Power-only, 0.75, 0.73, 0.74, 0.73, 0.79
   MLCER, 0.94, 0.93, 0.93, 0.93, 0.97
```
4. `confusion_matrices/` (각 method별)
5. `statistical_tests.csv`
6. `ablation_study_results.csv`
7. `error_analysis_report.txt`

**검증 기준:**
- [ ] MLCER이 모든 단일 계층 방법보다 높은 성능인가?
- [ ] 통계적으로 유의미한 차이인가? (p < 0.05)
- [ ] F1-score 개선이 10% 이상인가?

---

## Stage 6: Evaluation & Visualization (최종 평가 및 시각화)

### 목표
연구 결과를 논문에 사용할 수 있는 publication-quality 그래프와 표로 정리합니다.

### Task 6-1: Performance Comparison Visualization

**Figure 1: Bar Chart - Overall Performance**
```
X축: Methods (Host-only, Network-only, Power-only, MLCER)
Y축: Metrics (Accuracy, Precision, Recall, F1)
4개의 grouped bar chart
Color-coded, with error bars if cross-validation used
```

**Figure 2: Radar Chart - Multi-dimensional Performance**
```
각 축: 하나의 metric
각 method를 다른 색 선으로 표시
MLCER이 가장 바깥쪽 (우수)임을 보임
```

**Figure 3: Confusion Matrix Heatmap**
```
4개 subplot (각 method별)
색상: 진한 대각선 = 좋은 성능
MLCER의 대각선이 가장 진함을 강조
```

---

### Task 6-2: Time Alignment Effectiveness

**Figure 4: Before/After Alignment**
```
2개 subplot:
Top: Naive alignment (각 계층의 t=0 정렬)
  → 세 계층의 이벤트가 시간적으로 뒤섞임

Bottom: Anchor-based alignment
  → 세 계층의 이벤트가 시간적으로 일치

시각적으로 dramatic한 차이 보이기
```

**Figure 5: Alignment Error Distribution**
```
Histogram:
X축: Alignment error (초)
Y축: Frequency

Before anchoring: 넓게 분포 (0~100초)
After anchoring: 좁게 분포 (0~5초)
```

---

### Task 6-3: Attack Propagation Visualization

**Figure 6: Propagation Timeline**
```
공격 사례 하나를 선정 (예: Cryptojacking_session5)

X축: Time (seconds from attack start)
Y축: 3개 계층 (Network, Host, Power)

각 계층에서 anomaly 발생 시점을 marker로 표시
Arrows로 인과관계 연결

Legend:
- 시간축에 phase 표시 (Initial, Propagation, Sustained)
```

**Figure 7: Sankey Diagram - Attack Flow**
```
Left: Network anomalies
Middle: Host anomalies
Right: Power anomalies

선의 두께 = 빈도
공격이 어떤 경로로 전파되는지 시각화
```

---

### Task 6-4: Feature Importance Analysis

**Figure 8: Feature Importance (MLCER model)**
```
Bar chart:
X축: Top 20 important features
Y축: Importance score (from Random Forest or SHAP)

Color-code by layer:
- Blue: Host features
- Green: Network features
- Red: Power features
- Purple: Derived/causal features

논문의 주장: 다층 feature가 모두 기여함을 보임
```

---

### Task 6-5: Case Study Visualization

**공격 시나리오 하나를 심층 분석:**

**Case Study: Cryptojacking Attack Reconstruction**

**Figure 9: Multi-panel Timeline**
```
4개 subplot (시간 동기화):
Panel A: Network traffic (packet rate over time)
Panel B: Host CPU cycles over time
Panel C: Power consumption over time
Panel D: MLCER anomaly score over time

모든 panel에 동일한 X축 (시간)
세로 점선으로 주요 이벤트 시점 표시:
- T1: SSH 접속
- T2: 프로세스 생성
- T3: CPU 급증
- T4: 전력 증가
```

**Figure 10: Protocol State Transition**
```
State machine diagram:
정상 흐름 (점선)
실제 관찰된 흐름 (실선)
Violation 지점을 빨간색으로 강조
```

---

### Task 6-6: Summary Tables

**Table 1: Dataset Statistics**
```
| Layer   | Scenario       | Sessions | Records | Duration (h) | Sampling Rate |
|---------|----------------|----------|---------|--------------|---------------|
| Host    | Benign         | 5        | 2300    | 4.0          | ~5s           |
| Host    | Cryptojacking  | 4        | 1791    | 1.1          | ~5s           |
| ...     | ...            | ...      | ...     | ...          | ...           |
```

**Table 2: Performance Comparison**
```
| Method       | Accuracy | Precision | Recall | F1-score | Improvement over Best Single-layer |
|--------------|----------|-----------|--------|----------|------------------------------------|
| Host-only    | 0.78     | 0.75      | 0.76   | 0.75     | -                                  |
| Network-only | 0.82     | 0.80      | 0.81   | 0.80     | -                                  |
| Power-only   | 0.75     | 0.73      | 0.74   | 0.73     | -                                  |
| MLCER (Ours) | 0.94     | 0.93      | 0.93   | 0.93     | +14.6%                             |
```

**Table 3: Ablation Study**
```
| Configuration         | Accuracy | Delta | Contribution |
|-----------------------|----------|-------|--------------|
| MLCER (Full)          | 0.94     | -     | -            |
| - Causal features     | 0.91     | -0.03 | 3%           |
| - Protocol features   | 0.92     | -0.02 | 2%           |
| - Power features      | 0.87     | -0.07 | 7%           |
| - Network features    | 0.85     | -0.09 | 9%           |
```

---

### Task 6-7: Research Questions 답변 정리

**RQ1: MLCER이 단일 계층 방법보다 재구성 정확도가 높은가?**
```
Answer: Yes.
Evidence:
- F1-score: MLCER 0.93 vs Best single-layer 0.80 (+16.3%)
- Statistical test: p < 0.001 (highly significant)
- Figure X shows consistent superiority across all metrics
```

**RQ2: Time Anchor 기반 정렬이 naive 정렬보다 우수한가?**
```
Answer: Yes.
Evidence:
- Alignment error reduced from 45.2s to 1.8s (96% reduction)
- Cross-layer correlation improved from 0.12 to 0.78
- Figure Y demonstrates clear visual improvement
```

**RQ3: 물리 계층 검증이 변조 탐지에 효과적인가?**
```
Answer: Yes.
Evidence:
- Tampering detection rate: 89% (vs 35% without physical validation)
- False alarm rate: 4% (vs 15%)
- Case study in Section Z shows concrete example
```

**RQ4: 프로토콜 의미론 분석이 공격 분류를 개선하는가?**
```
Answer: Yes.
Evidence:
- Adding protocol features improved F1 from 0.91 to 0.93 (+2%)
- DoS detection improved most significantly (F1: 0.85 → 0.92)
- Table W shows protocol violations strongly correlate with attacks
```

---

### Stage 6 최종 산출물

**Deliverables:**
1. `figures/publication_quality/`
   - All figures in high-resolution PNG and vector PDF
   - Figure numbers and captions in separate file
2. `tables/`
   - All tables in LaTeX format
   - Also in CSV for reference
3. `research_questions_answers.txt`
   - 각 RQ에 대한 명확한 답변
   - Supporting evidence 나열
4. **Final Report: `MLCER_Experimental_Results_Report.pdf`**
   - Executive summary
   - All figures and tables
   - Interpretation and discussion
   - Limitations and future work

---

## 전체 실험 체크리스트

### Phase 1: Data Understanding ✅
- [ ] 파일 구조 완전히 파악
- [ ] 타임스탬프 형식 확인
- [ ] 시나리오 분포 확인
- [ ] 데이터 품질 검증
- [ ] 시간 동기화 문제 확인

### Phase 2: Preprocessing ✅
- [ ] 모든 계층 데이터 로딩 성공
- [ ] 타임스탬프 정규화 완료
- [ ] 세션 분리 완료
- [ ] 결측치/이상치 처리
- [ ] EDA 완료

### Phase 3: Time Anchors ✅
- [ ] Network anchors 추출
- [ ] Power anchors 추출
- [ ] Host anchors 추출
- [ ] Anchor matching 완료
- [ ] Validation passed

### Phase 4: Timeline Integration ✅
- [ ] 각 계층 타임라인 정렬
- [ ] Unified timeline 생성
- [ ] Alignment error < 2초
- [ ] Quality metrics 계산

### Phase 5: Cross-layer Analysis ✅
- [ ] Multi-layer features 생성
- [ ] 인과관계 분석 완료
- [ ] 공격 전파 경로 재구성
- [ ] Protocol 분석 완료
- [ ] Attack signatures 추출

### Phase 6: Baseline Comparison ✅
- [ ] 4개 method 모두 구현
- [ ] Train/test split 완료
- [ ] 모든 모델 학습 완료
- [ ] 성능 평가 완료
- [ ] 통계 검정 완료
- [ ] Ablation study 완료

### Phase 7: Results & Visualization ✅
- [ ] 모든 figure 생성
- [ ] 모든 table 생성
- [ ] RQ 답변 정리
- [ ] Final report 작성

---

## 예상 실행 시간 및 리소스

**Stage 0-1:** 2-4시간 (데이터 탐색)
**Stage 2:** 4-6시간 (전처리)
**Stage 3:** 6-10시간 (Anchor 추출, 복잡함)
**Stage 4:** 4-6시간 (타임라인 통합)
**Stage 5:** 8-12시간 (상관분석, 계산 집약적)
**Stage 6:** 6-10시간 (모델 학습 및 평가)
**Stage 7:** 4-6시간 (시각화 및 보고서)

**총 예상 시간:** 34-54시간

**컴퓨팅 리소스:**
- RAM: 최소 16GB (32GB 권장)
- CPU: 멀티코어 (8+ cores 권장)
- Storage: 50GB 여유 공간

---

## 중요한 구현 원칙

### 원칙 1: 재현 가능성 (Reproducibility)
```
- Random seed 고정
- 모든 parameter 기록
- 버전 관리 (pandas, sklearn, etc.)
- 실행 환경 기록 (requirements.txt)
```

### 원칙 2: 검증 가능성 (Verifiability)
```
- 중간 결과물 모두 저장
- 각 stage별 sanity check
- Assertion 사용 (예: assert alignment_error < 5)
```

### 원칙 3: 모듈화 (Modularity)
```
- 각 stage를 독립 스크립트로
- 입력/출력 명확히 정의
- 하나의 stage 실패해도 다음 진행 가능 (saved checkpoints)
```

### 원칙 4: 문서화 (Documentation)
```
- 각 함수에 docstring
- README에 실행 방법
- Config 파일로 파라미터 관리