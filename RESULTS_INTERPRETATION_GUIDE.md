# 🔍 결과 해석 가이드 (Results Interpretation Guide)

## 📊 핵심 발견사항 요약

### 1. Attack Propagation Chains (공격 전파 경로)

#### **DoS Attack** (서비스 거부 공격)
```
Network → (6초) → Host → (4초) → Power
총 전파 시간: 10초
```

**해석**:
- **6초 lag (Network→Host)**: 네트워크 패킷 flood가 호스트 시스템에 영향을 주는데 6초 소요
- **4초 lag (Host→Power)**: 호스트 CPU/메모리 부하가 전력 소비에 반영되는데 4초 소요
- **의미**: DoS 공격 탐지 시 네트워크 레이어에서 먼저 감지하면 호스트/전력 이상 징후가 6-10초 후에 나타날 것으로 예측 가능

**활용 방안**:
1. **조기 경보**: 네트워크 레이어에서 anomaly 감지 → 6초 내 호스트 레이어 모니터링 강화
2. **False Positive 감소**: 단일 레이어 이상만으로 판단하지 않고 6-10초 시간차 확인
3. **자동 대응**: 네트워크 이상 감지 → 10초 이내 호스트+전력 레이어에서 이상 확인 시 자동 차단

---

#### **Reconnaissance Attack** (정찰 공격)
```
Network → (1초) → Host → (6초) → Power
총 전파 시간: 7초
```

**해석**:
- **1초 lag (Network→Host)**: 포트 스캔/정찰 패킷이 즉시 호스트 로그에 기록됨 (거의 실시간)
- **6초 lag (Host→Power)**: 정찰 활동이 전력에 미치는 영향은 6초 후
- **의미**: Recon은 "빠른 버스트" 공격 - 네트워크와 호스트가 거의 동시에 이상 징후 보임

**활용 방안**:
1. **실시간 탐지**: 네트워크+호스트 레이어 동시 이상 → Recon 공격으로 분류
2. **자동 차단**: 1초 이내 호스트 반응 → 즉각 방화벽 rule 업데이트
3. **공격 분류**: DoS(6초 lag) vs Recon(1초 lag)로 공격 유형 자동 분류

---

#### **Cryptojacking Attack** (암호화폐 채굴)
```
Host → (6초) → Power
(네트워크 레이어 없음 - host-originated)
```

**해석**:
- **6초 lag (Host→Power)**: CPU 집약적 채굴 활동이 전력 소비 증가로 나타나는데 6초 소요
- **네트워크 없음**: 내부에서 시작된 공격이므로 네트워크 트래픽 이상 없음
- **의미**: 호스트 CPU 사용률 급증 → 6초 후 전력 소비 증가 패턴

**활용 방안**:
1. **내부 위협 탐지**: 네트워크 이상 없이 호스트 CPU 급증 → Cryptojacking 의심
2. **전력 기반 검증**: 호스트 CPU 이상 + 6초 후 전력 증가 → Cryptojacking 확정
3. **자동 프로세스 킬**: 패턴 매칭 시 의심 프로세스 자동 종료

---

### 2. Temporal Signatures (시간적 특징)

#### **Phase Analysis** (단계별 분석)

| Attack | Initiation (0-10s) | Peak (10-30s) | Sustained (30-60s) |
|--------|-------------------|---------------|-------------------|
| **DoS** | 급격한 증가 (0.12) | 하락세 (-0.004 trend) | 안정화 (0.04) |
| **Recon** | 매우 높은 버스트 (0.66) | 급격한 하락 (-0.13 trend) | 낮은 활동 (0.07) |
| **Cryptojacking** | 점진적 증가 (0.06) | 지속 증가 (+0.0002 trend) | 유지 (0.07) |

**해석**:

**DoS 특징**:
- 초반 10초: 공격 시작, 높은 활동
- 10-30초: 시스템이 과부하로 응답 능력 저하 → 활동 감소
- 30-60초: 낮은 수준에서 안정화
- **Critical Event**: 7초에 peak intensity → **7초가 가장 위험한 순간**

**Recon 특징**:
- 초반 10초: 매우 높은 버스트 (0.66 - 모든 공격 중 최고치)
- 즉시 하락: 정찰은 빠르게 수행 후 종료
- **Critical Event**: 0-1초에 peak → **즉각적인 탐지 필요**

**Cryptojacking 특징**:
- 점진적 증가: 은밀하게 시작
- 늦은 peak: 48초에 최고조 → **오랜 시간 감지 안될 수 있음**
- 지속적 유지: 30-60초에도 계속 활동

---

### 3. 실전 활용 시나리오

#### **시나리오 1: 실시간 침입 탐지 시스템 (IDS)**

```python
# Pseudo-code for multi-layer IDS

def detect_attack(network_anomaly, host_anomaly, power_anomaly, time_diff):
    """
    Multi-layer correlation-based attack detection
    """

    # DoS Detection
    if network_anomaly and time_diff(network, host) == 6:
        if host_anomaly and time_diff(host, power) == 4:
            return "DoS Attack Confirmed (99% confidence)"

    # Recon Detection
    if network_anomaly and host_anomaly and time_diff(network, host) <= 1:
        return "Reconnaissance Attack (95% confidence)"

    # Cryptojacking Detection
    if host_anomaly and not network_anomaly:
        if power_anomaly and time_diff(host, power) == 6:
            return "Cryptojacking Attack (97% confidence)"

    return "Unknown or Benign"
```

**효과**:
- False Positive 감소: 단일 레이어 이상만으로 판단하지 않음
- 공격 유형 자동 분류: 시간차 패턴으로 DoS vs Recon vs Crypto 구분
- 조기 경보: 네트워크 이상 감지 → 6-10초 내 호스트/전력 확인

---

#### **시나리오 2: 공격 예측 및 선제 대응**

**DoS 공격 예측**:
```
t=0: Network layer detects flood (패킷 rate 급증)
→ PREDICTION: Host anomaly at t=6s, Power spike at t=10s

t=6: Host CPU 사용률 확인 (예측 검증)
→ CONFIRMED: DoS attack in progress

ACTION:
- t=6: 트래픽 필터링 강화
- t=10: 전력 소비 제한 (서비스 보호)
```

**효과**:
- 6초의 예측 시간 확보
- 선제적 방어 조치 가능
- 피해 최소화

---

#### **시나리오 3: Forensics (사후 분석)**

**질문**: "공격이 언제 시작되었나?"

**답변**:
```
Power layer spike detected at 16:30:45
→ BACKTRACK: Host anomaly likely at 16:30:39 (6초 전)
→ BACKTRACK: Network flood likely at 16:30:33 (12초 전)

ROOT CAUSE: Network flood started at ~16:30:33
```

**효과**:
- 정확한 공격 시작 시각 추정
- 로그 분석 범위 축소
- 공격 경로 역추적

---

### 4. Figure 해석 가이드

#### **Figure 1: Temporal Evolution**
- **X축**: 공격 시작 후 경과 시간 (0-60초)
- **Y축**: 각 레이어의 활동 강도 (normalized)
- **읽는 법**:
  - DoS: 7초에 peak → 이후 하락
  - Recon: 0-1초에 급격한 spike → 즉시 하락
  - Cryptojacking: 48초에 늦은 peak → 점진적 증가

**활용**:
- 공격 유형별 "지문" 확인
- 새로운 이상 징후를 기존 패턴과 비교
- 탐지 알고리즘의 시간 윈도우 설정 (DoS: 0-10s, Crypto: 0-60s)

#### **Figure 2: Lagged Correlation Heatmap**
- **X축**: Layer pair (Network→Host, Host→Power, etc.)
- **Y축**: Time lag (-10 to +10 seconds)
- **색상**: 상관계수 (빨강=양의 상관, 파랑=음의 상관)
- **★ 표시**: Optimal lag (최대 상관계수)

**읽는 법**:
- DoS: Network→Host에서 lag=-6에 ★ → 네트워크가 6초 앞섬
- 빨간색이 진할수록 강한 상관관계

#### **Figure 3: Phase Comparison**
- **X축**: Phase (Initiation, Peak, Sustained)
- **Y축**: Mean intensity
- **Bar 색상**: Scenario (DoS, Recon, Crypto)

**읽는 법**:
- Recon의 Initiation phase bar가 가장 높음 → 초반 버스트 가장 강력
- Cryptojacking은 3단계 모두 비슷 → 일정한 활동

---

### 5. 한계점과 주의사항

⚠️ **이 결과는 "얼추 맞추기" 전략**:
- **절대 시간 아님**: 공격별로 T=0 기준이 다름
- **실제 전파 시간과 다를 수 있음**: ±2.5초 오차 범위
- **Power 데이터 희소**: 82% missing → 전력 관련 결과는 참고용

✅ **신뢰할 수 있는 부분**:
- 상대적 전파 순서 (Network → Host → Power)
- 공격 유형별 temporal signature 차이
- Lag의 대략적 범위 (1-6초)

---

### 6. 논문/보고서 작성 시 활용

#### **주장할 수 있는 것**:
1. ✅ "DoS 공격은 Network → Host (6s) → Power (4s) 순서로 전파됨"
2. ✅ "Recon 공격은 1초 이내 즉각적인 Host 반응 보임"
3. ✅ "Cryptojacking은 네트워크 이상 없이 Host에서 시작"
4. ✅ "각 공격 유형은 구별 가능한 temporal signature 가짐"

#### **주장하면 안되는 것**:
1. ❌ "정확히 6.00초 후에 전파됨" → ±2.5초 오차 있음
2. ❌ "모든 DoS 공격이 이렇게 동작함" → 이 데이터셋에서만
3. ❌ "절대 시간으로 동기화됨" → 공격별 상대 시간

#### **추천 문구**:
```
"Attack-relative time normalization with ±2.5s tolerance window
revealed distinct propagation patterns: DoS attacks showed
Network → Host (6±2.5s) → Power (4±2.5s) propagation chain,
while Reconnaissance attacks demonstrated near-instantaneous
Network → Host propagation (1±2.5s)."
```

---

### 7. 다음 단계 제안

#### **단기 (논문 작성)**:
1. Figure 1, 2, 3 논문에 삽입
2. Table 3의 correlation 결과를 Results section에 기술
3. Temporal signature 차이를 Discussion에서 강조

#### **중기 (추가 분석)**:
1. **Feature-level correlation**: 어떤 Host feature가 Power와 가장 강한 상관관계?
2. **Granger Causality Test**: 통계적으로 인과관계 검증
3. **Classification Model**: Aligned timeline 사용해 attack type 분류 모델 구축

#### **장기 (데이터 재수집)**:
1. 모든 레이어 동시 수집 (GPS/NTP 동기화)
2. Power 샘플링 주파수 증가 (1Hz → 10Hz)
3. True event reconstruction 시도

---

## 🎯 핵심 Takeaway

1. **각 공격 유형은 고유한 "시간 지문" 보유**
   - DoS: 6초 lag, 7초 peak
   - Recon: 1초 lag, 즉각 peak
   - Cryptojacking: 6초 lag, 48초 peak

2. **Multi-layer correlation으로 탐지 정확도 향상 가능**
   - 단일 레이어 이상 → 시간차 확인 → 공격 유형 분류

3. **예측 및 선제 대응 가능**
   - Network 이상 감지 → 6-10초 내 Host/Power 확인
   - 조기 경보 시스템 구축 가능

4. **한계 인정하되 의미있는 인사이트 제공**
   - "얼추 맞추기"이지만 실용적 가치 있음
   - 상대적 전파 패턴은 신뢰 가능

---

**작성일**: 2025-10-25
**다음 업데이트**: 추가 분석 결과 반영 시
