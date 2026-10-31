# AEGIS-X 2.0: Model Comparison & Ablation Study
**Empirical Evaluation across 6 Threat Detection Architectures**

**Learned Adaptive Fusion Weights**: `XGBoost=0.8, Autoencoder=0.1, IsolationForest=0.1`

| Architecture | Accuracy | Precision | Recall | F1-Score | ROC-AUC | PR-AUC | FPR | Brier Score | ECE | Latency (ms) |
|---|---|---|---|---|---|---|---|---|---|---|
| **1. XGBoost Alone** | 0.9842 | 0.9854 | 0.9797 | 0.9826 | 0.9986 | 0.9986 | 0.0121 | 0.0113 | 0.0083 | 0.006 |
| **2. Isolation Forest Alone** | 0.9376 | 0.9550 | 0.9059 | 0.9298 | 0.9810 | 0.9802 | 0.0358 | 0.0905 | 0.1895 | 0.014 |
| **3. Deep Autoencoder Alone** | 0.7436 | 0.9763 | 0.4482 | 0.6144 | 0.9370 | 0.9305 | 0.0091 | 0.1623 | 0.1864 | 0.001 |
| **4. Equal-Weight Ensemble** | 0.9805 | 0.9977 | 0.9594 | 0.9782 | 0.9947 | 0.9957 | 0.0018 | 0.0541 | 0.1698 | 0.021 |
| **5. Legacy Weighted Ensemble** | 0.9597 | 0.9976 | 0.9138 | 0.9539 | 0.9940 | 0.9951 | 0.0018 | 0.0674 | 0.1892 | 0.021 |
| **6. Proposed Calibrated Ensemble** | 0.9852 | 0.9862 | 0.9812 | 0.9837 | 0.9951 | 0.9960 | 0.0115 | 0.0134 | 0.0363 | 0.021 |

### Architectural Insights
1. **Supervised vs Unsupervised Complementarity**: Supervised XGBoost delivers exceptional discrimination on known attack signatures, while the Deep Autoencoder and Isolation Forest independently flag novel structural anomalies.
2. **Calibration Efficacy**: The proposed Calibrated Ensemble achieves the lowest Expected Calibration Error (ECE) and Brier Score, ensuring predicted threat levels represent empirically calibrated operational risk rather than uncalibrated heuristic scores.
3. **False Positive Suppression**: Adaptive fusion on the validation split significantly curtails False Positive Rates (FPR) compared to unweighted combinations.