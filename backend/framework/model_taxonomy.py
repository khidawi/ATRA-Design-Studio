"""
ST-AI Framework v3 — Model Taxonomy
Hierarchical classification used by the registration UI.
Drives the two-step model selection (category → specific type)
and maps every specific type to the canonical ModelTypeEnum.
"""
from framework.enums import ModelTypeEnum

# ── Category → list of (label, ModelTypeEnum) ─────────────────────────────
MODEL_TAXONOMY = {
    "Discriminative": [
        ("CNN / Image Classifier",             ModelTypeEnum.CNN),
        ("Feedforward NN (MLP)",               ModelTypeEnum.NN),
        ("RNN / LSTM / GRU",                   ModelTypeEnum.NN),
        ("Transformer — Discriminative (BERT, ViT)", ModelTypeEnum.NN),
        ("Graph Neural Network (GNN)",         ModelTypeEnum.NN),
        ("Tabular ML — XGBoost / Random Forest / LightGBM", ModelTypeEnum.NN),
        ("Support Vector Machine (SVM)",       ModelTypeEnum.NN),
        ("Decision Tree",                      ModelTypeEnum.NN),
        ("Random Forest",                      ModelTypeEnum.ENSEMBLE),
        ("Gradient Boosting (XGBoost, LightGBM)", ModelTypeEnum.NN),
        ("Logistic Regression",                ModelTypeEnum.NN),
        ("Naive Bayes",                        ModelTypeEnum.NN),
        ("Linear Regression",                  ModelTypeEnum.NN),
        ("K-Nearest Neighbours (KNN)",         ModelTypeEnum.NN),
        ("Recommendation System",              ModelTypeEnum.NN),
        ("Anomaly Detection (isolation forest, autoencoder)", ModelTypeEnum.NN),
        ("Physics-Informed Neural Network (PINN)", ModelTypeEnum.PINN),
        ("Federated Learning Model",           ModelTypeEnum.NN),
    ],
    "Generative": [
        ("Large Language Model (LLM)",         ModelTypeEnum.LLM),
        ("Retrieval-Augmented Generation (RAG)", ModelTypeEnum.LLM),
        ("Text-to-Code (Copilot, CodeLlama)", ModelTypeEnum.LLM),
        ("Multimodal Generative (GPT-4V, Gemini)", ModelTypeEnum.LLM),
        ("Generative Adversarial Network (GAN)", ModelTypeEnum.NN),
        ("Variational Autoencoder (VAE)",      ModelTypeEnum.NN),
        ("Diffusion Model (Stable Diffusion, DALL-E)", ModelTypeEnum.NN),
    ],
    "Reinforcement Learning": [
        ("Standard RL Agent (DQN, PPO, SAC)", ModelTypeEnum.RL),
        ("Multi-Agent RL (MARL)",              ModelTypeEnum.RL),
        ("Inverse RL / Imitation Learning",   ModelTypeEnum.RL),
        ("Model-Based RL",                     ModelTypeEnum.RL),
        ("Offline RL / Batch RL",             ModelTypeEnum.RL),
        ("RLHF (RL from Human Feedback)",     ModelTypeEnum.RL),
    ],
    "Hybrid / Ensemble": [
        ("Ensemble (voting, stacking, boosting)", ModelTypeEnum.ENSEMBLE),
        ("Hybrid (mixed architecture)",        ModelTypeEnum.HYBRID),
        ("Bayesian Network",                   ModelTypeEnum.NN),
        ("Fuzzy Logic System",                 ModelTypeEnum.NN),
        ("Expert System / Rule-Based",         ModelTypeEnum.NN),
        ("Optimisation Algorithm (GA, LP)",   ModelTypeEnum.NN),
    ],
}

CATEGORIES = list(MODEL_TAXONOMY.keys())

def get_model_labels(category: str) -> list:
    """Return list of display labels for a given category."""
    return [label for label, _ in MODEL_TAXONOMY.get(category, [])]

def get_model_enum(category: str, label: str) -> ModelTypeEnum:
    """Map a category + label to the canonical ModelTypeEnum."""
    for lbl, enum_val in MODEL_TAXONOMY.get(category, []):
        if lbl == label:
            return enum_val
    return ModelTypeEnum.NN


# ── Model-specific inherent risk descriptions ──────────────────────────────
# Shown in the architecture map narrative and PCS explanation
MODEL_RISK_PROFILE = {
    "Large Language Model (LLM)": {
        "risk": "Hallucination as normal failure mode — confident, fluent, factually wrong output indistinguishable from correct output",
        "attacks": ["Prompt injection", "Jailbreaking", "Indirect prompt injection via documents", "Training data extraction"],
        "silent_failure": "Compliance hallucination — incorrect regulatory or legal output accepted without review",
        "eps_b_label": "HIGH (0.25)",
        "pcs_floor_note": "ε_b = 0.25, W_h elevated, OutputValidationGate mandatory for non-advisory roles",
    },
    "Standard RL Agent (DQN, PPO, SAC)": {
        "risk": "Reward signal is the attack surface — corrupting reward corrupts the entire learned policy",
        "attacks": ["Reward poisoning", "Environment manipulation", "Policy extraction", "Adversarial observation perturbation"],
        "silent_failure": "Policy drift — agent behaviour degrades silently as environment shifts from training distribution",
        "eps_b_label": "MEDIUM (0.15)",
        "pcs_floor_note": "W_r elevated, AUTOMATED feedback loop is pre-deployment blocker",
    },
    "Physics-Informed Neural Network (PINN)": {
        "risk": "Outputs can be statistically plausible while violating a physical, clinical, or financial law",
        "attacks": ["Constraint relaxation attack", "Adversarial inputs at neural-physical gap", "Supply chain poisoning of physics equations"],
        "silent_failure": "Physics violation — metrologically incorrect output passes all accuracy metrics",
        "eps_b_label": "LOW (0.03)",
        "pcs_floor_note": "D_m mandatory and non-zero, DomainRule REQUIRED before PCS computable",
    },
    "CNN / Image Classifier": {
        "risk": "Silent bias drift — learns spurious correlations that do not generalise, produces biased outputs with no accuracy signal",
        "attacks": ["Adversarial examples", "Physical adversarial patches", "Membership inference", "Model extraction"],
        "silent_failure": "Bias drift — demographic bias accumulates across inference cycles without accuracy degradation",
        "eps_b_label": "LOW (0.05)",
        "pcs_floor_note": "Δ extends 14–90 days with BIAS_DRIFT, FairnessAudit mandatory",
    },
    "Retrieval-Augmented Generation (RAG)": {
        "risk": "Entire retrieval corpus is attack surface — poisoned document affects all users at inference time",
        "attacks": ["Corpus poisoning", "Indirect prompt injection via retrieved content", "Knowledge base manipulation"],
        "silent_failure": "Corpus drift — knowledge base outdated while LLM generates confident responses",
        "eps_b_label": "HIGH (0.25 — inherits LLM floor)",
        "pcs_floor_note": "CHAINED_AI patterns apply to corpus dependency, W_s elevated",
    },
}

def get_risk_profile(model_label: str) -> dict:
    """Return risk profile dict for a model label, with fallback."""
    return MODEL_RISK_PROFILE.get(model_label, {
        "risk": "Standard ML risk profile — distribution shift and boundary staleness",
        "attacks": ["Feature poisoning", "Model extraction", "Membership inference"],
        "silent_failure": "Distribution shift — confident predictions outside training distribution",
        "eps_b_label": "BASELINE",
        "pcs_floor_note": "Standard framework controls apply",
    })


# ── Infrastructure hosting type (extends InfrastructureEnum) ──────────────
HOSTING_TYPES = [
    "On-premises data centre",
    "Private cloud (dedicated virtualised)",
    "Public cloud — IaaS (AWS, Azure, GCP)",
    "Public cloud — MLaaS (SageMaker, Azure ML, Vertex AI)",
    "Third-party AI API (OpenAI, Anthropic, Google)",
    "Hybrid cloud (sensitive on-prem, scale-out cloud)",
    "Sovereign cloud (government / jurisdiction-specific)",
    "Edge computing (network edge, industrial control)",
    "On-device (smartphone, wearable, embedded)",
    "Federated (distributed participant nodes)",
]

HOSTING_RISK = {
    "On-premises data centre":                {"I_mult": 1.00, "Ws_min": 1.0, "rollback": True,    "risk": "LOW"},
    "Private cloud (dedicated virtualised)":  {"I_mult": 1.05, "Ws_min": 1.0, "rollback": True,    "risk": "LOW"},
    "Public cloud — IaaS (AWS, Azure, GCP)":  {"I_mult": 1.15, "Ws_min": 1.2, "rollback": True,    "risk": "MEDIUM"},
    "Public cloud — MLaaS (SageMaker, Azure ML, Vertex AI)": {"I_mult": 1.20, "Ws_min": 1.2, "rollback": True, "risk": "MEDIUM"},
    "Third-party AI API (OpenAI, Anthropic, Google)":        {"I_mult": 1.40, "Ws_min": 1.6, "rollback": False, "risk": "HIGH"},
    "Hybrid cloud (sensitive on-prem, scale-out cloud)":     {"I_mult": 1.10, "Ws_min": 1.1, "rollback": True,  "risk": "MEDIUM"},
    "Sovereign cloud (government / jurisdiction-specific)":  {"I_mult": 1.08, "Ws_min": 1.1, "rollback": True,  "risk": "LOW"},
    "Edge computing (network edge, industrial control)":     {"I_mult": 1.10, "Ws_min": 1.3, "rollback": False, "risk": "MEDIUM"},
    "On-device (smartphone, wearable, embedded)":            {"I_mult": 1.05, "Ws_min": 1.4, "rollback": False, "risk": "MEDIUM"},
    "Federated (distributed participant nodes)":             {"I_mult": 1.15, "Ws_min": 1.3, "rollback": False, "risk": "HIGH"},
}
