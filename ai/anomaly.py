import math
from collections import Counter

import numpy as np
from sklearn.ensemble import IsolationForest


def _shannon_entropy(file_path, sample_size=8192):
    try:
        with open(file_path, "rb") as f:
            data = f.read(sample_size)
    except (PermissionError, FileNotFoundError, OSError):
        return 0.0

    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _extract_features(artifact):
    created = artifact["created"]
    modified = artifact["modified"]
    accessed = artifact["accessed"]

    return [
        artifact.get("size", 0),
        accessed.hour,
        abs((modified - created).total_seconds()),
        abs((accessed - modified).total_seconds()),
        artifact.get("path_depth", 0),
        _shannon_entropy(artifact["path"]),
    ]


def score_artifacts(artifacts, contamination=0.05):
    if len(artifacts) < 2:
        for artifact in artifacts:
            artifact["anomaly_score"] = 0.0
            artifact["is_anomaly"] = False
        return artifacts

    feature_matrix = np.array([_extract_features(a) for a in artifacts])

    model = IsolationForest(contamination=contamination, random_state=42)
    model.fit(feature_matrix)

    raw_scores = model.decision_function(feature_matrix)
    predictions = model.predict(feature_matrix)

    for artifact, score, pred in zip(artifacts, raw_scores, predictions):
        artifact["anomaly_score"] = round(float(score), 4)
        artifact["is_anomaly"] = bool(pred == -1)

    return sorted(artifacts, key=lambda a: a["anomaly_score"])