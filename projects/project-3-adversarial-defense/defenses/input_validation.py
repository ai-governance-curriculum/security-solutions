"""Anomaly-detection input validator: reject inputs outside training distribution."""
from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest


class InputValidator:
    def __init__(self, training_samples: np.ndarray, contamination: float = 0.01):
        self.detector = IsolationForest(contamination=contamination, random_state=0)
        self.detector.fit(training_samples)

    def is_in_distribution(self, x: np.ndarray) -> bool:
        return bool(self.detector.predict(x.reshape(1, -1))[0] == 1)

    def filter_batch(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """Return (accepted_X, accepted_indices)."""
        labels = self.detector.predict(X)
        mask = labels == 1
        return X[mask], np.where(mask)[0]


def fastapi_dependency(validator: InputValidator):
    """Use as FastAPI dependency to reject anomalous inputs."""
    from fastapi import HTTPException

    def check(features: list[float]):
        if not validator.is_in_distribution(np.array(features)):
            raise HTTPException(400, "input rejected: out-of-distribution")
        return features
    return check
