"""
NetGuardian Machine Learning Anomaly Detection Engine
Implements per-device Isolation Forest models trained on localized rolling traffic baselines.

Academic Rationale for Isolation Forest:
---------------------------------------
Isolation Forest (Liu et al., 2008) is an unsupervised ensemble anomaly detection algorithm.
Unlike profiling algorithms (e.g. One-Class SVM, Kernel Density Estimation) which model the
distribution of 'normal' points and flag outliers as deviations, Isolation Forest exploits
two quantitative properties of anomalies:
  1. They are the minority (few in number).
  2. They have attribute values distinctly different from normal instances.

By recursively partitioning the feature space with random cutoffs, anomalies are isolated
much closer to the root of the trees (shorter average path lengths).
Key advantages for NetGuardian:
  - Linear time complexity O(n) with low constant factors, easily running on low-spec hardware.
  - Negligible memory consumption per device model (~a few hundred KB).
  - Multi-modal traffic accommodation without requiring prior distribution assumptions.
  - Zero-cost: requires no labeled training data, external GPUs, or cloud API calls.
"""

from datetime import datetime, timezone
import logging
import threading
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

import config
from database.db import Database, db as default_db

logger = logging.getLogger(__name__)


class DeviceMLEngine:
    """
    Manages individual Isolation Forest models for each network device.
    Extracts rolling windowed features (packet count, byte volume, hour of day, protocol variety).
    """

    def __init__(self, database: Optional[Database] = None):
        self.db = database or default_db
        # In-memory model registry: mac -> { 'model': IsolationForest, 'last_trained': ts, 'sample_count': int }
        self._models: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def extract_features(self, window_records: List[Dict[str, Any]]) -> np.ndarray:
        """
        Converts windowed database traffic aggregations into a numerical NumPy feature matrix.
        Features per window:
          [0]: packet_count
          [1]: byte_volume
          [2]: hour_of_day (0-23)
          [3]: protocol_variety (unique protocol count)
        """
        features = []
        for r in window_records:
            features.append([
                float(r.get("packet_count", 0)),
                float(r.get("byte_volume", 0)),
                float(r.get("hour_of_day", 0)),
                float(r.get("protocol_variety", 1)),
            ])
        return np.array(features, dtype=np.float32)

    def train_baseline(self, mac_address: str, hours_back: int = 168) -> Tuple[bool, str]:
        """
        Trains an Isolation Forest model using the target device's historical traffic.
        hours_back: Default 168 hours (7 days of hourly aggregations).
        """
        mac = mac_address.lower().strip()
        # Retrieve hourly windowed stats
        history = self.db.get_device_windowed_stats(mac, hours_back=hours_back)

        if len(history) < config.ML_MIN_SAMPLES_FOR_TRAIN:
            msg = (
                f"Insufficient historical samples for {mac} ({len(history)}/"
                f"{config.ML_MIN_SAMPLES_FOR_TRAIN} required). Baseline accumulating."
            )
            logger.debug(msg)
            return False, msg

        X = self.extract_features(history)

        from sklearn.ensemble import IsolationForest

        # Train Isolation Forest
        model = IsolationForest(
            n_estimators=100,
            contamination=config.ML_CONTAMINATION_RATE,
            random_state=42,
            n_jobs=1,  # Single-threaded per device to preserve host desktop CPU
        )
        model.fit(X)

        with self._lock:
            self._models[mac] = {
                "model": model,
                "last_trained": datetime.now(timezone.utc),
                "sample_count": len(history),
            }

        logger.info(
            "Trained baseline Isolation Forest for device %s with %d samples.",
            mac,
            len(history),
        )
        return True, "Baseline trained successfully."

    def evaluate_observation(
        self,
        mac_address: str,
        packet_count: int,
        byte_volume: int,
        hour_of_day: int,
        protocol_variety: int = 1,
    ) -> Dict[str, Any]:
        """
        Evaluates a single window observation against the device's baseline model.

        Returns:
            Dict containing:
              - is_anomalous: bool
              - score: raw decision score (negative indicates outlier)
              - has_baseline: bool
              - description: str
        """
        mac = mac_address.lower().strip()

        with self._lock:
            model_info = self._models.get(mac)

        if not model_info:
            # Attempt to train if not already loaded
            trained, _ = self.train_baseline(mac)
            if not trained:
                return {
                    "is_anomalous": False,
                    "score": 0.0,
                    "has_baseline": False,
                    "description": "Baseline still building.",
                }
            with self._lock:
                model_info = self._models.get(mac)

        model: IsolationForest = model_info["model"]

        observation = np.array(
            [[float(packet_count), float(byte_volume), float(hour_of_day), float(protocol_variety)]],
            dtype=np.float32,
        )

        # Decision function: negative score = outlier, positive = inlier
        raw_score = float(model.decision_function(observation)[0])
        prediction = int(model.predict(observation)[0])  # -1 = anomaly, 1 = normal

        is_anomalous = (prediction == -1) or (raw_score < config.ML_SCORE_THRESHOLD)

        desc = (
            f"Observation (pkts={packet_count}, bytes={byte_volume}, hr={hour_of_day}): "
            f"Anomaly Score = {raw_score:.3f}"
        )

        return {
            "is_anomalous": is_anomalous,
            "score": raw_score,
            "has_baseline": True,
            "description": desc,
        }


# Global singleton
device_ml_engine = DeviceMLEngine()
