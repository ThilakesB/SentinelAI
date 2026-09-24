"""
scripts/train_baseline.py
==========================
First-run script: collects 30 minutes of process/network data and
trains the initial Isolation Forest model. Run ONCE before starting
the API server for the first time.

Usage (from sentinel-ai/):
  python scripts/train_baseline.py

Requires the agent to run as Administrator for full process visibility.
"""
from __future__ import annotations

import asyncio
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Allow imports from project root
sys.path.insert(0, str(Path(__file__).parent.parent))


async def main() -> None:
    print("=" * 60)
    print("SentinelAI — Initial Baseline Training")
    print("=" * 60)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("Collecting 30 minutes of baseline data...")
    print("(This window must remain open. DO NOT close it.)\n")

    # Initialize local DB
    from database.local_db import init_local_db
    await init_local_db()

    from monitoring.process_monitor import collect_process_snapshot
    from monitoring.network_monitor import collect_network_snapshot
    from monitoring.resource_baseline import baseline
    from ai_engine.feature_extractor import extract_features, features_to_dict
    from ai_engine.model_store import save_model, register_model_in_db, _compute_checksum

    COLLECTION_DURATION_SEC = 1800  # 30 minutes
    POLL_INTERVAL_SEC = 5
    all_vectors = []

    start = time.monotonic()
    cycles = 0

    try:
        while (time.monotonic() - start) < COLLECTION_DURATION_SEC:
            elapsed = time.monotonic() - start
            remaining = COLLECTION_DURATION_SEC - elapsed
            print(f"\r  [{cycles:4d} cycles | {int(elapsed/60):2d}m {int(elapsed%60):02d}s elapsed | "
                  f"{int(remaining/60):2d}m remaining]  ", end="", flush=True)

            proc_snaps, net_snaps = await asyncio.gather(
                collect_process_snapshot(),
                collect_network_snapshot(),
            )

            # Compute deviations and build feature vectors
            for snap in proc_snaps:
                deviations = baseline.get_deviations(
                    process_name=snap.get("name", ""),
                    cpu=snap.get("cpu_percent", 0.0),
                    ram_mb=snap.get("ram_mb", 0.0),
                    net_sent=snap.get("net_sent_mb", 0.0),
                    net_recv=snap.get("net_recv_mb", 0.0),
                    conn_count=snap.get("conn_count", 0),
                )
                vec = extract_features(snap, net_snaps, {}, deviations)
                all_vectors.append(vec)

            cycles += 1
            await asyncio.sleep(POLL_INTERVAL_SEC)

    except KeyboardInterrupt:
        print(f"\n\nInterrupted after {cycles} cycles.")

    print(f"\n\nCollection complete. {len(all_vectors)} feature vectors gathered.")

    if len(all_vectors) < 100:
        print("ERROR: Too few samples (< 100). Run for longer or check process visibility (run as Admin).")
        sys.exit(1)

    import numpy as np
    from sklearn.ensemble import IsolationForest

    print(f"Training Isolation Forest on {len(all_vectors)} samples...")
    X = np.array(all_vectors, dtype=np.float32)
    model = IsolationForest(
        n_estimators=200,
        max_samples="auto",
        contamination=0.05,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X)
    print("Training complete.")

    version = f"v{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_baseline"
    path = save_model(model, version, sample_count=len(all_vectors))
    sha256 = _compute_checksum(path)
    await register_model_in_db(version, path, sha256, len(all_vectors))

    # Persist baseline
    await baseline.persist_to_local_db()

    print(f"\n✓ Model saved: {path}")
    print(f"  SHA-256: {sha256[:32]}...")
    print(f"  Version: {version}")
    print(f"  Samples: {len(all_vectors)}")
    print("\nYou can now start the API server: uvicorn backend.main:app --reload")


if __name__ == "__main__":
    asyncio.run(main())
