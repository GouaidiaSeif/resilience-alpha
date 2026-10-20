"""Chargement et métadonnées du modèle publié (ml/model/model.joblib).

Le fichier .joblib contient des objets scikit-learn sérialisés (pickle) : il ne se recharge de façon fiable
qu'avec les mêmes versions de bibliothèques que l'entraînement. Ces versions sont enregistrées dans le modèle
(clé « versions ») et figées dans ml/requirements-lock.txt, que l'image Docker du détecteur installe.
"""

from __future__ import annotations

import platform
import warnings
from pathlib import Path

import joblib
import numpy
import sklearn

# Bibliothèques dont dépend la désérialisation du modèle.
TRACKED = {"scikit-learn": sklearn.__version__, "numpy": numpy.__version__, "joblib": joblib.__version__}


def library_versions() -> dict[str, str]:
    return {"python": platform.python_version(), **TRACKED}


def version_mismatch(bundle: dict) -> dict[str, tuple[str, str]]:
    """{bibliothèque: (version d'entraînement, version installée)} pour chaque écart. Vide si tout concorde."""
    trained = bundle.get("versions") or {}
    return {lib: (trained[lib], have) for lib, have in TRACKED.items() if lib in trained and trained[lib] != have}


def load_bundle(path: Path) -> tuple[dict, dict[str, tuple[str, str]]]:
    """Charge le modèle. Lève RuntimeError avec la marche à suivre si les versions empêchent le chargement."""
    with warnings.catch_warnings():
        # scikit-learn avertit à chaque objet si sa version diffère : on rapporte l'écart une seule fois.
        warnings.filterwarnings("ignore", message=r".*Trying to unpickle estimator.*")
        try:
            bundle = joblib.load(path)
        except FileNotFoundError:
            raise
        except Exception as exc:  # noqa: BLE001 - pickle incompatible : message utile plutôt qu'une trace
            raise RuntimeError(
                f"Impossible de charger {path} ({type(exc).__name__}: {exc}). Le modèle a sans doute été entraîné "
                "avec d'autres versions : pip install -r ml/requirements-lock.txt, ou ré-entraîner "
                "(python ml/train.py --from-file ml/data/train.jsonl)."
            ) from exc
    return bundle, version_mismatch(bundle)


def mismatch_text(mismatch: dict[str, tuple[str, str]]) -> str:
    return ", ".join(f"{lib} {trained} (modèle) ≠ {have} (installé)" for lib, (trained, have) in mismatch.items())
