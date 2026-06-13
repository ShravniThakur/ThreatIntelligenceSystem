"""Multi-label Android malware classifier (prototype).

``train.py`` trains a per-label LightGBM model and writes ``artifacts/model.pkl``.
``predict.py`` is the lightweight serving path used by the live pipeline — it loads
that pickle WITHOUT importing the heavy training deps (shap/matplotlib).

NOTE: the bundled model was trained on SYNTHETIC data and is a prototype — its
outputs are experimental and must not be treated as a production verdict.
"""
