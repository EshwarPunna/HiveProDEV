"""
Minimal TF-IDF index — used only if sentence-transformers isn't
installed. It's real retrieval (term-frequency / inverse-document-
frequency cosine similarity over the actual NIST control text), just
lower quality than a proper embedding model since it can't match on
meaning ("compromised credentials" won't match "account takeover").
Kept dependency-free (numpy only) so the system still runs somewhere
with no internet access to pull a transformer model.
"""
from __future__ import annotations

import json
import math
import os
import re
from collections import Counter

import numpy as np

TOKEN_RE = re.compile(r"[a-z0-9]+")


def tokenize(text: str) -> list:
    return TOKEN_RE.findall(text.lower())


def build_tfidf_index(texts: list, out_dir: str):
    os.makedirs(out_dir, exist_ok=True)
    doc_tokens = [tokenize(t) for t in texts]
    df = Counter()
    for toks in doc_tokens:
        for term in set(toks):
            df[term] += 1

    n_docs = len(texts)
    vocab = {term: i for i, term in enumerate(sorted(df.keys()))}
    idf = np.zeros(len(vocab), dtype=np.float32)
    for term, i in vocab.items():
        idf[i] = math.log((1 + n_docs) / (1 + df[term])) + 1

    matrix = np.zeros((n_docs, len(vocab)), dtype=np.float32)
    for row, toks in enumerate(doc_tokens):
        counts = Counter(toks)
        length = max(len(toks), 1)
        for term, c in counts.items():
            if term in vocab:
                matrix[row, vocab[term]] = (c / length) * idf[vocab[term]]

    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    matrix = matrix / norms

    np.save(os.path.join(out_dir, "embeddings.npy"), matrix)
    with open(os.path.join(out_dir, "tfidf_vocab.json"), "w", encoding="utf-8") as f:
        json.dump({"vocab": vocab, "idf": idf.tolist()}, f)


def embed_query_tfidf(query: str, out_dir: str) -> np.ndarray:
    with open(os.path.join(out_dir, "tfidf_vocab.json"), "r", encoding="utf-8") as f:
        d = json.load(f)
    vocab, idf = d["vocab"], np.array(d["idf"], dtype=np.float32)
    toks = tokenize(query)
    vec = np.zeros(len(vocab), dtype=np.float32)
    counts = Counter(toks)
    length = max(len(toks), 1)
    for term, c in counts.items():
        if term in vocab:
            vec[vocab[term]] = (c / length) * idf[vocab[term]]
    norm = np.linalg.norm(vec)
    if norm > 0:
        vec = vec / norm
    return vec
