"""Search interface over the ChromaDB workflow and API class indices."""

from __future__ import annotations

import logging
from collections import Counter
from pathlib import Path

import chromadb

from angr_api_mcp.indexer.store import (
    API_CLASSES_COLLECTION,
    WORKFLOWS_COLLECTION,
    get_client,
)

logger = logging.getLogger(__name__)

# Trust level ordering for re-ranking results (lower = better)
_TRUST_ORDER = {"highest": 0, "high": 1, "medium": 2}


class WorkflowSearcher:
    """Stateful searcher backed by a ChromaDB persistent store."""

    def __init__(self, db_path: Path):
        self._client = get_client(db_path)
        self._workflows = self._client.get_or_create_collection(WORKFLOWS_COLLECTION)
        self._api_classes = self._client.get_or_create_collection(API_CLASSES_COLLECTION)

    def search_workflows(self, query: str, n_results: int = 5) -> list[dict]:
        """Semantic search for workflows matching a task description.

        Returns ranked results with trust-level re-ranking:
        highest-trust results first, then by similarity within each tier.
        """
        if self._workflows.count() == 0:
            return []

        # Over-fetch to allow re-ranking
        results = self._workflows.query(
            query_texts=[query],
            n_results=min(n_results * 3, 20),
        )

        if not results["metadatas"] or not results["metadatas"][0]:
            return []

        # Pair distances with metadata for re-ranking
        paired = list(zip(
            results["distances"][0],
            results["metadatas"][0],
        ))

        # Sort: trust level first (lower = better), then distance (lower = closer)
        paired.sort(key=lambda x: (
            _TRUST_ORDER.get(x[1].get("trust_level", "medium"), 2),
            x[0],
        ))

        return [meta for _, meta in paired[:n_results]]

    def get_api_doc(self, name: str, n_results: int = 5) -> list[dict]:
        """Fuzzy class/method lookup.

        Tries exact match first (class name as ID), then falls back to
        semantic search.
        """
        try:
            exact = self._api_classes.get(ids=[name])
            if exact["metadatas"]:
                return exact["metadatas"]
        except Exception:
            pass

        results = self._api_classes.query(
            query_texts=[name],
            n_results=n_results,
        )

        if not results["metadatas"] or not results["metadatas"][0]:
            return []

        return results["metadatas"][0]

    def list_related_apis(self, class_name: str) -> dict:
        """Find APIs commonly co-occurring with the given class.

        Scans all workflows that use the queried class, then aggregates
        all other class names that appear in those workflows.
        """
        if self._workflows.count() == 0:
            return {"queried": class_name, "related": [], "workflow_count": 0}

        results = self._workflows.query(
            query_texts=[class_name],
            n_results=min(self._workflows.count(), 50),
        )

        if not results["metadatas"] or not results["metadatas"][0]:
            return {"queried": class_name, "related": [], "workflow_count": 0}

        # Filter to workflows that actually contain this class
        matching_metas = [
            meta for meta in results["metadatas"][0]
            if class_name in meta.get("classes_used", "").split(",")
        ]

        if not matching_metas:
            return {"queried": class_name, "related": [], "workflow_count": 0}

        # Count co-occurring classes
        co_occurrence: Counter[str] = Counter()
        for meta in matching_metas:
            classes = set(meta.get("classes_used", "").split(","))
            classes.discard(class_name)
            classes.discard("")
            co_occurrence.update(classes)

        return {
            "queried": class_name,
            "related": [
                {"class": cls, "co_occurrence_count": count}
                for cls, count in co_occurrence.most_common(20)
            ],
            "workflow_count": len(matching_metas),
        }
