"""ChromaDB ingestion and persistence for extracted angr workflows."""

from __future__ import annotations

import logging
from pathlib import Path

import chromadb

from angr_api_mcp.extractor.models import Workflow

logger = logging.getLogger(__name__)

WORKFLOWS_COLLECTION = "workflows"
API_CLASSES_COLLECTION = "api_classes"


def get_client(db_path: Path) -> chromadb.ClientAPI:
    """Get a persistent ChromaDB client."""
    db_path.mkdir(parents=True, exist_ok=True)
    return chromadb.PersistentClient(path=str(db_path))


def clear_index(client: chromadb.ClientAPI) -> None:
    """Drop both ChromaDB collections, leaving an empty database."""
    for name in (WORKFLOWS_COLLECTION, API_CLASSES_COLLECTION):
        try:
            client.delete_collection(name)
        except Exception:
            pass


def get_index_info(client: chromadb.ClientAPI) -> dict:
    """Return metadata about the current index (version, build time, counts).

    Returns a dict with keys: angr_version, indexed_at, workflow_count,
    api_class_count. Values are "unknown" / 0 when the index is empty.
    """
    info: dict = {
        "angr_version": "unknown",
        "indexed_at": "unknown",
        "workflow_count": 0,
        "api_class_count": 0,
    }
    try:
        wf_col = client.get_collection(WORKFLOWS_COLLECTION)
        meta = wf_col.metadata or {}
        info["angr_version"] = meta.get("angr_version", "unknown")
        info["indexed_at"] = meta.get("indexed_at", "unknown")
        info["workflow_count"] = wf_col.count()
    except Exception:
        pass
    try:
        info["api_class_count"] = client.get_collection(API_CLASSES_COLLECTION).count()
    except Exception:
        pass
    return info


def build_workflow_index(
    client: chromadb.ClientAPI,
    workflows: list[Workflow],
    angr_version: str = "unknown",
    indexed_at: str = "",
) -> None:
    """Ingest extracted workflows into ChromaDB.

    Creates/replaces the workflows collection with the provided data.
    """
    import datetime

    if not indexed_at:
        indexed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    try:
        client.delete_collection(WORKFLOWS_COLLECTION)
    except Exception:
        pass

    collection = client.create_collection(
        name=WORKFLOWS_COLLECTION,
        metadata={
            "hnsw:space": "cosine",
            "angr_version": angr_version,
            "indexed_at": indexed_at,
        },
    )

    if not workflows:
        logger.warning("No workflows to index")
        return

    # Deduplicate by ID (same function extracted from multiple passes)
    seen: set[str] = set()
    unique: list[Workflow] = []
    for w in workflows:
        wid = w.id
        if wid not in seen:
            seen.add(wid)
            unique.append(w)
    if len(unique) < len(workflows):
        logger.info("Dropped %d duplicate workflow IDs", len(workflows) - len(unique))
    workflows = unique

    # ChromaDB has batch size limits; process in chunks
    batch_size = 500
    for i in range(0, len(workflows), batch_size):
        batch = workflows[i : i + batch_size]
        collection.add(
            ids=[w.id for w in batch],
            documents=[w.to_embedding_text() for w in batch],
            metadatas=[_workflow_to_metadata(w) for w in batch],
        )

    logger.info("Indexed %d workflows into ChromaDB", len(workflows))


def build_api_class_index(
    client: chromadb.ClientAPI,
    workflows: list[Workflow],
) -> None:
    """Build the API class index from workflow data.

    Extracts unique angr classes used across all workflows and creates
    a searchable collection for get_api_doc lookups.
    """
    try:
        client.delete_collection(API_CLASSES_COLLECTION)
    except Exception:
        pass

    collection = client.create_collection(
        name=API_CLASSES_COLLECTION,
        metadata={"hnsw:space": "cosine"},
    )

    # Aggregate class information across workflows
    class_info: dict[str, dict] = {}  # class_name -> info
    for w in workflows:
        for call in w.calls:
            cls = call.class_name
            if cls not in class_info:
                class_info[cls] = {
                    "class_name": cls,
                    "methods": set(),
                    "workflow_count": 0,
                    "example_file": w.file_path,
                }
            class_info[cls]["methods"].add(call.method_name)
            class_info[cls]["workflow_count"] += 1

    if not class_info:
        logger.warning("No API classes to index")
        return

    ids = []
    documents = []
    metadatas = []
    for cls_name, info in class_info.items():
        methods = sorted(info["methods"])
        doc_text = f"angr class {cls_name}. Methods: {', '.join(methods)}."
        ids.append(cls_name)
        documents.append(doc_text)
        metadatas.append({
            "class_name": cls_name,
            "methods": ",".join(methods),
            "workflow_count": info["workflow_count"],
            "example_file": info["example_file"],
        })

    collection.add(ids=ids, documents=documents, metadatas=metadatas)
    logger.info("Indexed %d API classes into ChromaDB", len(class_info))


def _workflow_to_metadata(w: Workflow) -> dict:
    """Convert a Workflow to ChromaDB metadata dict."""
    return {
        "function_name": w.function_name,
        "file_path": w.file_path,
        "trust_level": w.trust_level.value,
        "category": w.category,
        "num_calls": len(w.calls),
        "classes_used": ",".join(sorted(w.angr_classes_used)),
        "description": w.description[:500],
        # ChromaDB metadata values have size limits; truncate large fields
        "source_snippet": w.source_snippet[:2000],
        "display_text": w.to_display_text()[:4000],
    }
