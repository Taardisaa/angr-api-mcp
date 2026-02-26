"""Core data models for angr workflow extraction."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class TrustLevel(Enum):
    HIGHEST = "highest"  # angr-doc examples
    HIGH = "high"        # angr test suite
    MEDIUM = "medium"    # angr main source


@dataclass
class SourceFile:
    """A Python source file to be processed."""

    path: Path
    trust_level: TrustLevel
    category: str  # "example", "test", "main_source"


@dataclass
class ApiCall:
    """A single angr API call (method invocation or constructor)."""

    class_name: str       # e.g., "Project", "SimulationManager"
    method_name: str      # e.g., "explore" or "__init__" for constructors
    full_text: str        # e.g., "proj.factory.simulation_manager(state)"
    line_number: int
    byte_offset: int      # position in source for ordering
    return_var: str | None = None       # variable this result is assigned to
    receiver_var: str | None = None     # variable this is called on
    argument_vars: list[str] = field(default_factory=list)


@dataclass
class DataFlowEdge:
    """Links one API call's output to another's input."""

    source_call_index: int   # index into Workflow.calls
    target_call_index: int   # index into Workflow.calls
    variable_name: str       # the variable connecting them
    role: str                # "receiver" or "argument"


@dataclass
class Workflow:
    """A complete API workflow extracted from a single function or module body."""

    calls: list[ApiCall]
    data_flow: list[DataFlowEdge]
    source_snippet: str
    function_name: str
    file_path: str
    trust_level: TrustLevel
    category: str
    angr_classes_used: set[str] = field(default_factory=set)
    description: str = ""

    @property
    def id(self) -> str:
        """Unique identifier derived from source location and content."""
        first_offset = self.calls[0].byte_offset if self.calls else 0
        key = f"{self.file_path}:{self.function_name}:{len(self.calls)}:{first_offset}"
        return hashlib.sha256(key.encode()).hexdigest()[:24]

    def to_display_text(self) -> str:
        """Format as the ordered step-by-step display shown to the user."""
        lines = [f"Workflow: {self.function_name}"]
        lines.append(f"Source: {self.file_path}")
        lines.append("")
        for i, call in enumerate(self.calls):
            if call.method_name == "__init__":
                step = f"{i + 1}. angr.{call.class_name}()"
            else:
                receiver = f"{call.receiver_var}." if call.receiver_var else ""
                step = f"{i + 1}. {receiver}{call.method_name}(...)"

            # Annotate with data flow info
            incoming = [e for e in self.data_flow if e.target_call_index == i]
            if incoming:
                deps = ", ".join(
                    f"uses {e.variable_name} from step {e.source_call_index + 1}"
                    for e in incoming
                )
                step += f"  [{deps}]"
            lines.append(step)
        return "\n".join(lines)

    def to_embedding_text(self) -> str:
        """Generate text used for semantic embedding/search."""
        class_list = ", ".join(sorted(self.angr_classes_used))
        call_list = " -> ".join(
            f"{c.class_name}.{c.method_name}" for c in self.calls
        )
        parts = []
        if self.description:
            parts.append(f"angr workflow: {self.description}.")
        parts.append(f"Classes: {class_list}.")
        parts.append(f"Call chain: {call_list}.")
        parts.append(f"Source function: {self.function_name}")
        return " ".join(parts)
