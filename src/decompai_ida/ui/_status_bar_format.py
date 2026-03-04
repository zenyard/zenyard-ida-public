from dataclasses import dataclass


def _format_compact_count(n: int) -> str:
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}K"
    return str(n)


@dataclass(frozen=True)
class PendingInferenceCounts:
    functions: int = 0
    global_variables: int = 0
    swift_sources: int = 0
    signature_modifications: int = 0
    struct_modifications: int = 0

    @staticmethod
    def from_raw_counts(counts: dict[str, int]) -> "PendingInferenceCounts":
        function_overview = counts.get("FunctionOverview", 0)
        name_count = counts.get("Name", 0)
        global_vars = name_count - function_overview

        return PendingInferenceCounts(
            functions=function_overview,
            global_variables=max(global_vars, 0),
            swift_sources=counts.get("SwiftFunction", 0),
            signature_modifications=(
                counts.get("ParameterType", 0) + counts.get("ReturnType", 0)
            ),
            struct_modifications=counts.get("StructDefinition", 0),
        )

    @property
    def total(self) -> int:
        return (
            self.functions
            + self.global_variables
            + self.swift_sources
            + self.signature_modifications
            + self.struct_modifications
        )

    def format_tooltip(self) -> str:
        lines = list[str]()

        if self.functions > 0:
            lines.append(f"• {_format_compact_count(self.functions)} functions")
        if self.global_variables > 0:
            lines.append(
                f"• {_format_compact_count(self.global_variables)} global variables"
            )
        if self.swift_sources > 0:
            lines.append(
                f"• {_format_compact_count(self.swift_sources)} Swift sources"
            )
        if self.signature_modifications > 0:
            lines.append(
                f"• {_format_compact_count(self.signature_modifications)} signature modifications"
            )
        if self.struct_modifications > 0:
            lines.append(
                f"• {_format_compact_count(self.struct_modifications)} struct modifications"
            )

        return "\n".join(lines)
