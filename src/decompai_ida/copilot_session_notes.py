from datetime import datetime
import typing as ty


def append_session_entry(
    existing_notes: ty.Optional[str],
    *,
    user_query: str,
    completed_todos: list[str],
    response_snippet: str,
    max_chars: int,
) -> str:
    parts = []
    if existing_notes is not None and existing_notes.strip():
        parts.append(existing_notes.strip())

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry_lines = [f"--- {timestamp} ---"]
    query = user_query.strip()
    if query:
        if len(query) > 200:
            query = query[:200] + "..."
        entry_lines.append(f"Query: {query}")
    if completed_todos:
        entry_lines.append("Completed:")
        entry_lines.extend(f"  - {todo}" for todo in completed_todos)
    snippet = response_snippet.strip()
    if snippet:
        if len(snippet) > 500:
            snippet = snippet[:500] + "..."
        entry_lines.append(f"Summary: {snippet}")

    parts.append("\n".join(entry_lines))
    merged = "\n\n".join(parts).strip()
    return _truncate_notes(merged, max_chars=max_chars)


def _truncate_notes(text: str, *, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    # Drop oldest content until the tail fits; prefer cutting at session starts
    # (`\n\n--- `) so we do not split the middle of an entry.
    session_boundary = "\n\n--- "
    while len(text) > max_chars:
        cut_at = len(text) - max_chars
        boundary_index = text.find(session_boundary, cut_at)
        if boundary_index >= 0:
            text = text[boundary_index + 2 :].strip()
            continue
        newline_index = text.find("\n", cut_at)
        if newline_index >= 0:
            text = text[newline_index + 1 :].strip()
            continue
        return text[-max_chars:].strip()
    return text
