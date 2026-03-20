"""Patch applier module for applying code changes and counting differences."""

import difflib


def apply_patch(source_code: str, change: dict) -> str:
    """
    Apply a patch to source code by replacing lines.

    Args:
        source_code: The original source code as a string.
        change: A dictionary with keys:
            - start_line: 1-indexed line number to start replacement (inclusive)
            - end_line: 1-indexed line number to end replacement (inclusive)
            - new_code: The replacement code (can be multi-line)

    Returns:
        The patched source code as a string.

    Raises:
        ValueError: If the line range is invalid:
            - start_line < 1
            - end_line < start_line
            - end_line > number of lines in source_code
    """
    start_line = change["start_line"]
    end_line = change["end_line"]
    new_code = change["new_code"]

    # Split source into lines, preserving line structure
    lines = source_code.splitlines(keepends=True)

    # Get the number of lines (for 1-indexed validation)
    num_lines = len(lines)

    # Validate line range
    if start_line < 1 or end_line < start_line or end_line > num_lines:
        raise ValueError("out of range")

    # Convert to 0-indexed for list operations
    start_idx = start_line - 1
    end_idx = end_line  # exclusive in Python slicing

    # Get lines before, the replacement, and lines after
    before = lines[:start_idx]
    after = lines[end_idx:]

    # Construct the patched source
    # Check if the last line being replaced had a newline
    last_replaced_line = lines[end_idx - 1] if end_idx > 0 else ""
    had_trailing_newline = last_replaced_line.endswith("\n")

    # Build the replacement code with proper newline handling
    if new_code and (after or had_trailing_newline) and not new_code.endswith("\n"):
        new_code += "\n"

    # Combine parts
    if new_code:
        patched_lines = before + [new_code] + after
    else:
        patched_lines = before + after

    # Join back together
    result = "".join(patched_lines)

    return result


def count_changed_lines(original: str, patched: str) -> int:
    """
    Count the number of lines that changed between original and patched code.

    Uses difflib.SequenceMatcher to identify differences. For each non-equal region
    (replace, delete, insert), counts both the lines removed from original AND the
    lines added in patched. This means replace operations are double-counted by design:
    a replace of 2 lines with 1 line counts as 3 (2 removed + 1 added).

    Args:
        original: The original code as a string.
        patched: The patched code as a string.

    Returns:
        The sum of lines removed from original PLUS lines added in patched,
        across all non-equal regions.
    """
    # Split into lines
    original_lines = original.splitlines()
    patched_lines = patched.splitlines()

    # Use SequenceMatcher to find matching blocks
    matcher = difflib.SequenceMatcher(None, original_lines, patched_lines)
    opcodes = matcher.get_opcodes()

    # Count lines that are not in 'equal' opcodes
    changed_count = 0
    for tag, i1, i2, j1, j2 in opcodes:
        if tag != "equal":
            # Count both original and patched lines for non-equal opcodes
            # 'replace' changes some lines from i1:i2 to j1:j2
            # 'delete' removes lines i1:i2
            # 'insert' adds lines j1:j2
            changed_count += (i2 - i1) + (j2 - j1)

    return changed_count
