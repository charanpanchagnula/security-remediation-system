"""Tests for patch_applier.py — TDD: write tests first, then implement."""

import pytest
from autoresearch.patch_applier import apply_patch, count_changed_lines


class TestApplyPatch:
    """Test apply_patch function."""

    def test_apply_patch_valid_single_line_replace(self):
        """Replace a single line with single-line replacement."""
        source = "line 1\nline 2\nline 3\n"
        change = {"start_line": 2, "end_line": 2, "new_code": "replaced line"}
        result = apply_patch(source, change)
        assert result == "line 1\nreplaced line\nline 3\n"

    def test_apply_patch_multiple_lines_replace(self):
        """Replace multiple lines with single-line replacement."""
        source = "line 1\nline 2\nline 3\nline 4\n"
        change = {"start_line": 2, "end_line": 3, "new_code": "new"}
        result = apply_patch(source, change)
        assert result == "line 1\nnew\nline 4\n"

    def test_apply_patch_multiline_replacement(self):
        """Replace lines with multi-line new code."""
        source = "line 1\nline 2\nline 3\n"
        change = {"start_line": 2, "end_line": 2, "new_code": "new 1\nnew 2\nnew 3"}
        result = apply_patch(source, change)
        assert result == "line 1\nnew 1\nnew 2\nnew 3\nline 3\n"

    def test_apply_patch_first_line(self):
        """Replace the first line."""
        source = "line 1\nline 2\nline 3\n"
        change = {"start_line": 1, "end_line": 1, "new_code": "new first"}
        result = apply_patch(source, change)
        assert result == "new first\nline 2\nline 3\n"

    def test_apply_patch_last_line(self):
        """Replace the last line."""
        source = "line 1\nline 2\nline 3\n"
        change = {"start_line": 3, "end_line": 3, "new_code": "new last"}
        result = apply_patch(source, change)
        assert result == "line 1\nline 2\nnew last\n"

    def test_apply_patch_all_lines(self):
        """Replace all lines."""
        source = "line 1\nline 2\nline 3\n"
        change = {"start_line": 1, "end_line": 3, "new_code": "all new"}
        result = apply_patch(source, change)
        assert result == "all new\n"

    def test_apply_patch_surrounding_lines_preserved(self):
        """Verify surrounding lines are not affected."""
        source = "line 1\nline 2\nline 3\nline 4\nline 5\n"
        change = {"start_line": 2, "end_line": 4, "new_code": "replaced"}
        result = apply_patch(source, change)
        assert result == "line 1\nreplaced\nline 5\n"
        # Check that line 1 and line 5 are intact
        lines = result.splitlines(keepends=True)
        assert "line 1" in lines[0]
        assert "line 5" in lines[-1]

    def test_apply_patch_invalid_start_line_zero(self):
        """Raise ValueError when start_line is 0."""
        source = "line 1\nline 2\nline 3\n"
        change = {"start_line": 0, "end_line": 1, "new_code": "new"}
        with pytest.raises(ValueError, match="out of range"):
            apply_patch(source, change)

    def test_apply_patch_invalid_start_line_negative(self):
        """Raise ValueError when start_line is negative."""
        source = "line 1\nline 2\nline 3\n"
        change = {"start_line": -1, "end_line": 1, "new_code": "new"}
        with pytest.raises(ValueError, match="out of range"):
            apply_patch(source, change)

    def test_apply_patch_invalid_end_line_less_than_start(self):
        """Raise ValueError when end_line < start_line."""
        source = "line 1\nline 2\nline 3\n"
        change = {"start_line": 3, "end_line": 1, "new_code": "new"}
        with pytest.raises(ValueError, match="out of range"):
            apply_patch(source, change)

    def test_apply_patch_invalid_end_line_too_large(self):
        """Raise ValueError when end_line > number of lines."""
        source = "line 1\nline 2\nline 3\n"
        change = {"start_line": 2, "end_line": 5, "new_code": "new"}
        with pytest.raises(ValueError, match="out of range"):
            apply_patch(source, change)

    def test_apply_patch_empty_new_code(self):
        """Replace with empty string (deletion)."""
        source = "line 1\nline 2\nline 3\n"
        change = {"start_line": 2, "end_line": 2, "new_code": ""}
        result = apply_patch(source, change)
        assert result == "line 1\nline 3\n"

    def test_apply_patch_no_trailing_newline(self):
        """Handle source without trailing newline."""
        source = "line 1\nline 2\nline 3"
        change = {"start_line": 2, "end_line": 2, "new_code": "replaced"}
        result = apply_patch(source, change)
        assert result == "line 1\nreplaced\nline 3"

    def test_apply_patch_single_line_source(self):
        """Handle single line source."""
        source = "line 1"
        change = {"start_line": 1, "end_line": 1, "new_code": "new"}
        result = apply_patch(source, change)
        assert result == "new"

    def test_apply_patch_empty_source(self):
        """Handle empty source."""
        source = ""
        change = {"start_line": 1, "end_line": 1, "new_code": "new"}
        with pytest.raises(ValueError, match="out of range"):
            apply_patch(source, change)


class TestCountChangedLines:
    """Test count_changed_lines function."""

    def test_count_changed_lines_zero_diff(self):
        """No changes -> 0 changed lines."""
        original = "line 1\nline 2\nline 3"
        patched = "line 1\nline 2\nline 3"
        assert count_changed_lines(original, patched) == 0

    def test_count_changed_lines_single_line_changed(self):
        """One line changed -> 1 changed line."""
        original = "line 1\nline 2\nline 3"
        patched = "line 1\nchanged\nline 3"
        assert count_changed_lines(original, patched) == 2  # one removed, one added

    def test_count_changed_lines_multiple_lines_changed(self):
        """Multiple lines changed."""
        original = "line 1\nline 2\nline 3"
        patched = "line 1\nchanged 1\nchanged 2"
        # Original: line 1, line 2, line 3
        # Patched: line 1, changed 1, changed 2
        # Equal: line 1; Not equal: line 2->changed 1, line 3->changed 2
        assert count_changed_lines(original, patched) == 4  # 2 removed + 2 added

    def test_count_changed_lines_inserted_lines(self):
        """New lines inserted."""
        original = "line 1\nline 3"
        patched = "line 1\nline 2\nline 3"
        # line 1 equal, line 2 added, line 3 equal = 1 added
        assert count_changed_lines(original, patched) == 1

    def test_count_changed_lines_deleted_lines(self):
        """Lines deleted."""
        original = "line 1\nline 2\nline 3"
        patched = "line 1\nline 3"
        # line 1 equal, line 2 deleted, line 3 equal = 1 deleted
        assert count_changed_lines(original, patched) == 1

    def test_count_changed_lines_completely_different(self):
        """Completely different content."""
        original = "original"
        patched = "completely different"
        # Both lines are different, so both are not in equal opcodes
        assert count_changed_lines(original, patched) == 2

    def test_count_changed_lines_empty_to_content(self):
        """Empty original to content."""
        original = ""
        patched = "line 1\nline 2"
        assert count_changed_lines(original, patched) == 2

    def test_count_changed_lines_content_to_empty(self):
        """Content to empty."""
        original = "line 1\nline 2"
        patched = ""
        assert count_changed_lines(original, patched) == 2

    def test_count_changed_lines_identical_empty(self):
        """Both empty."""
        original = ""
        patched = ""
        assert count_changed_lines(original, patched) == 0

    def test_count_changed_lines_multiline_changes(self):
        """Replace multiple lines with different number of lines."""
        original = "line 1\nline 2\nline 3\nline 4"
        patched = "line 1\nchanged\nline 4"
        # Equal: line 1, line 4
        # Changed: line 2 and line 3 removed, changed added (1 delete, 1 add, 1 delete = 3)
        # Actually: line 2->changed (1 not equal), line 3 (1 not equal), line 4 equal
        # So we should count how many non-equal matches
        result = count_changed_lines(original, patched)
        assert result > 0  # Some lines changed

    def test_count_changed_lines_trailing_newlines(self):
        """Test with trailing newlines."""
        original = "line 1\nline 2\n"
        patched = "line 1\nchanged\n"
        # line 1 is equal, line 2 changed (1 removed, 1 added = 2)
        assert count_changed_lines(original, patched) == 2
