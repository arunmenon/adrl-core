"""Content extraction (ADRL-SAF-003)."""

from __future__ import annotations

from adrl.gates.content import extract_blocks, total_text, touched_paths


def test_extracts_system_tools_and_message_blocks() -> None:
    body = {
        "system": [{"type": "text", "text": "sys"}],
        "tools": [{"name": "Read", "input_schema": {}}],
        "messages": [
            {"role": "user", "content": "hello"},
            {
                "role": "assistant",
                "content": [
                    {"type": "thinking", "thinking": "private"},
                    {"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "/a"}},
                ],
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "t1",
                        "content": [
                            {"type": "text", "text": "file body"},
                            {"type": "image", "source": {"type": "base64", "data": "xx"}},
                        ],
                    }
                ],
            },
        ],
    }
    blocks = extract_blocks(body, b"k")
    types = [b.content_type for b in blocks]
    assert types == ["system", "tools", "user_string", "tool_use", "tool_result", "image"]
    assert not next(b for b in blocks if b.content_type == "image").scannable
    assert touched_paths(blocks) == ["/a"]
    assert "file body" in total_text(body)
    assert "private" not in total_text(body)


def test_keys_change_with_content_and_position() -> None:
    a = extract_blocks({"messages": [{"role": "user", "content": "x"}]}, b"k")[0]
    b = extract_blocks({"messages": [{"role": "user", "content": "y"}]}, b"k")[0]
    c = extract_blocks({"messages": [{"role": "user", "content": "x"}]}, b"k2")[0]
    assert a.key != b.key and a.key != c.key
