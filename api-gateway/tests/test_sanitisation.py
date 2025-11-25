from gateway.routes import sanitize_value

def test_sanitize_string():
    """Test that strings are escaped and stripped."""
    assert sanitize_value("  <script>alert('xss')</script>  ") == "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"

def test_sanitize_dict():
    """Test that dictionaries are sanitized recursively."""
    dirty = {"key1": "  <b>bold</b>  ", "key2": "<script>"}
    clean = {"key1": "&lt;b&gt;bold&lt;/b&gt;", "key2": "&lt;script&gt;"}
    assert sanitize_value(dirty) == clean

def test_sanitize_list():
    """Test that lists are sanitized recursively."""
    dirty = ["  <em>em</em>  ", "<br>"]
    clean = ["&lt;em&gt;em&lt;/em&gt;", "&lt;br&gt;"]
    assert sanitize_value(dirty) == clean