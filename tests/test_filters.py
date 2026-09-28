from vulnscan.dataset.filters import (
    contains_sink,
    is_parseable_function,
    is_test_function,
    is_test_path,
    meets_min_size,
)


def test_is_test_path():
    assert is_test_path("tests/test_foo.py")
    assert is_test_path("pkg/test_helper.py")
    assert is_test_path("foo_test.py")
    assert not is_test_path("pkg/app.py")


def test_is_test_function():
    assert is_test_function("test_login")
    assert is_test_function("TestClient.run")
    assert is_test_function("Foo.test_bar")
    assert not is_test_function("handle_request")


def test_contains_sink():
    assert contains_sink("os.system(cmd)")
    assert contains_sink("eval(user)")
    assert contains_sink("pickle.loads(blob)")
    assert not contains_sink("return a + b")


def test_parseable_function_after_class_indent():
    method = "    def handle(self, x):\n        return x\n"
    assert is_parseable_function(method)
    assert not is_parseable_function('""" % stack')
    assert not is_parseable_function("from tornado import locale\n")


def test_meets_min_size():
    tiny = "def f():\n    return 1\n"
    assert not meets_min_size(tiny)
    bigger = "def f(a, b, c, d):\n    x = a + b\n    y = c + d\n    return x + y\n"
    assert meets_min_size(bigger)
