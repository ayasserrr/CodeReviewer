import ast

from helpers.entrypoint_detector import detect_entrypoints_in_file


def _parse(source: str) -> ast.Module:
    return ast.parse(source, filename="test.py")


class TestDetectEntrypointsInFile:
    def test_main_guard_detected(self):
        tree = _parse("if __name__ == '__main__':\n    pass\n")
        entrypoints = detect_entrypoints_in_file("app.py", "app.py", tree)
        kinds = {e.kind for e in entrypoints}
        assert "main_guard" in kinds

    def test_framework_app_instance_detected(self):
        tree = _parse("from fastapi import FastAPI\napp = FastAPI()\n")
        entrypoints = detect_entrypoints_in_file("main.py", "main.py", tree)
        app_entries = [e for e in entrypoints if e.kind == "framework_app_instance"]
        assert len(app_entries) == 1
        assert app_entries[0].detail == "app"

    def test_flask_app_instance_detected(self):
        tree = _parse("from flask import Flask\napplication = Flask(__name__)\n")
        entrypoints = detect_entrypoints_in_file("app.py", "app.py", tree)
        app_entries = [e for e in entrypoints if e.kind == "framework_app_instance"]
        assert app_entries[0].detail == "application"

    def test_manage_py_filename_detected_without_ast(self):
        entrypoints = detect_entrypoints_in_file("manage.py", "manage.py", None)
        assert [e.kind for e in entrypoints] == ["manage_py"]

    def test_wsgi_and_asgi_filenames_detected(self):
        assert detect_entrypoints_in_file("wsgi.py", "wsgi.py", None)[0].kind == "wsgi"
        assert detect_entrypoints_in_file("asgi.py", "asgi.py", None)[0].kind == "asgi"

    def test_file_can_match_multiple_signals(self):
        tree = _parse("from fastapi import FastAPI\napp = FastAPI()\n\nif __name__ == '__main__':\n    pass\n")
        entrypoints = detect_entrypoints_in_file("main.py", "main.py", tree)
        kinds = {e.kind for e in entrypoints}
        assert kinds == {"main_guard", "framework_app_instance"}

    def test_ordinary_file_produces_no_entrypoints(self):
        tree = _parse("def helper():\n    pass\n")
        assert detect_entrypoints_in_file("utils.py", "utils.py", tree) == []

    def test_none_tree_only_checks_filename(self):
        assert detect_entrypoints_in_file("random.py", "random.py", None) == []
