import ast

from helpers.endpoint_detector import detect_endpoints_in_file, mark_duplicates


def _parse(source: str, filename: str = "test.py") -> ast.Module:
    return ast.parse(source, filename=filename)


class TestFunctionBasedEndpoints:
    def test_fastapi_verb_decorator(self):
        tree = _parse("@app.get('/users')\ndef list_users():\n    pass\n")
        endpoints = detect_endpoints_in_file(tree, "routes.py")
        assert len(endpoints) == 1
        assert endpoints[0].method.value == "GET"
        assert endpoints[0].path == "/users"
        assert endpoints[0].handler == "list_users"
        assert endpoints[0].framework == "fastapi"
        assert endpoints[0].is_class_based is False

    def test_fastapi_multiple_verbs_same_file(self):
        tree = _parse(
            "@app.get('/x')\ndef get_x():\n    pass\n\n"
            "@router.post('/x')\ndef post_x():\n    pass\n"
        )
        endpoints = detect_endpoints_in_file(tree, "routes.py")
        methods = {e.method.value for e in endpoints}
        assert methods == {"GET", "POST"}

    def test_flask_route_default_method_is_get(self):
        tree = _parse("@app.route('/ping')\ndef ping():\n    pass\n")
        endpoints = detect_endpoints_in_file(tree, "app.py")
        assert len(endpoints) == 1
        assert endpoints[0].method.value == "GET"
        assert endpoints[0].framework == "flask"

    def test_flask_route_with_explicit_methods_expands_to_multiple_endpoints(self):
        tree = _parse("@app.route('/ping', methods=['GET', 'POST'])\ndef ping():\n    pass\n")
        endpoints = detect_endpoints_in_file(tree, "app.py")
        methods = {e.method.value for e in endpoints}
        assert methods == {"GET", "POST"}
        assert all(e.path == "/ping" for e in endpoints)

    def test_non_decorated_function_produces_no_endpoint(self):
        tree = _parse("def helper():\n    pass\n")
        assert detect_endpoints_in_file(tree, "utils.py") == []

    def test_decorator_without_string_path_ignored(self):
        tree = _parse("@app.get(path_variable)\ndef handler():\n    pass\n")
        assert detect_endpoints_in_file(tree, "routes.py") == []


class TestClassBasedViews:
    def test_flask_method_view_resolved_via_add_url_rule(self):
        source = (
            "from flask.views import MethodView\n\n"
            "class UserView(MethodView):\n"
            "    def get(self):\n"
            "        pass\n"
            "    def post(self):\n"
            "        pass\n\n"
            "app.add_url_rule('/users', view_func=UserView.as_view('users'))\n"
        )
        tree = _parse(source, "views.py")
        endpoints = detect_endpoints_in_file(tree, "views.py")
        assert len(endpoints) == 2
        assert all(e.is_class_based for e in endpoints)
        assert all(e.class_name == "UserView" for e in endpoints)
        assert all(e.path == "/users" for e in endpoints)
        assert {e.method.value for e in endpoints} == {"GET", "POST"}

    def test_django_view_resolved_via_path_as_view(self):
        source = (
            "from django.views import View\n\n"
            "class UserView(View):\n"
            "    def get(self, request):\n"
            "        pass\n\n"
            "urlpatterns = [path('/users', UserView.as_view())]\n"
        )
        tree = _parse(source, "urls.py")
        endpoints = detect_endpoints_in_file(tree, "urls.py")
        assert len(endpoints) == 1
        assert endpoints[0].framework == "django"
        assert endpoints[0].path == "/users"

    def test_cbv_without_resolvable_registration_is_skipped(self):
        source = (
            "from flask.views import MethodView\n\n"
            "class OrphanView(MethodView):\n"
            "    def get(self):\n"
            "        pass\n"
        )
        tree = _parse(source, "views.py")
        assert detect_endpoints_in_file(tree, "views.py") == []

    def test_non_cbv_class_ignored(self):
        tree = _parse("class PlainClass:\n    def get(self):\n        pass\n")
        assert detect_endpoints_in_file(tree, "models.py") == []


class TestMarkDuplicates:
    def test_unique_endpoints_not_marked_duplicate(self):
        tree_a = _parse("@app.get('/a')\ndef a():\n    pass\n")
        tree_b = _parse("@app.get('/b')\ndef b():\n    pass\n")
        endpoints = detect_endpoints_in_file(tree_a, "a.py") + detect_endpoints_in_file(tree_b, "b.py")
        result = mark_duplicates(endpoints)
        assert all(not e.duplicate for e in result)

    def test_same_method_and_path_across_files_marked_duplicate(self):
        tree_a = _parse("@app.get('/same')\ndef handler_one():\n    pass\n")
        tree_b = _parse("@app.get('/same')\ndef handler_two():\n    pass\n")
        endpoints = detect_endpoints_in_file(tree_a, "a.py") + detect_endpoints_in_file(tree_b, "b.py")
        result = mark_duplicates(endpoints)
        assert all(e.duplicate for e in result)
        assert len(result) == 2

    def test_same_path_different_method_not_duplicate(self):
        tree = _parse(
            "@app.get('/x')\ndef get_x():\n    pass\n\n@app.post('/x')\ndef post_x():\n    pass\n"
        )
        endpoints = detect_endpoints_in_file(tree, "a.py")
        result = mark_duplicates(endpoints)
        assert all(not e.duplicate for e in result)
