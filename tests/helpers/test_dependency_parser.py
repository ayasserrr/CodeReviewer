from pathlib import Path

from helpers.dependency_parser import parse_dependencies, parse_pyproject_toml, parse_requirements_txt


class TestParsePyprojectToml:
    def test_pep621_dependencies(self, tmp_path: Path):
        f = tmp_path / "pyproject.toml"
        f.write_text('[project]\ndependencies = ["fastapi>=0.115", "sqlalchemy[asyncio]>=2.0"]\n')
        deps = parse_pyproject_toml(f)
        names = {d.name for d in deps}
        assert names == {"fastapi", "sqlalchemy"}
        assert all(d.source_file == "pyproject.toml" for d in deps)

    def test_poetry_dependencies_excludes_python(self, tmp_path: Path):
        f = tmp_path / "pyproject.toml"
        f.write_text('[tool.poetry.dependencies]\npython = "^3.13"\nflask = "^3.0"\nrequests = {version = "^2.0"}\n')
        deps = parse_pyproject_toml(f)
        names = {d.name for d in deps}
        assert names == {"flask", "requests"}
        version_by_name = {d.name: d.version for d in deps}
        assert version_by_name["flask"] == "^3.0"
        assert version_by_name["requests"] == "^2.0"

    def test_malformed_toml_returns_empty_list_not_raises(self, tmp_path: Path):
        f = tmp_path / "pyproject.toml"
        f.write_text("this is not [ valid toml")
        assert parse_pyproject_toml(f) == []

    def test_missing_file_returns_empty_list(self, tmp_path: Path):
        assert parse_pyproject_toml(tmp_path / "does-not-exist.toml") == []

    def test_no_version_specifier(self, tmp_path: Path):
        f = tmp_path / "pyproject.toml"
        f.write_text('[project]\ndependencies = ["fastapi"]\n')
        deps = parse_pyproject_toml(f)
        assert deps[0].name == "fastapi"
        assert deps[0].version is None


class TestParseRequirementsTxt:
    def test_basic_requirements(self, tmp_path: Path):
        f = tmp_path / "requirements.txt"
        f.write_text("fastapi==0.115.0\nsqlalchemy>=2.0\nrequests\n")
        deps = parse_requirements_txt(f)
        names = {d.name for d in deps}
        assert names == {"fastapi", "sqlalchemy", "requests"}
        assert all(d.source_file == "requirements.txt" for d in deps)

    def test_skips_comments_and_blank_lines(self, tmp_path: Path):
        f = tmp_path / "requirements.txt"
        f.write_text("# a comment\n\nfastapi==0.115.0\n")
        deps = parse_requirements_txt(f)
        assert len(deps) == 1
        assert deps[0].name == "fastapi"

    def test_skips_options_and_urls(self, tmp_path: Path):
        f = tmp_path / "requirements.txt"
        f.write_text("-e .\n--index-url https://example.com\ngit+https://github.com/x/y.git\nflask==3.0\n")
        deps = parse_requirements_txt(f)
        assert len(deps) == 1
        assert deps[0].name == "flask"

    def test_missing_file_returns_empty_list(self, tmp_path: Path):
        assert parse_requirements_txt(tmp_path / "does-not-exist.txt") == []


class TestParseDependencies:
    def test_dispatches_to_both_parsers_when_both_present(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = ["fastapi"]\n')
        (tmp_path / "requirements.txt").write_text("flask==3.0\n")
        deps = parse_dependencies(tmp_path, ("pyproject.toml", "requirements.txt"))
        names = {d.name for d in deps}
        assert names == {"fastapi", "flask"}

    def test_only_parses_files_present_in_root_config_file_names(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = ["fastapi"]\n')
        (tmp_path / "requirements.txt").write_text("flask==3.0\n")
        deps = parse_dependencies(tmp_path, ("pyproject.toml",))  # requirements.txt not listed
        names = {d.name for d in deps}
        assert names == {"fastapi"}
