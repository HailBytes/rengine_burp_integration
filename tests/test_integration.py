import csv
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from rengine_burp_integration import ReNgineDashboardBurpIntegrator  # noqa: E402


def make():
    return ReNgineDashboardBurpIntegrator("https://rengine.example/", burp_api_key="k")


def test_init_normalizes_urls_and_headers():
    i = make()
    assert i.rengine_url == "https://rengine.example"
    assert i.burp_headers["API-KEY"] == "k"
    assert i.rengine_session.verify is False


def test_parse_exported_files_filters_live_and_interesting(tmp_path):
    (tmp_path / "s.txt").write_text("a.example\nb.example\n\n")
    (tmp_path / "e.txt").write_text("https://a.example/admin\nhttps://a.example/home\n")
    (tmp_path / "u.txt").write_text("https://a.example\nftp://b.example\n")
    data = make().parse_exported_files(
        {"subdomains": str(tmp_path / "s.txt"), "endpoints": str(tmp_path / "e.txt"),
         "urls": str(tmp_path / "u.txt")}
    )
    assert data["subdomains"] == ["a.example", "b.example"]
    assert data["live_subdomains"] == ["https://a.example"]
    assert data["interesting_endpoints"] == ["https://a.example/admin"]


def test_create_burp_import_files(tmp_path):
    data = {
        "subdomains": ["a.example"],
        "endpoints": ["https://a.example/api", "not-a-url"],
        "urls": [],
        "live_subdomains": ["https://b.example"],
        "interesting_endpoints": ["https://a.example/api"],
    }
    files = make().create_burp_import_files(data, str(tmp_path))
    scope = set(pathlib.Path(files["scope"]).read_text().split())
    assert scope == {"https://a.example", "https://b.example"}
    targets = pathlib.Path(files["targets"]).read_text().split()
    assert "not-a-url" not in targets and "https://a.example/api" in targets
    with open(files["csv"], newline="") as f:
        rows = list(csv.reader(f))
    assert rows[0] == ["Type", "URL", "Notes"]
    assert ["Interesting Endpoint", "https://a.example/api", "High Priority"] in rows
