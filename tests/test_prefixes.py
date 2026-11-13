from bgpwatch.prefixes import PrefixIndex, clean_path, origin_of, top_level, upstream_of


def test_covering_most_specific_first():
    idx = PrefixIndex()
    idx.add("10.0.0.0/8", "a")
    idx.add("10.1.0.0/16", "b")
    idx.add("2001:db8::/32", "v6")
    got = [(str(n), v) for n, v in idx.covering("10.1.2.0/24")]
    assert got == [("10.1.0.0/16", "b"), ("10.0.0.0/8", "a")]
    assert idx.covering("11.0.0.0/24") == []
    assert [v for _, v in idx.covering("2001:db8:1::/48")] == ["v6"]
    assert idx.covering("10.1.0.0/16", include_self=False)[0][1] == "a"
    assert "10.1.0.0/16" in idx and len(idx) == 3


def test_top_level():
    assert sorted(top_level(["10.0.0.0/8", "10.1.0.0/16", "192.0.2.0/24", "2001:db8::/32", "2001:db8:1::/48"])) == \
        ["10.0.0.0/8", "192.0.2.0/24", "2001:db8::/32"]


def test_paths():
    assert clean_path([1, 2, 2, 2, 3]) == [1, 2, 3]
    assert clean_path([1, 2, [5, 6]]) == [1, 2]
    assert origin_of([1, 2, 3]) == 3
    assert origin_of([1, 2, [7]]) == 7
    assert origin_of([1, 2, [7, 8]]) is None
    assert origin_of([]) is None
    assert upstream_of([1, 9, 4788, 4788]) == 9
    assert upstream_of([4788]) is None
