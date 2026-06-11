from keeper.version import VERSION_INFO, __version__, get_version, get_version_info


class TestVersion:
    def test_version_string(self):
        assert isinstance(__version__, str)
        assert len(__version__) > 0
        parts = __version__.split(".")
        assert len(parts) >= 3

    def test_get_version(self):
        assert get_version() == __version__

    def test_version_info_tuple(self):
        info = get_version_info()
        assert isinstance(info, tuple)
        assert len(info) >= 4
        assert isinstance(info[0], int)
        assert isinstance(info[1], int)
        assert isinstance(info[2], int)

    def test_version_info_constant(self):
        assert VERSION_INFO == get_version_info()

    def test_version_consistency(self):
        parts = __version__.split(".")
        major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2].split("-")[0])
        assert major == VERSION_INFO[0]
        assert minor == VERSION_INFO[1]
        assert patch == VERSION_INFO[2]
