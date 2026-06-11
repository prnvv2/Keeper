__version__ = "0.2.0"
VERSION_INFO = (0, 2, 0, "dev", 0)

def get_version() -> str:
    return __version__

def get_version_info() -> tuple:
    return VERSION_INFO
