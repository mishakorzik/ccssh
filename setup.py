import re

from setuptools import find_packages, setup

def _version() -> str:
    src = open("ccssh/__init__.py", encoding="utf-8").read()
    m = re.search(r'__version__\s*=\s*"([^"]+)"', src)
    if not m:
        raise SystemExit("ccssh/__init__.py has no __version__")
    return m.group(1)

setup(
    name="ccssh",
    version=_version(),
    description="From-scratch SSH client in Python (sync + async + CLI), OpenSSH-interop verified",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="MishaKorzhik_He1Zen",
    author_email="developer.mishakorzhik@gmail.com",
    license="MIT",
    packages=find_packages(include=["ccssh", "ccssh.*"]),
    python_requires=">=3.9",
    install_requires=["cryptography>=41"],
    entry_points={"console_scripts": ["ccssh=ccssh.cli:main"]},
    project_urls={
        "Bug Tracker": "https://github.com/mishakorzik/ccssh/issues",
        "Donate": "https://www.buymeacoffee.com/misakorzik",
    },
    keywords=[
        "ssh",
        "shell",
        "remote",
        "tcp",
        "forward",
        "tunnel",
        "async",
        "sync",
        "openssh",
        "open",
        "fast",
        "encrypt",
        "encryption",
        "server",
        "network"
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Programming Language :: Python :: 3.15",
        "Programming Language :: Python :: 3.16",
        "Topic :: System :: Networking",
        "Topic :: Security :: Cryptography",
    ],
)
