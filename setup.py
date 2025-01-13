import pathlib
from setuptools import setup, find_packages

HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text()


setup(
    name="upnpfuzz",
    use_scm_version={
        "root": str(HERE),
        "write_to": str(HERE / "upnpfuzz" / "_version.py"),
    },
    description="The Universal Plug and Play (UPnP) Fuzzer",
    long_description=README,
    author="Threat9",
    author_email="marcin@threat9.com",
    url="https://www.threat9.com",
    download_url="https://github.com/threat9/upnpfuzz/",
    packages=find_packages(),
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "upnpfuzz=upnpfuzz.main:main",
        ]
    },
    install_requires=[
        "requests",
    ],
    extras_require={
        "dev": [
            "isort",
            "setuptools_scm",
            "twine",
            "wheel",
            "build",
            "ruff",
        ],
    },
    classifiers=[
        "Operating System :: POSIX",
        "Environment :: Console",
        "Environment :: Console :: Curses",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.6",
        "Intended Audience :: Developers",
        "Intended Audience :: Education",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Topic :: Utilities",
    ],
)
