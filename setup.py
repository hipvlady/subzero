# Copyright (c) Subzero Development Team.
# Distributed under the terms of the Modified BSD License.

"""Setup configuration for Subzero Zero Trust API Gateway."""

from os import path

from setuptools import find_packages, setup

here = path.abspath(path.dirname(__file__))

# Read the README file
with open(path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

# Read version from _version.py
version_ns = {}
with open(path.join(here, "subzero", "_version.py")) as f:
    exec(f.read(), {}, version_ns)

# Read requirements
with open(path.join(here, "requirements.txt"), encoding="utf-8") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="ztag",
    version=version_ns["__version__"],
    description="Zero Trust API Gateway with Enterprise-Grade Performance",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/hipvlady/subzero",
    author="Vlad Parakhin",
    author_email="vlad@fwdinc.net",
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
        "Topic :: System :: Systems Administration :: Authentication/Directory",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3 :: Only",
        "Operating System :: OS Independent",
        "Framework :: FastAPI",
        "Framework :: AsyncIO",
    ],
    keywords="zero-trust api gateway auth0 authentication authorization security jwt ai mcp",
    packages=find_packages(exclude=["docs", "tests*", "examples", "scripts", "archive"]),
    python_requires=">=3.11",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4",
            "pytest-asyncio>=0.23",
            "pytest-cov>=4.1",
            "pytest-benchmark>=4.0",
            "black>=25.9",
            "ruff>=0.1",
            "mypy>=1.8",
            "sphinx>=7.2",
            "sphinx-rtd-theme>=2.0",
        ],
        "redis": ["redis>=5.0"],
        "monitoring": [
            "prometheus-client>=0.19",
            "opentelemetry-api>=1.22",
            "opentelemetry-sdk>=1.22",
        ],
        "testing": [
            "locust>=2.20",
            "psutil>=5.9",
        ],
    },
    entry_points={
        "console_scripts": [
            "subzero=subzero.__main__:main",
        ],
    },
    package_data={
        "subzero": [
            "py.typed",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    project_urls={
        "Bug Reports": "https://github.com/hipvlady/subzero/issues",
        "Source": "https://github.com/hipvlady/subzero",
        "Documentation": "https://github.com/hipvlady/subzero/blob/main/README.md",
        "Changelog": "https://github.com/hipvlady/subzero/blob/main/CHANGELOG.md",
    },
)
