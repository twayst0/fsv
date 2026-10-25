from setuptools import setup, find_packages

setup(
    name="fsv",
    version="2.1.0",
    description="FSV — Web Vulnerability Scanner & MCP Security Tool",
    author="Anıl Kara",
    python_requires=">=3.11",
    packages=find_packages(),
    install_requires=open("requirements.txt").read().splitlines(),
    entry_points={
        "console_scripts": [
            "fsv=fsv.cli:cli",
            "fsv-mcp=fsv.mcp.server:run",
            "fsv-web=fsv.web.app:run",
        ],
    },
    include_package_data=True,
    package_data={
        "fsv": ["web/static/*"],
    },
)
