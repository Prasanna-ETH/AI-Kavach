from setuptools import setup, find_packages

setup(
    name="asfalis-llm-sentinel",
    version="2.2.0",
    description="Enterprise AI/LLM Security Auditor & Vulnerability Scanner for CI/CD Integration",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "httpx>=0.24.0",
        "pyyaml>=6.0",
        "pydantic>=2.0",
    ],
    entry_points={
        "console_scripts": [
            "llm-sentinel=library.cli_hook:main",
        ],
    },
)
