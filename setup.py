
### 3. setup.py

```python
from setuptools import setup, find_packages

setup(
    name="kasau_xss_tester",
    version="2.0.0",
    description="Advanced XSS Vulnerability Scanner",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Kasau",
    author_email="security@kasau.dev",
    url="https://github.com/kasau/kasau-xss-tester",
    packages=find_packages(),
    install_requires=[
        "requests>=2.26.0",
        "beautifulsoup4>=4.10.0",
        "colorama>=0.4.4",
    ],
    entry_points={
        "console_scripts": [
            "kasau-xss=run:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Development Status :: 5 - Production/Stable",
    ],
    python_requires=">=3.7",
)
