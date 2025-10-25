from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="network-packet-sniffer",
    version="1.0.0",
    author="xytex-s",
    author_email="",  # Add your email if you want
    description="A robust network packet sniffer with cross-platform support",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/xytex-s/Network-Packet-Sniffer",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: System Administrators",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
    ],
    python_requires=">=3.6",
    install_requires=[
        "psutil>=5.8.0",
    ],
    entry_points={
        "console_scripts": [
            "packet-sniffer=sniffer:main",
        ],
    },
)