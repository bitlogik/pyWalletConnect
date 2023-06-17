#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# pyWalletConnect : setup data
# Copyright (C) 2021-2023 BitLogiK

from setuptools import setup, find_packages


VERSION = ""
exec(open("pywalletconnect/version.py", encoding="utf-8").read())


with open("README.md") as readme_file:
    readme = readme_file.read()

setup(
    name="pyWalletConnect",
    version=VERSION,
    description="WalletConnect implementation for Python wallets",
    long_description=readme + "\n\n",
    long_description_content_type="text/markdown",
    keywords="blockchain wallet cryptography security",
    author="BitLogiK",
    author_email="contact@bitlogik.fr",
    url="https://github.com/bitlogik/pyWalletConnect",
    license="GPLv3",
    python_requires=">=3.7",
    install_requires=[
        "cryptography>=3.3",
        "wsproto>=1.0.0",
    ],
    package_data={},
    include_package_data=False,
    classifiers=[
        "Programming Language :: Python :: 3 :: Only",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    packages=find_packages(),
    zip_safe=False,
)
