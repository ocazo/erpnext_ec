# -*- coding: utf-8 -*-
"""Compatibilidad con instalaciones legacy (bench sin soporte uv).
Los metadatos reales del proyecto se gestionan en pyproject.toml."""
import ast
import re

from setuptools import find_namespace_packages, setup

_version_re = re.compile(r"__version__\s+=\s+(.*)")

with open("__init__.py", "rb") as f:
	version = str(
		ast.literal_eval(_version_re.search(f.read().decode("utf-8")).group(1))
	)

setup(
	name="erpnext_ec",
	version=version,
	description="ErpNext Ecuador",
	author="BeebTech Studios",
	author_email="ronald.chonillo@beebtech.net",
	packages=find_namespace_packages(include=["erpnext_ec*"]),
	zip_safe=False,
	include_package_data=True,
)
