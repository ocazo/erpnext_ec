from __future__ import unicode_literals

import click
import frappe


def before_install():
	print("before_install erpnext_ec")


def after_install():
	try:
		print("Setting ERPNext Ecuador...")
		click.secho("Thank you for installing ERPNext Ecuador!", fg="green")
	except Exception as e:
		click.secho(
			"Installation for ERPNext Ecuador app failed due to an error."
			" Please try re-installing the app.",
			fg="bright_red",
		)
		raise e
