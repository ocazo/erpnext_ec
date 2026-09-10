# -*- coding: utf-8 -*-
# Patch ERPNext v16 - Sidebar y Desktop Icon de "ERPNext Ec"
# En Frappe 16 el sidebar y el conmutador de workspaces se construyen desde
# los doctypes Workspace Sidebar y Desktop Icon. Se generan en after_app_install,
# pero el workspace "ERPNext Ec" se creo despues, por lo que hay que generarlos
# explicitamente. La funcion es idempotente.

import frappe
from frappe.utils.install import auto_generate_icons_and_sidebar


def ensure_sri_estado_page():
	if frappe.db.exists("Page", "sri-estado"):
		return

	prev_developer_mode = frappe.conf.developer_mode
	frappe.conf.developer_mode = 1
	try:
		page = frappe.get_doc({
			"doctype": "Page",
			"page_name": "sri-estado",
			"title": "Estado SRI",
			"module": "Erpnext Ec",
		})
		page.flags.do_not_update_json = True
		page.insert(ignore_permissions=True)
		print("Page sri-estado creada")
	finally:
		frappe.conf.developer_mode = prev_developer_mode


def execute():
	ensure_sri_estado_page()
	auto_generate_icons_and_sidebar()
