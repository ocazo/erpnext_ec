# -*- coding: utf-8 -*-
# Patch ERPNext v16 - El Desktop Icon del workspace "SRI" se genera con el label
# igual al nombre del workspace ("SRI"). Se cambia el label del shortcut del
# escritorio a "Sri", manteniendo el link al Workspace Sidebar "SRI".
#
# La colacion de la base es utf8mb4_unicode_ci (case-insensitive), por lo que
# "SRI" y "Sri" colisionan en la clave primaria (autoname = field:label): no se
# puede renombrar in-place, hay que eliminar y recrear.

import frappe

WORKSPACE = "SRI"
NEW_LABEL = "Sri"
COPIED_FIELDS = (
	"icon_type",
	"link_type",
	"link_to",
	"icon",
	"parent_icon",
	"hidden",
	"idx",
	"standard",
)


def execute():
	if not frappe.db.exists("Desktop Icon", WORKSPACE):
		return

	old = frappe.get_doc("Desktop Icon", WORKSPACE)
	if old.label == NEW_LABEL:
		return

	values = {field: old.get(field) for field in COPIED_FIELDS}

	frappe.delete_doc("Desktop Icon", old.name, force=True, ignore_missing=True)
	frappe.db.commit()

	new = frappe.new_doc("Desktop Icon")
	new.label = NEW_LABEL
	new.update(values)
	new.insert(ignore_permissions=True)
	frappe.db.commit()
