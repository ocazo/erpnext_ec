frappe.pages["sri-estado"] = frappe.pages["sri-estado"] || {};

frappe.pages["sri-estado"].on_page_load = function (wrapper) {
	frappe.ui.make_app_page({
		parent: wrapper,
		title: __("Estado de Configuración SRI"),
		single_column: true,
	});
};

frappe.pages["sri-estado"].on_page_show = function (wrapper) {
	load_sri_estado(wrapper);
};

function load_sri_estado(wrapper) {
	let $parent = $(wrapper).find(".layout-main-section");
	$parent.empty();

	frappe.call({
		method: "erpnext_ec.utilities.tools.validate_sri_settings",
		callback: function (r) {
			let groups = (r.message && r.message.groups) || [];
			render_sri_estado($parent, groups);
		},
	});
}

function render_sri_estado($parent, groups) {
	if (!groups.length) {
		$parent.append('<p class="text-muted">' + __("No hay empresas configuradas.") + "</p>");
		return;
	}

	for (let group of groups) {
		let card = $('<div class="frappe-card mb-3 p-3"></div>');
		let header = $('<div class="d-flex justify-content-between align-items-center mb-2"></div>');

		let title = $("<h5 class='mb-0'></h5>");
		title.text(group.value || group.description || "");

		let estado = $("<span></span>");
		let estado_item = (group.header || []).find((h) => h.description === "Estado");
		if (estado_item) {
			estado.html(estado_item.value);
		}

		header.append(title).append(estado);
		card.append(header);

		let table = $('<table class="table table-sm mb-2"></table>');
		for (let h of group.header || []) {
			if (["Estado", "Empresa"].includes(h.description)) continue;
			let row = $("<tr></tr>");
			row.append($('<td class="text-muted"></td>').text(h.description));
			row.append($("<td></td>").text(h.value == null ? "" : h.value));
			table.append(row);
		}
		card.append(table);

		for (let a of group.alerts || []) {
			let alert = $('<div class="alert alert-danger py-2 mb-1"></div>');
			alert.text(a.description + (a.help ? " — " + a.help : ""));
			card.append(alert);
		}

		$parent.append(card);
	}
}
