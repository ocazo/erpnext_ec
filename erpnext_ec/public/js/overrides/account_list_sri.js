function AccountSriBuild(treeview) {
    console.log("AccountSriBuild");
    var document_preview = `
           <p>Confirmar para crear los datos de las cuentas para el SRI?</p>
           <table>
               <tr>
                   <td><i class="fa fa-file"></i> Se eliminarán los formatos de impresión ya creados previamente</td>                   
               </tr>
               <tr>
                   <td><i class="fa fa-file"></i> Estos formatos son requeridos para el envío de RIDE</td>                   
               </tr>`;

    frappe.warn('Crear datos de cuentas para el SRI?',
        document_preview,
        () => {
            frappe.call({
                method: "erpnext_ec.utilities.settings_tools.load_accounts",
                freeze: true,
                freeze_message: "Procesando datos, espere un momento.",
                callback: function(r) {
                    frappe.show_alert({
                        message: __(`Proceso realizado con éxito`),
                        indicator: 'green'
                    }, 5);
                },
                error: function(r) {
                    frappe.show_alert({
                        message: __(`Error en proceso`),
                        indicator: 'red'
                    }, 10);
                },
            });
        },
        'Confirmar creación de datos para el SRI'
    );    
}

frappe.treeview_settings["Account"] = frappe.treeview_settings["Account"] || {};
(function () {
    var _account_tree_onload = frappe.treeview_settings["Account"].onload;
    frappe.treeview_settings["Account"].onload = function (treeview) {
        if (_account_tree_onload) {
            _account_tree_onload(treeview);
        }
        treeview.page.add_inner_button('<i class="fa fa-file"></i> Crear datos SRI', function () {
            AccountSriBuild(treeview);
        });
    };
})();
