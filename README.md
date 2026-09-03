## ERPNext Ec

ERPNext Ecuador

Aplicacion de ErpNext para Ecuador
Permite habilitar los documentos electrónicos del SRI

### Compatibilidad (migración v16 / Python 3.14 / uv)

- **ERPNext / Frappe v16** (16.33 / 16.32) — hooks adaptados (`jenv` y `get_translated_dict` eliminados).
- **Python 3.14** gestionado con **uv** — dependencias modernizadas:
  `requests`, `urllib3`, `xmltodict`, `python-dateutil`, `lxml`, `cryptography`, `python-barcode`.
  Eliminadas: `suds`, `dicttoxml`, `pycryptodome`, `xmlsig`, `xades`, `pyOpenSSL`, `web3`.
  La firma XAdES-BES se realiza 100% con `cryptography` (PKCS#12).
- **Ficha Técnica SRI 2.34 (julio 2026)**:
  - Factura/NC/ND/GRS/LIQ en versión XML 1.1.0 (6 decimales en cantidad y precio unitario).
  - Anexo 23: `codigoAuxiliar` en `<detalle>` (materiales de construcción) — campo `Item.codigo_auxiliar_sri`.
  - Anexo 24: leyenda *Gran Contribuyente* en `infoAdicional` (Company).
  - Anexo 25: tag `<placa>` entre `<moneda>` y `<pagos>` (Sales Invoice.sri_placa).
  - Anexo 26: `campoAdicional` *RUC Proveedor* (Company).
  - RIDE: subtotal "Tarifa Especial" (IVA diferenciado), leyenda Gran Contribuyente, placa y RUC Proveedor.
  - Catálogos: Liquidación de Compra `codDoc` 03; tipos de identificación Tabla 6;
    retenciones de IVA Tabla 20 e ISD 2.5% (código 4586) disponibles en cuentas contables.
  - XSD de validación local: `factura_V1/1`, `notaCredito_V1/1`, `guiaRemision_V1/1`, `liquidacionCompra_V1/1`.

### Instalación (bench v16)

```bash
bench get-app https://github.com/ocazo/erpnext_ec   # o copiar el directorio a apps/
uv pip install -e ./apps/erpnext_ec --python ./env/bin/python
# Nota de layout clásico: asegurar que PYTHONPATH resuelva el paquete raíz de la app:
#   echo "$(pwd)/apps" > env/lib/python*/site-packages/zzz_erpnext_ec_apps.pth
bench --site <sitio> install-app erpnext_ec
bench --site <sitio> migrate   # ejecuta los patches (print formats RIDE, email templates, campos SRI)
bench build --app erpnext_ec   # requiere Node >= 24
bench start
```

> Los patches de `erpnext_ec` (v15_0 y v16_0) se registran en `patches.txt` y se ejecutan
> con `bench migrate`; en Frappe v16 `install-app` los marca como completados sin ejecutarlos,
> por lo que tras una instalación nueva debe correrse `bench migrate` (o ejecutar cada patch
> con `bench --site <sitio> execute`).

### Refer & Earn
My unique referral link Frappe Cloud for support us

<a href="https://frappecloud.com/dashboard/signup?referrer=9961e30a">
https://frappecloud.com/dashboard/signup?referrer=9961e30a
</a>
</br>

[RC 1.1]

#### License

GNU/General Public License (see [license.txt](license.txt))

The ERPNext code is licensed as GNU General Public License (v3) and the Documentation is licensed as Creative Commons (CC-BY-SA-3.0) and the copyright is owned by Frappe Technologies Pvt Ltd (Frappe) and Contributors.

By contributing to ERPNext, you agree that your contributions will be licensed under its GNU General Public License (v3).

