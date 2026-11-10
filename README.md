# Hardening CIS en Cisco IOS (PNETLab)

[![Video demostrativo](docs/images/01-topologia.png)](https://youtu.be/3RDcoVWvwRA)

**Video demostrativo:** https://youtu.be/3RDcoVWvwRA

[![Video](https://img.shields.io/badge/%E2%96%B6-Video_demostrativo-red?style=for-the-badge&logo=youtube&logoColor=white)](https://youtu.be/3RDcoVWvwRA)
[![Informe](https://img.shields.io/badge/%F0%9F%93%84-Informe-blue?style=for-the-badge)](docs/informe.md)
[![Script](https://img.shields.io/badge/%F0%9F%90%8D-Script-yellow?style=for-the-badge)](scripts/hardening_cis.py)
[![Configs](https://img.shields.io/badge/%E2%9A%99-Running--configs-green?style=for-the-badge)](running-configs/)
[![Reportes](https://img.shields.io/badge/%F0%9F%93%8A-Reportes-orange?style=for-the-badge)](reports/)
[![Capturas](https://img.shields.io/badge/%F0%9F%96%BC-Capturas-purple?style=for-the-badge)](docs/images/)

**Ir directo a:**
[Topología](docs/informe.md#2-topología) ·
[Controles CIS](docs/informe.md#4-recomendaciones-aplicadas-y-por-qué) ·
[Antes](docs/informe.md#5-evidencia-antes-del-hardening) ·
[Apply](docs/informe.md#6-aplicación-del-hardening) ·
[Después](docs/informe.md#7-pruebas-después-del-hardening) ·
[Auditoría final](docs/informe.md#8-auditoría-final) ·
[Limitaciones](docs/informe.md#10-limitaciones)

| | |
|---|---|
| **Autor** | Mario de León |
| **Matrícula** | 20250682 |
| **Materia** | Seguridad de Redes |
| **Maestro** | Jonathan Rondon |

## Propósito

Demostrar cómo se aplica *hardening* a un router y a un switch Cisco IOS siguiendo recomendaciones del **CIS Benchmark de Cisco IOS**, y comprobar que funciona. El laboratorio incluye:

- Una topología en PNETLab con un router (R1) y un switch (SW1).
- Un script en Python (`scripts/hardening_cis.py`) que audita 15 controles CIS por SSH, con dos modos:
  - `--mode audit`: genera un informe sin modificar nada.
  - `--mode apply`: aplica las reglas que fallan, guarda la configuración y genera un informe posterior (Antes/Después).
- Pruebas de que la superficie de ataque se reduce (nmap, Telnet, SSH, `show`) sin romper la conectividad.

Resultado: de **1/15** (R1) y **0/15** (SW1) controles cumplidos a **15/15** en ambos equipos.

## Topología

```mermaid
graph LR
  NAT((Internet / NAT)) --- AUD["AUDITOR<br/>Kali 10.6.82.70"]
  AUD -- "e0/2 · VLAN 99" --- SW1["SW1<br/>Switch L2"]
  PC["PC-USER<br/>Kali 10.6.82.10"] -- "e0/1 · VLAN 10" --- SW1
  SW1 -- "e0/0 · trunk 10,99" --- R1["R1<br/>Router"]
```

| Nodo | Función | IP |
|------|---------|----|
| R1 | Router, gateway de las VLAN (router-on-a-stick) | 10.6.82.1 (VLAN 10) · 10.6.82.65 (VLAN 99) |
| SW1 | Switch con VLAN 10 (USERS) y VLAN 99 (MGMT) | 10.6.82.66 |
| PC-USER | Cliente de la VLAN de usuarios | 10.6.82.10/26 |
| AUDITOR | Ejecuta el script y nmap | 10.6.82.70/26 |
| NAT | Internet solo para instalar paquetes | DHCP |

El direccionamiento (10.6.82.0/24) se deriva de los últimos cuatro dígitos de la matrícula (0682).

## Flujo del script

```mermaid
flowchart LR
  A[Conexión SSH a R1 y SW1] --> B[Lee running-config]
  B --> C{Modo}
  C -- audit --> D[Informe PASS/FAIL]
  C -- apply --> E[Aplica solo los controles en FAIL] --> F[Guarda config y re-audita] --> G[Informe Antes/Después]
```

## Contenido

| Ruta | Descripción |
|------|-------------|
| [`docs/informe.md`](docs/informe.md) | Informe completo: controles, justificación y evidencias |
| `docs/images/` | Capturas de pantalla |
| `scripts/hardening_cis.py` | Script de auditoría y hardening |
| `running-configs/` | Configuraciones de R1 y SW1: antes, después y auditoría final |
| `reports/` | Informes generados por el script (`.txt` y `.json`) |

## Uso del script

```bash
pip3 install netmiko==3.4.0
python3 scripts/hardening_cis.py --mode audit   # solo informe
python3 scripts/hardening_cis.py --mode apply   # aplica y genera informe posterior
```

## Nota sobre credenciales

Es un laboratorio. `Admin123` y `enable password cisco` son credenciales de práctica que solo existen en la topología de PNETLab; las configuraciones de "antes" las muestran a propósito como parte de la configuración vulnerable.
