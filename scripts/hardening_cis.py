#!/usr/bin/env python3
"""Auditoria y hardening CIS (Cisco IOS) - Mario de Leon - Lab PNETLab 0682
Uso:
  python3 hardening_cis.py --mode audit   # solo informe, no cambia nada
  python3 hardening_cis.py --mode apply   # aplica reglas + informe posterior
"""
import argparse, getpass, json, re
from datetime import datetime
from netmiko import ConnectHandler

DEVICES = {"R1": "10.6.82.65", "SW1": "10.6.82.66"}


def connect(ip, user, pwd):
    conn = ConnectHandler(device_type="cisco_ios", host=ip, username=user, password=pwd,
                          global_delay_factor=4, conn_timeout=30, auth_timeout=30,
                          banner_timeout=30, timeout=60)
    conn.enable()
    return conn


def has(cfg, pat):
    return re.search(pat, cfg, re.M) is not None


def blocks(cfg):
    out = []
    for ln in cfg.splitlines():
        if ln and not ln.startswith(" ") and ln != "!":
            out.append([ln, []])
        elif ln.startswith(" ") and out:
            out[-1][1].append(ln.strip())
    return [(h, "\n".join(b)) for h, b in out]


def g_present(pat):
    return lambda c: [] if has(c, pat) else ["global"]


def iface_test(cond, need):
    def t(c):
        return [h for h, b in blocks(c)
                if h.startswith("interface") and cond(b) and need not in b.split("\n")]
    return t


def vty_test(pat):
    def t(c):
        return [h for h, b in blocks(c)
                if h.startswith("line vty") and not re.search(pat, b, re.M)]
    return t


def per_block_fix(cmd):
    return lambda f, s: [x for h in f for x in (h, cmd)]


CHECKS = [
    dict(id="C01", title="service password-encryption",
         test=g_present(r"^service password-encryption"),
         fix=lambda f, s: ["service password-encryption"]),
    dict(id="C02", title="enable secret (sin enable password)",
         test=lambda c: [] if has(c, r"^enable secret \d ") and not has(c, r"^enable password") else ["global"],
         fix=lambda f, s: ["no enable password", f"enable secret {s['enable']}"]),
    dict(id="C03", title="HTTP/HTTPS server deshabilitado",
         test=lambda c: ["global"] if has(c, r"^ip http (secure-)?server") else [],
         fix=lambda f, s: ["no ip http server", "no ip http secure-server"]),
    dict(id="C04", title="CDP deshabilitado",
         test=g_present(r"^no cdp run"), fix=lambda f, s: ["no cdp run"]),
    dict(id="C05", title="SSH version 2",
         test=g_present(r"^ip ssh version 2"), fix=lambda f, s: ["ip ssh version 2"]),
    dict(id="C06", title="VTY solo SSH",
         test=vty_test(r"^transport input ssh\s*$"),
         fix=per_block_fix("transport input ssh")),
    dict(id="C07", title="exec-timeout en VTY",
         test=vty_test(r"^exec-timeout (?!0 0)\d+"),
         fix=per_block_fix("exec-timeout 5 0")),
    dict(id="C08", title="Banner de acceso",
         test=g_present(r"^banner (login|motd)"),
         fix=lambda f, s: ["banner login #Acceso restringido. Solo personal autorizado.#"]),
    dict(id="C09", title="no ip source-route",
         test=g_present(r"^no ip source-route"), fix=lambda f, s: ["no ip source-route"]),
    dict(id="C10", title="logging buffered",
         test=g_present(r"^logging buffered"), fix=lambda f, s: ["logging buffered 16384"]),
    dict(id="C11", title="login block-for",
         test=g_present(r"^login block-for"),
         fix=lambda f, s: ["login block-for 120 attempts 3 within 60"]),
    dict(id="C12", title="AAA local (authn + authz exec)",
         test=lambda c: [] if has(c, r"^aaa new-model") and has(c, r"^aaa authorization exec default local") else ["global"],
         fix=lambda f, s: ["aaa new-model",
                           "aaa authentication login default local",
                           "aaa authorization exec default local"]),
    dict(id="C13", title="no ip proxy-arp en interfaces con IP",
         test=iface_test(lambda b: "ip address" in b and "no ip address" not in b, "no ip proxy-arp"),
         fix=per_block_fix("no ip proxy-arp")),
    dict(id="C14", title="switchport nonegotiate en trunks",
         test=iface_test(lambda b: "switchport mode trunk" in b, "switchport nonegotiate"),
         fix=per_block_fix("switchport nonegotiate")),
    dict(id="C15", title="Timestamps en logs",
         test=g_present(r"^service timestamps log datetime"),
         fix=lambda f, s: ["service timestamps log datetime msec"]),
]


def audit(conn):
    cfg = conn.send_command("show running-config")
    return {ck["id"]: ck["test"](cfg) for ck in CHECKS}, cfg


def apply_fixes(conn, results, secrets):
    for ck in CHECKS:
        fails = results[ck["id"]]
        if fails:
            conn.send_config_set(ck["fix"](fails, secrets), cmd_verify=False)
    conn.save_config()


def save_cfg(name, tag, ts, cfg):
    with open(f"runcfg_{name}_{tag}_{ts}.txt", "w") as f:
        f.write(cfg)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["audit", "apply"], required=True)
    ap.add_argument("-u", "--user", default="admin")
    a = ap.parse_args()

    pwd = getpass.getpass("Password SSH: ")
    secrets = {"enable": getpass.getpass("Nuevo enable secret: ")} if a.mode == "apply" else {}
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report, lines = {}, [f"INFORME CIS - modo {a.mode} - {ts}", "=" * 60]

    for name, ip in DEVICES.items():
        conn = None
        try:
            conn = connect(ip, a.user, pwd)
            before, cfg_b = audit(conn)
            after = None
            if a.mode == "apply":
                save_cfg(name, "antes", ts, cfg_b)
                apply_fixes(conn, before, secrets)
                after, cfg_a = audit(conn)
                save_cfg(name, "despues", ts, cfg_a)
            else:
                save_cfg(name, "audit", ts, cfg_b)
        except Exception as e:
            lines += [f"\n[{name}] {ip}", f"ERROR: {e}"]
            continue
        finally:
            if conn:
                try:
                    conn.disconnect()
                except Exception:
                    pass

        report[name] = {"before": before, "after": after}
        lines += [f"\n[{name}] {ip}",
                  f"{'ID':<5}{'Control':<42}{'Antes':<8}" + ("Despues" if after else "")]
        for ck in CHECKS:
            b = "FAIL" if before[ck["id"]] else "PASS"
            row = f"{ck['id']:<5}{ck['title']:<42}{b:<8}"
            if after:
                row += "FAIL" if after[ck["id"]] else "PASS"
            lines.append(row)
        passed = sum(1 for v in (after or before).values() if not v)
        lines.append(f"Cumplimiento: {passed}/{len(CHECKS)}")

    with open(f"informe_{a.mode}_{ts}.txt", "w") as f:
        f.write("\n".join(lines))
    with open(f"informe_{a.mode}_{ts}.json", "w") as f:
        json.dump(report, f, indent=2)
    print("\n".join(lines))


if __name__ == "__main__":
    main()
