#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_experiments.py -- Orquestador de la Tarea 1 2026.

Requiere tener traza.bin (salida de pcap2bin) en el directorio actual.
Si no, se puede generar con:
    zcat 201812031400.pcap.gz | ./pcap2bin > traza.bin

Hace todo el pipeline del enunciado:
  - Inyecta DDoS y Scan (si no existen los .bin + .json)
  - Corre exact_hh y tarea1 para cada (ataque, sketch, w)
  - Genera figuras con zoom temporal + error relativo en log-Y
  - Escribe results/summary.csv
"""

import argparse
import json
import os
import subprocess
import sys

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Configuracion del enunciado.
WS = [256, 1024, 4096]
D = 5
PHI = 0.01
W = 60.0
DELTA = 10.0
SEED = 42


def run(cmd, check=True):
    print("+", " ".join(cmd), flush=True)
    return subprocess.run(cmd, check=check)


def ensure_dir(p):
    os.makedirs(p, exist_ok=True)


def generar_ataques():
    if not (os.path.exists("traza_ddos.bin") and os.path.exists("gt_ddos.json")):
        run([sys.executable, "inject_attack.py", "ddos",
             "--base", "traza.bin", "--out", "traza_ddos.bin",
             "--gt", "gt_ddos.json",
             "--start", "300", "--duration", "30",
             "--pps", "10000", "--sources", "4000",
             "--seed", str(SEED)])
    if not (os.path.exists("traza_scan.bin") and os.path.exists("gt_scan.json")):
        run([sys.executable, "inject_attack.py", "scan",
             "--base", "traza.bin", "--out", "traza_scan.bin",
             "--gt", "gt_scan.json",
             "--start", "300", "--duration", "30",
             "--pps", "8000", "--dst-count", "60000",
             "--seed", str(SEED)])


def correr_exact(traza, key, query, out):
    run(["./exact_hh", traza, "--key", key, "-W", str(W), "--delta", str(DELTA),
         "--phi", str(PHI), "--query", query, "--out-query", out])


def correr_tarea1(traza, key, sketch, w, query, out, mode="detect"):
    run(["./tarea1", traza, "--mode", mode, "--key", key,
         "--sketch", sketch, "-d", str(D), "-w", str(w),
         "-W", str(W), "--delta", str(DELTA), "--phi", str(PHI),
         "--query", query, "--out", out])


def leer_exact(path):
    df = pd.read_csv(path)
    df = df.rename(columns={"exact_f": "f_exact"})
    return df


def leer_sketch(path):
    return pd.read_csv(path)


def figura_frecuencias(dd, ataque, gt, outpath):
    """
    Dos paneles:
      - Superior: zoom temporal [ini-60, fin+60], eje Y lineal con unidades.
      - Inferior: error relativo |est-exact|/exact en log-Y, solo ventanas afectadas.
    """
    base = dd["exact"]
    ini, fin = gt["ventana_ataque_rel_s"]
    t_lo, t_hi = ini - 60, fin + 60

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8), sharex=True)

    ax1.axvspan(ini, fin, color="red", alpha=0.10, label="Rango de ataque inyectado")
    ax1.plot(base["t_rel_s"], base["f_exact"], "k-", lw=2.5, label="Conteo exacto (Ground Truth)")
    colores = {256: "tab:blue", 1024: "tab:orange", 4096: "tab:green"}
    estilos = {"cms": "-", "cs": "--"}
    
    for w in WS:
        for sk in ("cms", "cs"):
            d = dd["sketches"][(sk, w)]
            nombre_sk = f"Count-Min (w={w})" if sk == "cms" else f"Count-Sketch (w={w})"
            ax1.plot(d["t_rel_s"], d["est"], estilos[sk],
                     color=colores[w], alpha=0.85, label=nombre_sk)
                     
    ax1.set_ylabel(f"Frecuencia acumulada $f(x)$\n(paquetes por ventana de {int(W)} s)")
    ax1.set_title(f"Ataque {ataque.upper()}: Frecuencia exacta vs. estimada por Sketch")
    ax1.legend(ncol=2, fontsize=8)
    ax1.grid(alpha=0.3)
    ax1.set_xlim(t_lo, t_hi)

    ax2.axvspan(ini, fin, color="red", alpha=0.10)
    for w in WS:
        for sk in ("cms", "cs"):
            d = dd["sketches"][(sk, w)].copy()
            m = (d["t_rel_s"] >= ini) & (d["t_rel_s"] <= fin + W) & (d["exact"] > 0)
            err = (d.loc[m, "est"] - d.loc[m, "exact"]).abs() / d.loc[m, "exact"]
            err = err.clip(lower=1e-4)
            nombre_sk = f"Count-Min (w={w})" if sk == "cms" else f"Count-Sketch (w={w})"
            ax2.plot(d.loc[m, "t_rel_s"], err, estilos[sk] + "o",
                     color=colores[w], ms=4, alpha=0.8, label=nombre_sk)
                     
    ax2.set_yscale("log")
    ax2.set_xlabel("Tiempo transcurrido desde el inicio de la traza (segundos)")
    ax2.set_ylabel("Error relativo de frecuencia\n$|\\hat{f} - f| / f$")
    ax2.set_title("Error relativo en ventanas de tiempo afectadas")
    ax2.legend(ncol=2, fontsize=8)
    ax2.grid(alpha=0.3, which="both")
    ax2.set_xlim(t_lo, t_hi)

    plt.tight_layout()
    plt.savefig(outpath, dpi=140)
    plt.close()


def figura_delta(dd, ataque, gt, outpath):
    """
    Dos paneles:
      - Superior: Delta f exacto, CS y CMS-mediana, symlog en Y.
      - Inferior: error absoluto |Delta est - Delta exacto| en log-Y.
    """
    base = dd["delta"]
    ini, fin = gt["ventana_ataque_rel_s"]
    t_lo, t_hi = ini - 60, fin + 60

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8), sharex=True)

    ax1.axvspan(ini, fin, color="red", alpha=0.10, label="Rango de ataque inyectado")
    ax1.axhline(0, color="gray", lw=0.8)
    ax1.plot(base["t_rel_s"], base["df_exact"], "k-", lw=2.5, label="$\\Delta f$ Exacto")
    ax1.plot(base["t_rel_s"], base["df_cs"], "b--", lw=1.5, label="$\\Delta f$ Count-Sketch")
    ax1.plot(base["t_rel_s"], base["df_cmsmed"], "r:", lw=1.5, label="$\\Delta f$ Count-Min (Mediana)")
    ax1.set_yscale("symlog", linthresh=1)
    ax1.set_ylabel("Variación de frecuencia $\\Delta f = f_j - f_{j-1}$\n(paquetes / ventana)")
    ax1.set_title(f"Ataque {ataque.upper()}: Variación de frecuencia entre ventanas consecutivas")
    ax1.legend()
    ax1.grid(alpha=0.3, which="both")
    ax1.set_xlim(t_lo, t_hi)

    ax2.axvspan(ini, fin, color="red", alpha=0.10)
    m = (base["t_rel_s"] >= t_lo) & (base["t_rel_s"] <= t_hi)
    err_cs  = (base.loc[m, "df_cs"]    - base.loc[m, "df_exact"]).abs().clip(lower=1e-1)
    err_cms = (base.loc[m, "df_cmsmed"] - base.loc[m, "df_exact"]).abs().clip(lower=1e-1)
    ax2.plot(base.loc[m, "t_rel_s"], err_cs,  "b--o", ms=4, label="Error Count-Sketch ($|\\Delta \\hat{f}_{CS} - \\Delta f|$)")
    ax2.plot(base.loc[m, "t_rel_s"], err_cms, "r:o",  ms=4, label="Error Count-Min ($|\\Delta \\hat{f}_{CMS} - \\Delta f|$)")
    ax2.set_yscale("log")
    ax2.set_xlabel("Tiempo transcurrido desde el inicio de la traza (segundos)")
    ax2.set_ylabel("Error absoluto de $\\Delta f$\n$|\\Delta \\hat{f} - \\Delta f|$ (paquetes)")
    ax2.set_title("Error absoluto en la estimación del cambio de frecuencia")
    ax2.legend()
    ax2.grid(alpha=0.3, which="both")
    ax2.set_xlim(t_lo, t_hi)

    plt.tight_layout()
    plt.savefig(outpath, dpi=140)
    plt.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--only-plots", action="store_true",
                    help="no vuelve a correr los binarios, solo regenera figuras")
    args = ap.parse_args()

    ensure_dir("out"); ensure_dir("results"); ensure_dir("figures")

    if not args.only_plots:
        if not os.path.exists("traza.bin"):
            sys.exit("falta traza.bin. Corre antes:\n"
                     "  zcat 201812031400.pcap.gz | ./pcap2bin > traza.bin")
        generar_ataques()

    resultados = []

    for ataque in ("ddos", "scan"):
        gt = json.load(open(f"gt_{ataque}.json"))
        # Clave segun el tipo de ataque.
        key = "dst" if ataque == "ddos" else "src"
        query = gt["ataque"]["victima"] if ataque == "ddos" else gt["ataque"]["atacante"]
        traza = f"traza_{ataque}.bin"

        # --- ground truth exacto ---
        f_exact = f"out/exact_{ataque}.csv"
        if not args.only_plots:
            correr_exact(traza, key, query, f_exact)
        exact = leer_exact(f_exact)

        dd = {"exact": exact, "sketches": {}}
        for w in WS:
            for sk in ("cms", "cs"):
                out = f"out/detect_{ataque}_{sk}_w{w}.csv"
                if not args.only_plots:
                    correr_tarea1(traza, key, sk, w, query, out, mode="detect")
                d = leer_sketch(out)
                dd["sketches"][(sk, w)] = d

                # MRE solo en ventanas afectadas: post inicio del ataque,
                # pre salida completa, y con f_exact > 0.
                ini, fin = gt["ventana_ataque_rel_s"]
                m = (d["t_rel_s"] >= ini) & (d["t_rel_s"] <= fin + W) & (d["exact"] > 0)
                mre = float("nan")
                if m.sum() > 0:
                    mre = ((d.loc[m, "est"] - d.loc[m, "exact"]).abs()
                           / d.loc[m, "exact"]).mean()

                # Latencia: primer t_rel_s con hh==1, menos inicio del ataque.
                def primera_hh(col):
                    idx = np.where(d[col].values == 1)[0]
                    return None if len(idx) == 0 else float(d["t_rel_s"].values[idx[0]]) - ini
                lat_ex = primera_hh("hh_exact")
                lat_sk = primera_hh("hh_sketch")

                m_ring = 7
                resultados.append({
                    "ataque": ataque, "sketch": sk, "w": w, "d": D,
                    "mre": mre,
                    "latencia_exacta_s": lat_ex,
                    "latencia_sketch_s": lat_sk,
                    "memoria_KB": m_ring * D * w * 8 // 1024,
                })

        out_delta = f"out/delta_{ataque}.csv"
        if not args.only_plots:
            correr_tarea1(traza, key, "cs", 1024, query, out_delta, mode="delta")
        dd["delta"] = pd.read_csv(out_delta)

        figura_frecuencias(dd, ataque, gt, f"figures/freq_{ataque}.png")
        figura_delta(dd, ataque, gt, f"figures/delta_{ataque}.png")

    df = pd.DataFrame(resultados)
    df.to_csv("results/summary.csv", index=False)
    print(df.to_string(index=False))


if __name__ == "__main__":
    main()