#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_experiments.py -- Orquestador de la Tarea 1 2026.

REQUISITOS
    - traza.bin en el directorio actual (salida de pcap2bin).
    - numpy, pandas, matplotlib.

LO QUE HACE
    1. Inyecta DDoS y Scan (si no existen traza_*.bin + gt_*.json).
    2. Corre exact_hh y tarea1 para cada (ataque, sketch, w).
    3. Genera figures/freq_*.png, figures/delta_*.png.
    4. Escribe results/summary.csv con MRE, latencia y memoria.
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
    """Inyecta DDoS y Scan si no existen los .bin y .json correspondientes."""
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
    """Ground truth con exact_hh."""
    run(["./exact_hh", traza, "--key", key, "-W", str(W), "--delta", str(DELTA),
         "--phi", str(PHI), "--query", query, "--out-query", out])


def correr_tarea1(traza, key, sketch, w, query, out, mode="detect"):
    """Estimacion con tarea1."""
    run(["./tarea1", traza, "--mode", mode, "--key", key,
         "--sketch", sketch, "-d", str(D), "-w", str(w),
         "-W", str(W), "--delta", str(DELTA), "--phi", str(PHI),
         "--query", query, "--out", out])


def leer_exact(path):
    """exact_hh --out-query usa: win,tau_us,t_rel_s,key,N,threshold,exact_f,exact_hh,exact_delta"""
    df = pd.read_csv(path)
    df = df.rename(columns={"exact_f": "f_exact",
                            "exact_hh": "hh_exact",
                            "exact_delta": "df_exact"})
    return df


def leer_sketch(path):
    return pd.read_csv(path)


def figura_frecuencias(dd, ataque, gt, outpath):
    """Una figura por ataque: exacta + 6 curvas (CMS/CS x 3 anchos)."""
    plt.figure(figsize=(11, 5.5))
    base = dd["exact"]
    ini, fin = gt["ventana_ataque_rel_s"]
    plt.axvspan(ini, fin, color="red", alpha=0.10, label="ataque")
    plt.plot(base["t_rel_s"], base["f_exact"], "k-", lw=2.5, label="exacto")

    colores = {256: "tab:blue", 1024: "tab:orange", 4096: "tab:green"}
    estilos = {"cms": "-", "cs": "--"}
    for w in WS:
        for sk in ("cms", "cs"):
            d = dd["sketches"][(sk, w)]
            plt.plot(d["t_rel_s"], d["est"], estilos[sk],
                     color=colores[w], alpha=0.85, label=f"{sk.upper()} w={w}")
    plt.xlabel("tiempo relativo (s)")
    plt.ylabel("frecuencia de la clave")
    plt.title(f"Ataque {ataque}: frecuencia exacta vs estimada")
    plt.legend(ncol=2, fontsize=8)
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(outpath, dpi=140)
    plt.close()


def figura_delta(dd, ataque, gt, outpath):
    """Delta f exacto vs CS vs CMS-mediana (una sola w para no saturar)."""
    plt.figure(figsize=(11, 5.5))
    base = dd["delta"]
    ini, fin = gt["ventana_ataque_rel_s"]
    plt.axvspan(ini, fin, color="red", alpha=0.10, label="ataque")
    plt.axhline(0, color="gray", lw=0.8)
    plt.plot(base["t_rel_s"], base["df_exact"], "k-", lw=2.5, label="Δf exacto")
    plt.plot(base["t_rel_s"], base["df_cs"], "b--", lw=1.5, label="Δf CS")
    plt.plot(base["t_rel_s"], base["df_cmsmed"], "r:", lw=1.5, label="Δf CMS-mediana")
    plt.xlabel("tiempo relativo (s)")
    plt.ylabel("Δf de la clave")
    plt.title(f"Ataque {ataque}: cambio de frecuencia")
    plt.legend()
    plt.grid(alpha=0.3)
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

                resultados.append({
                    "ataque": ataque, "sketch": sk, "w": w, "d": D,
                    "mre": mre,
                    "latencia_exacta_s": lat_ex,
                    "latencia_sketch_s": lat_sk,
                    "memoria_KB": D * w * 8 // 1024,
                })

        # --- Delta f (solo una w para la figura) ---
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