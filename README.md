# Tarea 1 2026 — CMS y CountSketch en ventana deslizante

**Curso:** Tópicos en Grandes Volúmenes de Datos
**Traza:** MAWI samplepoint-F, 2018-12-03 14:00 JST
**URL:** https://mawi.wide.ad.jp/mawi/samplepoint-F/2018/201812031400.pcap.gz
**Semilla de los ataques:** `42`

---

## 1. Estructura del proyecto

| Archivo              | Origen    | Descripción                                                             |
| -------------------- | --------- | ----------------------------------------------------------------------- |
| `pcap2bin.cpp`       | entregado | Convierte `pcap` a registros de 24 B.                                   |
| `exact_hh.cpp`       | entregado | Calcula el ground truth exacto por ventana.                             |
| `inject_attack.py`   | entregado | Inyecta ataques de tráfico sintético (DDoS y Scan).                     |
| `sketches.hpp`       | nuevo     | Implementación de Count-Min Sketch y CountSketch.                       |
| `tarea1.cpp`         | nuevo     | Driver principal con la ventana deslizante y anillo.                    |
| `run_experiments.py` | nuevo     | Orquesta la pipeline de experimentos y genera gráficos.                 |
| `Makefile`           | nuevo     | Reglas de compilación y ejecución (`all`, `run`, `run-plots`, `clean`). |

---

## 2. Requerimientos

### Lenguajes y herramientas

* **C++17**
* **C**
* **Python 3**
* **GNU Make**
* **curl**
* **zcat**
* **g++**

### Librerías de Python

Las dependencias de Python son:

```text
numpy>=1.20
pandas>=1.3
matplotlib>=3.4
```

Se pueden instalar mediante:

```bash
pip install -r requirements.txt
```

El archivo `requirements.txt` debe contener:

```text
numpy>=1.20
pandas>=1.3
matplotlib>=3.4
```

---

## 3. Guía de ejecución

### Opción A: Ejecución mediante Makefile — recomendada

El Makefile automatiza la compilación, descarga de datos, procesamiento y generación de gráficos.

#### 1. Compilar los binarios en C++

```bash
make all
```

Esto compila `pcap2bin`, `exact_hh` y `tarea1`.

#### 2. Descargar la traza MAWI (usada para los CSV's y PNG's encontradas en las carpetas out y figures respectivamente)

```bash
curl -L -C - -O https://mawi.wide.ad.jp/mawi/samplepoint-F/2018/201812031400.pcap.gz
```

#### 3. Convertir la traza a formato binario

```bash
zcat 201812031400.pcap.gz | ./pcap2bin > traza.bin
```

La salida corresponde a registros de 24 B.

#### 4. Ejecutar la pipeline completa

```bash
make run
```

Esto ejecuta la inyección de ataques, los experimentos y la generación de gráficos.

Si los experimentos ya fueron ejecutados y solo se desean volver a generar los gráficos —por ejemplo, después de modificar estilos, títulos o ejes en `run_experiments.py`— se puede ejecutar:

```bash
make run-plots
```

---

### Opción B: Ejecución manual, sin `make`

#### 1. Compilación manual con C++17

```bash
g++ -O3 -std=c++17 -Wall pcap2bin.cpp -o pcap2bin
g++ -O3 -std=c++17 -Wall exact_hh.cpp -o exact_hh
g++ -O3 -std=c++17 -Wall tarea1.cpp -o tarea1
```

#### 2. Preparación de la traza base

```bash
curl -L -C - -O https://mawi.wide.ad.jp/mawi/samplepoint-F/2018/201812031400.pcap.gz
zcat 201812031400.pcap.gz | ./pcap2bin > traza.bin
```

#### 3. Inyección de ataques

**Ataque DDoS:**

```bash
python3 inject_attack.py ddos --base traza.bin --out traza_ddos.bin --gt gt_ddos.json --start 300 --duration 30 --pps 10000 --sources 4000 --seed 42
```

**Ataque Scan:**

```bash
python3 inject_attack.py scan --base traza.bin --out traza_scan.bin --gt gt_scan.json --start 300 --duration 30 --pps 8000 --dst-count 60000 --seed 42
```

#### 4. Ejecución manual de los binarios

**Actividad 1 — Estimación de frecuencia:**

```bash
./tarea1 traza.bin --mode estimate --key src --sketch cms -w 1024 --query 198.18.0.7 --out out/est.csv
```

**Actividad 2 — Detección de Heavy Hitters:**

```bash
./tarea1 traza_ddos.bin --mode detect --key dst --sketch cs -w 4096 --query <IP_victima> --out out/detect_ddos_cs_w4096.csv
```

**Actividad 3 — Estimación de variación de frecuencia Δf:**

```bash
./tarea1 traza_scan.bin --mode delta --key src --sketch cs -w 1024 --query <IP_atacante> --out out/delta_scan.csv
```

#### 5. Generación manual de gráficos y resumen

Para ejecutar el orquestador sin volver a ejecutar las simulaciones de C++:

```bash
python3 run_experiments.py --only-plots
```

---

## 4. Salidas generadas

Al finalizar el pipeline mediante `make run` o `run_experiments.py`, se generan las siguientes carpetas y archivos:

```text
out/
├── exact_ddos.csv
├── exact_scan.csv
├── detect_ddos_cms_w256.csv
├── detect_ddos_cms_w1024.csv
├── ...
├── delta_ddos.csv
└── delta_scan.csv

figures/
├── freq_ddos.png
├── freq_scan.png
├── delta_ddos.png
└── delta_scan.png

results/
└── summary.csv
```

### `out/`

Contiene los CSV correspondientes a las distintas corridas, incluyendo:

* `exact_ddos.csv`: Ground truth del ataque DDoS.
* `exact_scan.csv`: Ground truth del ataque Scan.
* `detect_ddos_cms_w256.csv`, `detect_ddos_cms_w1024.csv`, etc.
* `delta_ddos.csv`: Δf exacto vs. CS vs. CMS-mediana.
* `delta_scan.csv`.

### `figures/`

Contiene los gráficos generados:

* `freq_ddos.png`: Frecuencia exacta vs. estimada (6 curvas con Zoom).
* `freq_scan.png`.
* `delta_ddos.png`: Cambio de frecuencia Δf y error absoluto.
* `delta_scan.png`.

### `results/`

Contiene:

* `summary.csv`: Tabla comparativa de MRE, latencia y memoria por `(ataque, sketch, w)`.

---

## 5. Decisiones de diseño

### 5.1. Un solo tipo de clave (128 bits)

Todas las claves se representan como `unsigned __int128`. De esta forma, el driver utiliza una sola tabla hash y un solo tipo de sketch para `src`, `dst`, `src24`, `src16` y `5tuple`.

Las claves de IP utilizan solamente los 32 bits bajos, mientras que la 5-tupla utiliza los 104 bits útiles:

* `src`: 32 bits
* `dst`: 32 bits
* `sport`: 16 bits
* `dport`: 16 bits
* `proto`: 8 bits

**Por qué:** Evita duplicar la lógica para cada tipo de clave y responde directamente al requerimiento de utilizar la misma estructura de ventana para CMS y CS.

### 5.2. Alineación de subventanas

La subventana de un paquete con timestamp `ts` se calcula como:

```text
q(ts) = ceil((ts - t0) / p)    con q >= 1
```

Un paquete que cae exactamente en un borde (`ts = t0 + k * p`) tiene `q = k`, correspondiendo a la subventana que termina en ese borde.

**Por qué `ceil` y no `floor + 1`:** Con `floor(dt/p) + 1`, un paquete en el borde cae en la subventana que empieza en dicho borde. Esto desalinea el anillo y produce desfases de una subventana al salir el ataque de la ventana activa.

### 5.3. Rotación del anillo

Al evaluar en `tau_j`:

1. Cargar los paquetes hasta `tau_j` (entra `S_j`).
2. Expirar la subventana más antigua (`S_{j-m}`).

Se eligió cargar primero para que `q_loaded` avance adecuadamente y `expire_oldest()` tenga la información necesaria para decidir cuándo rotar sin desfases.

### 5.4. Precarga

Antes de la primera evaluación (`tau_0 = t_0 + W`), se cargan los paquetes de `(t0, t0 + W]`, distribuyéndolos mediante `subwindow_of(ts)` entre las `m` ranuras del anillo.

Al llegar a `tau_0`, el anillo queda completamente poblado.

### 5.5. Hasher explícito para `__int128`

Dado que `std::unordered_map<__int128, T>` no compila de manera estándar en GCC, se define un functor `KeyHash` utilizando SplitMix64 sobre las dos mitades del entero de 128 bits.

### 5.6. Hash de los sketches

Se implementan dos funciones deterministas basadas en SplitMix64:

* `hash_pos(k, r, w)`: Mapea a una posición `h_r(k)` en `[0, w)` para la fila `r`.
* `hash_sign(k, r)`: Retorna un signo `s_r(k)` en `{-1, +1}` para la fila `r`.

### 5.7. Estimadores

* **CMS:** `min_j C[j][h_j(k)]`, truncado inferiormente a `0`.
* **CS:** `mediana_j (s_j(k) * C[j][h_j(k)])`, sin truncar, fundamental para permitir valores negativos en `Δf`.
* **CMS-mediana:** `mediana_j C[j][h_j(k)]`, sin multiplicar por signo.

### 5.8. Umbral de Heavy Hitter

```text
T_j = ceil(phi * N_j)
```

Donde `N_j` se mantiene exactamente mediante un anillo escalar paralelo.

Si `T_j = 0`, se ajusta a `1`.

---

## 6. Verificación obligatoria de `N_j`

Para verificar que el anillo escalar calcula de forma exacta el volumen total de paquetes `N_j`, este debe coincidir con la salida de `exact_hh`.

### Obtener `N_j` con `exact_hh`

```bash
./exact_hh traza.bin --key src -W 60 --delta 10 --phi 0.01 --query 0.0.0.0 --out-query out/exact_N.csv
```

### Obtener `N_j` con `tarea1`

```bash
./tarea1 traza.bin --mode estimate --key src --sketch cms -w 256 --query 0.0.0.0 --out out/est_N.csv
```

### Comparación mediante Python

```bash
python3 - <<'PY'
import pandas as pd

a = pd.read_csv("out/exact_N.csv")["N"].values
b = pd.read_csv("out/est_N.csv")["N"].values

n = min(len(a), len(b))

print(
    "Coinciden totalmente:",
    (a[:n] == b[:n]).all(),
    "| Ventanas comparadas:",
    n
)
PY
```
## 7. Preguntas obligatorias del informe

### 7.1. ¿Por qué la linealidad permite mantener la ventana con costo independiente de la cantidad de paquetes que permanecen en ella?

La linealidad permite representar la ventana completa como la suma de sus `m` subventanas. Al avanzar una subventana, no es necesario recorrer nuevamente todos los paquetes de la ventana: basta con restar la subventana que expira y sumar la nueva:

```text
A_{j+1} = A_j - S_{j-m+1} + S_{j+1}
```

Por lo tanto, en cada rotación solo se actualizan los contadores asociados a dos subventanas. Para un sketch de `d` filas y ancho `w`, esto requiere `2 * d * w` actualizaciones, dando una complejidad de `O(d * w)`, independiente de la cantidad de paquetes contenidos en la ventana.

### 7.2. ¿Qué diferencias observan entre el error de CMS y CS al reducir `w`?

Al reducir `w`, aumenta la probabilidad de colisiones entre claves. En CMS, estas colisiones solo pueden aumentar las estimaciones, por lo que el error tiende a manifestarse como una mayor sobreestimación.

En CS, las funciones de signo permiten que las contribuciones de las colisiones se cancelen en esperanza. Por ello, al reducir `w` el estimador sigue siendo insesgado, pero aumenta su varianza y, por tanto, puede presentar errores de mayor magnitud y variaciones no monótonas.

### 7.3. ¿Cuál de los dos ataques se detecta con mayor claridad y por qué la definición de la clave es distinta para DDoS y Scan?

La claridad de la detección depende de cómo se agrupa el tráfico mediante la clave. El ataque DDoS concentra el tráfico hacia una misma víctima, por lo que la clave `dst` permite agrupar las múltiples fuentes bajo una misma dirección de destino.

En cambio, el ataque Scan se caracteriza por un emisor que genera tráfico hacia múltiples destinos. Por ello, la clave `src` permite agrupar el tráfico generado por el atacante independientemente de los destinos contactados.

Así, cada ataque se analiza con la clave que concentra de mejor forma el comportamiento que se busca detectar: `dst` para DDoS y `src` para Scan.

### 7.4. ¿Qué información adicional entrega `Δf_j(x) = f_j(x) - f_{j-1}(x)` respecto de observar solo la frecuencia de la ventana actual?

La frecuencia `f_j(x)` indica cuánto tráfico de la clave `x` existe en la ventana actual, pero no muestra directamente cómo cambió respecto de la ventana anterior.

En cambio, `Δf_j(x)` permite identificar esos cambios: un valor positivo indica un aumento de frecuencia, mientras que un valor negativo indica una disminución. Esto permite identificar con mayor claridad la entrada y salida de un ataque, que se manifiestan respectivamente como un aumento y una disminución abruptos de la frecuencia.

### 7.5. Compare `Δcf^{CS}_j(x)` y `Δcf^{CMS-med}_j(x)`. ¿Por qué CountSketch puede utilizar su estimador habitual, mientras que en CMS se reemplaza el mínimo por una mediana y se pierden las garantías estándar?

CountSketch puede aplicar directamente su estimador habitual a la diferencia entre subventanas porque sus contadores utilizan signos `+1` y `-1`. Al restar subventanas, estas contribuciones conservan la estructura necesaria para que el estimador basado en la mediana siga siendo aplicable a `Δf`.

En CMS, el estimador habitual utiliza el mínimo entre las filas y depende de que las frecuencias sean no negativas. Al calcular diferencias entre subventanas, los valores pueden ser negativos, por lo que el mínimo deja de ser un estimador adecuado. Por ello se utiliza una mediana de las filas (`CMS-mediana`) para estimar la diferencia.

Sin embargo, esta modificación no conserva las garantías estándar de Count-Min Sketch, ya que dichas garantías dependen de las propiedades del estimador basado en el mínimo y de la no negatividad de las frecuencias.
