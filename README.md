# Tarea 1 2026 — CMS y CountSketch en ventana deslizante

**Curso:** Tópicos en Grandes Volúmenes de Datos  
**Traza:** MAWI samplepoint-F, 2018-12-03 14:00 JST  
**URL:** https://mawi.wide.ad.jp/mawi/samplepoint-F/2018/201812031400.pcap.gz  
**Semilla de los ataques:** 42  

---

## 1. Estructura del proyecto

| Archivo | Origen | Descripción |
|---|---|---|
| pcap2bin.cpp | entregado | Convierte pcap -> registros de 24 B |
| exact_hh.cpp | entregado | Ground truth exacto por ventana |
| inject_attack.py | entregado | Inyecta ataques de tráfico sintético (DDoS y Scan) |
| sketches.hpp | nuevo | Implementación de Count-Min Sketch y CountSketch |
| tarea1.cpp | nuevo | Driver principal con la ventana deslizante y anillo |
| run_experiments.py | nuevo | Orquesta la pipeline de experimentos y genera gráficos |
| Makefile | nuevo | Reglas de compilación y ejecución (all, run, run-plots, clean) |

---

## 2. Guía de Ejecución

### Opción A: Ejecución mediante Makefile (Recomendado)

El Makefile automatiza la compilación, descarga de datos, procesamiento y generación de gráficos.

# 1. Compilar los binarios en C++ (pcap2bin, exact_hh, tarea1)
make all

# 2. Descargar la traza MAWI desde el repositorio oficial
curl -L -C - -O https://mawi.wide.ad.jp/mawi/samplepoint-F/2018/201812031400.pcap.gz

# 3. Convertir la traza pcap.gz a formato binario (24 B/registro)
zcat 201812031400.pcap.gz | ./pcap2bin > traza.bin

# 4. Ejecutar la pipeline completa (Inyección + Experimentos + Gráficos)
make run

Si ya ejecutaste los experimentos y solo deseas volver a generar los gráficos (por ejemplo, tras modificar estilos, títulos o ejes en run_experiments.py), ejecuta:

make run-plots

---

### Opción B: Ejecución Manual Paso a Paso (Sin make)

Si prefieres compilar y correr cada módulo de forma individual sin utilizar make:

#### 1. Compilación manual con C++17
g++ -O3 -std=c++17 -Wall pcap2bin.cpp -o pcap2bin
g++ -O3 -std=c++17 -Wall exact_hh.cpp -o exact_hh
g++ -O3 -std=c++17 -Wall tarea1.cpp -o tarea1

#### 2. Preparación de la traza base
curl -L -C - -O https://mawi.wide.ad.jp/mawi/samplepoint-F/2018/201812031400.pcap.gz
zcat 201812031400.pcap.gz | ./pcap2bin > traza.bin

#### 3. Inyección de ataques (Python)
# Generar traza con ataque DDoS
python3 inject_attack.py ddos --base traza.bin --out traza_ddos.bin --gt gt_ddos.json --start 300 --duration 30 --pps 10000 --sources 4000 --seed 42

# Generar traza con ataque Scan
python3 inject_attack.py scan --base traza.bin --out traza_scan.bin --gt gt_scan.json --start 300 --duration 30 --pps 8000 --dst-count 60000 --seed 42

#### 4. Ejecución manual de los binarios para consultas individuales
# Estimación de frecuencia (Actividad 1)
./tarea1 traza.bin --mode estimate --key src --sketch cms -w 1024 --query 198.18.0.7 --out out/est.csv

# Detección de Heavy Hitters (Actividad 2)
./tarea1 traza_ddos.bin --mode detect --key dst --sketch cs -w 4096 --query <IP_victima> --out out/detect_ddos_cs_w4096.csv

# Estimación de variación de frecuencia Δf (Actividad 3)
./tarea1 traza_scan.bin --mode delta --key src --sketch cs -w 1024 --query <IP_atacante> --out out/delta_scan.csv

#### 5. Generación manual de gráficos y resumen de resultados
Para ejecutar el orquestador sin relanzar las simulaciones de C++:
python3 run_experiments.py --only-plots

---

## 3. Salidas generadas

Al finalizar el pipeline (make run o mediante run_experiments.py), se habrán creado las siguientes carpetas y archivos:

out/                    CSVs crudos de cada corrida
  exact_ddos.csv        Ground truth del ataque DDoS
  exact_scan.csv        Ground truth del ataque Scan
  detect_ddos_cms_w256.csv
  detect_ddos_cms_w1024.csv
  ...
  delta_ddos.csv        Δf exacto vs CS vs CMS-mediana
  delta_scan.csv

figures/
  freq_ddos.png         Frecuencia exacta vs estimada (6 curvas con Zoom)
  freq_scan.png
  delta_ddos.png        Cambio de frecuencia Δf y error absoluto
  delta_scan.png

results/
  summary.csv           Tabla comparativa de MRE, latencia y memoria por (ataque, sketch, w)

---

## 4. Decisiones de diseño

### 4.1. Un solo tipo de clave (128 bits)
Todas las claves se representan como unsigned __int128. Así el driver usa una sola tabla hash y un solo tipo de sketch para src, dst, src24, src16 y 5tuple. Las claves de IP usan solo los 32 bits bajos; la 5-tupla usa los 104 bits útiles (src 32, dst 32, sport 16, dport 16, proto 8).

Por qué: Evita duplicar la lógica para cada tipo de clave, respondiendo directamente al requerimiento de usar la misma estructura de ventana para CMS y CS.

### 4.2. Alineación de subventanas
La subventana de un paquete con timestamp ts se calcula como:
q(ts) = ceil((ts - t0) / p)  con q >= 1

Un paquete que cae exactamente en un borde (ts = t0 + k * p) tiene q = k, correspondiendo a la subventana que termina en ese borde.

Por qué ceil y no floor + 1: Con floor(dt/p) + 1, un paquete en el borde cae en la subventana que empieza en dicho borde. Esto desalinea el anillo y produce desfases de una subventana al salir el ataque de la ventana activa.

### 4.3. Rotación del anillo
Al evaluar en tau_j:
1. Cargar los paquetes hasta tau_j (entra S_j).
2. Expirar la subventana más antigua (S_{j-m}).

Se eligió cargar primero para que q_loaded avance adecuadamente y expire_oldest() tenga la información necesaria para decidir cuándo rotar sin desfases.

### 4.4. Precarga
Antes de la primera evaluación (tau_0 = t_0 + W), se cargan los paquetes de (t0, t0 + W] distribuyéndolos mediante subwindow_of(ts) entre las m ranuras del anillo. Al llegar a tau_0 el anillo queda completamente poblado.

### 4.5. Hasher explícito para __int128
Dado que std::unordered_map<__int128, T> no compila de manera estándar en GCC, se define un functor KeyHash utilizando SplitMix64 sobre las dos mitades del entero de 128 bits.

### 4.6. Hash de los sketches
Se implementan dos funciones deterministas basadas en SplitMix64:
- hash_pos(k, r, w): Mapea a una posición h_r(k) en [0, w) para la fila r.
- hash_sign(k, r): Retorna un signo s_r(k) en {-1, +1} para la fila r.

### 4.7. Estimadores
- CMS: min_j C[j][h_j(k)], truncado inferiormente a 0.
- CS: mediana_j ( s_j(k) * C[j][h_j(k)] ), sin truncar (fundamental para permitir valores negativos en Δf).
- CMS-mediana: mediana_j C[j][h_j(k)] sin multiplicar por signo.

### 4.8. Umbral de Heavy Hitter
T_j = ceil(phi * N_j)
Donde N_j se mantiene exactamente mediante un anillo escalar paralelo. Si T_j = 0, se ajusta a 1.

---

## 5. Bugs corregidos respecto a versiones preliminares

1. Alineación de subventanas: Cambio de floor(dt/p) + 1 a ceil(dt/p) para evitar meter paquetes de borde en la subventana siguiente.
2. Expiración en anillo (expire_oldest): Se introdujo un puntero explícito q_expire que incrementa una unidad por rotación, resolviendo el error off-by-one en la primera rotación.
3. Manejo de argumentos de CLI: Se reordenó la verificación del parámetro --out para permitir que el indicador --help se imprima correctamente sin arrojar un error de falta de parámetros.
4. Soporte de __int128 en unordered_map: Se integró la estructura KeyHash.

---

## 6. Verificación obligatoria de N_j

Para verificar que el anillo escalar calcula de forma exacta el volumen total de paquetes N_j coincide con la salida de exact_hh:

# Obtenemos N_j con exact_hh
./exact_hh traza.bin --key src -W 60 --delta 10 --phi 0.01 --query 0.0.0.0 --out-query out/exact_N.csv

# Obtenemos N_j con tarea1
./tarea1 traza.bin --mode estimate --key src --sketch cms -w 256 --query 0.0.0.0 --out out/est_N.csv

# Comparación mediante Python
python3 - <<'PY'
import pandas as pd
a = pd.read_csv("out/exact_N.csv")["N"].values
b = pd.read_csv("out/est_N.csv")["N"].values
n = min(len(a), len(b))
print("Coinciden totalmente:", (a[:n] == b[:n]).all(), "| Ventanas comparadas:", n)
PY

---

## 7. Preguntas obligatorias del informe (Guía rápida)

1. Propiedad de Linealidad: A_{j+1} = A_j - S_{j-m+1} + S_{j+1}. Solo se actualizan 2 * d * w contadores por rotación independientemente de la cantidad total de paquetes en la ventana. La complejidad de la rotación es O(d * w).
2. Comportamiento del error al reducir w: Reducir el ancho w incrementa las colisiones. En CMS se traduce en una mayor sobreestimación. En CS la estimación se mantiene insesgada pero aumenta su varianza, pudiendo mostrar variaciones no monótonas en el MRE.
3. Sensibilidad por tipo de clave: El ataque DDoS agrupado hacia una IP de destino destaca sobre la clave dst. El ataque Scan genera una alta frecuencia proveniente de un emisor hacia múltiples destinos, por lo que es detectado nítidamente bajo la clave src.
4. Importancia de la variación (Δf): Δf permite aislar los cambios abruptos de tráfico entre ventanas consecutivas. Produce firmas claras de entrada (pico positivo) y salida (pico negativo) del ataque.
5. Diferencias entre CS y CMS-mediana: Count-Sketch cancela ruidos de colisión en esperanza gracias a sus funciones de signo (+/- 1). Count-Min Sketch no incluye signo; al restar subventanas, aplicar la mediana sin corrección de signo es una heurística que carece de las garantías formales de CS.