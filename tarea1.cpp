// tarea1.cpp -- Driver de la Tarea 1 2026.
//
// Modos:
//   --mode estimate : f exacta vs f estimada (validacion, Actividad 1)
//   --mode detect   : f exacta, f_estimada, HH_exacto, HH_sketch (Actividad 2)
//   --mode delta    : Delta f exacto, CS y CMS-mediana (Actividad 3)
//
// Convencion de la ventana (enunciado seccion 4):
//   t0 = ts del primer paquete.
//   Subventana q cubre (t0 + (q-1)p, t0 + q*p], q >= 1.
//   ranura(q) = (q-1) mod m.
//   Evaluacion j en tau_j = t0 + W + j*p.
//
// ORDEN DE OPERACIONES (critico)
// ------------------------------
// En cada evaluacion tau:
//   1) EXPIRAR la subventana que sale:  q_exp = (tau-t0)/p - m
//   2) CARGAR los paquetes hasta tau (entra la subventana nueva)
//   3) Actualizar el contador exacto (ventana [tau-W, tau])
//
// El orden importa porque la subventana que entra y la que sale comparten
// ranura: ranura(q) = ranura(q - m). Si se carga primero, la ranura contiene
// las dos subventanas mezcladas y al expirar se destruye tambien la nueva.

#include "sketches.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cinttypes>
#include <cmath>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#pragma pack(push, 1)
struct Record {
    uint64_t ts_us;
    uint32_t src, dst;
    uint16_t sport, dport, len;
    uint8_t proto, flags;
};
#pragma pack(pop)
static_assert(sizeof(Record) == 24, "Record debe ocupar 24 B");

enum KeyKind { K_SRC, K_DST, K_SRC24, K_SRC16, K_5TUPLE };

static inline UKey make_key(const Record &r, KeyKind k) {
    switch (k) {
    case K_SRC:   return (UKey)r.src;
    case K_DST:   return (UKey)r.dst;
    case K_SRC24: return (UKey)(r.src & 0xFFFFFF00u);
    case K_SRC16: return (UKey)(r.src & 0xFFFF0000u);
    default: {
        uint64_t hi = ((uint64_t)r.src << 32) | (uint64_t)r.dst;
        uint64_t lo = ((uint64_t)r.sport << 24) | ((uint64_t)r.dport << 8) |
                      (uint64_t)r.proto;
        return ((UKey)hi << 64) | (UKey)lo;
    }
    }
}

struct KeyHash {
    size_t operator()(UKey k) const {
        auto mix = [](uint64_t x) {
            x += 0x9E3779B97F4A7C15ull;
            x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
            x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
            return x ^ (x >> 31);
        };
        return (size_t)(mix((uint64_t)k) ^ mix((uint64_t)(k >> 64)));
    }
};

static bool parse_ipv4(const char *s, uint32_t *out) {
    unsigned a, b, c, d;
    if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    *out = (a << 24) | (b << 16) | (c << 8) | d;
    return true;
}

static std::string key_to_string(UKey k, KeyKind kind) {
    char buf[96], a[16], b[16];
    auto ip = [](uint32_t v, char *out) {
        sprintf(out, "%u.%u.%u.%u", v >> 24, (v >> 16) & 255, (v >> 8) & 255, v & 255);
    };
    if (kind == K_5TUPLE) {
        uint64_t hi = (uint64_t)(k >> 64), lo = (uint64_t)k;
        ip((uint32_t)(hi >> 32), a); ip((uint32_t)hi, b);
        sprintf(buf, "%s:%u->%s:%u/%u", a, (unsigned)((lo >> 24) & 0xFFFF), b,
                (unsigned)((lo >> 8) & 0xFFFF), (unsigned)(lo & 0xFF));
    } else {
        ip((uint32_t)k, a);
        if (kind == K_SRC24)      sprintf(buf, "%s/24", a);
        else if (kind == K_SRC16) sprintf(buf, "%s/16", a);
        else                      sprintf(buf, "%s", a);
    }
    return std::string(buf);
}

struct Trace {
    const Record *r = nullptr; size_t n = 0;
    void *addr = nullptr; size_t bytes = 0;
};

static Trace map_trace(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); exit(1); }
    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); exit(1); }
    if (st.st_size % (off_t)sizeof(Record)) {
        fprintf(stderr, "tamano no multiplo de 24 B\n"); exit(1);
    }
    void *p = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED) { perror("mmap"); exit(1); }
    close(fd);
    madvise(p, st.st_size, MADV_SEQUENTIAL);
    Trace t; t.addr = p; t.bytes = st.st_size;
    t.r = (const Record *)p; t.n = st.st_size / sizeof(Record);
    return t;
}

template <typename SK>
struct SlidingWindow {
    uint32_t m;
    uint32_t d, w;
    uint64_t t0_us, p_us;
    std::vector<SK> sub;         // m sub-sketches (ranuras del anillo)
    std::vector<uint64_t> subN;  // conteo escalar por subventana
    SK A;                        // sketch agregado de la ventana activa
    uint64_t N;                  // N_j exacto (anillo escalar)

    SlidingWindow(uint32_t m_, uint32_t d_, uint32_t w_, uint64_t t0_, uint64_t p_)
        : m(m_), d(d_), w(w_), t0_us(t0_), p_us(p_),
          sub(), subN(m_, 0), A(d_, w_), N(0) {
        sub.reserve(m);
        for (uint32_t i = 0; i < m; ++i) sub.emplace_back(d, w);
    }

    // Subventana q a la que pertenece un paquete con ts.
    // q = ceil((ts - t0)/p), con q >= 1.
    int64_t subwindow_of(uint64_t ts) const {
        uint64_t dt = ts - t0_us;
        int64_t q = (int64_t)((dt + p_us - 1) / p_us);
        if (q < 1) q = 1;
        return q;
    }

    // Ranura del anillo para la subventana q.
    uint32_t slot_of(int64_t q) const {
        return (uint32_t)((q - 1) % (int64_t)m);
    }

    // Un paquete con ts va a la subventana subwindow_of(ts).
    // Se actualiza la ranura, el agregado A y el contador escalar.
    void load_packet(UKey k, uint64_t ts) {
        int64_t q = subwindow_of(ts);
        uint32_t slot = slot_of(q);
        sub[slot].update(k, 1);
        subN[slot] += 1;
        A.update(k, 1);
        N += 1;
    }

    // Expira la subventana q_exp: resta de A, limpia la ranura.
    // El driver llama a esta funcion ANTES de cargar la subventana nueva,
    // porque q_exp y q_entra comparten ranura.
    void expire_subwindow(int64_t q_exp) {
        uint32_t slot = slot_of(q_exp);
        A.add(sub[slot], -1);
        N -= subN[slot];
        sub[slot].clear();
        subN[slot] = 0;
    }
};

static void usage(const char *p) {
    fprintf(stderr,
        "uso: %s TRAZA.bin --mode estimate|detect|delta --out CSV [opciones]\n"
        "  --key src|dst|src24|src16|5tuple  (def. src)\n"
        "  -W SEG           ancho de ventana (def. 60)\n"
        "  --delta SEG      paso entre evaluaciones (def. 10)\n"
        "  --phi F          umbral HH (def. 0.01)\n"
        "  -d D             filas del sketch (def. 5)\n"
        "  -w W             ancho del sketch (def. 1024)\n"
        "  --sketch cms|cs  (def. cms)\n"
        "  --query IP       clave a consultar (repetible)\n"
        "  --max-windows N  cortar tras N ventanas\n", p);
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(argv[0]); return 2; }
    const char *path = argv[1];
    std::string mode = "detect", sketch_name = "cms";
    KeyKind kind = K_SRC;
    double W_s = 60.0, delta_s = 10.0, phi = 0.01;
    uint32_t d = 5, w = 1024;
    std::vector<std::string> query_text;
    const char *out = nullptr;
    size_t max_windows = (size_t)-1;

    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-h" || a == "--help") { usage(argv[0]); return 0; }
        auto next = [&]() -> const char * {
            if (i + 1 >= argc) { fprintf(stderr, "falta valor para %s\n", a.c_str()); exit(2); }
            return argv[++i];
        };
        if (a == "--mode") mode = next();
        else if (a == "--key") {
            std::string k = next();
            if (k == "src") kind = K_SRC;
            else if (k == "dst") kind = K_DST;
            else if (k == "src24") kind = K_SRC24;
            else if (k == "src16") kind = K_SRC16;
            else if (k == "5tuple") kind = K_5TUPLE;
            else { fprintf(stderr, "clave desconocida: %s\n", k.c_str()); return 2; }
        }
        else if (a == "-W") W_s = atof(next());
        else if (a == "--delta") delta_s = atof(next());
        else if (a == "--phi") phi = atof(next());
        else if (a == "-d") d = (uint32_t)atoi(next());
        else if (a == "-w") w = (uint32_t)atoi(next());
        else if (a == "--sketch") sketch_name = next();
        else if (a == "--query") query_text.emplace_back(next());
        else if (a == "--out") out = next();
        else if (a == "--max-windows") max_windows = (size_t)atol(next());
        else { fprintf(stderr, "opcion no reconocida: %s\n", argv[i]); return 2; }
    }
    if (!out) { fprintf(stderr, "--out es obligatorio\n"); return 2; }

    std::vector<UKey> queries;
    for (const std::string &q : query_text) {
        uint32_t ip = 0;
        if (!parse_ipv4(q.c_str(), &ip)) { fprintf(stderr, "IP invalida: %s\n", q.c_str()); return 2; }
        if (kind == K_SRC24) ip &= 0xFFFFFF00u;
        else if (kind == K_SRC16) ip &= 0xFFFF0000u;
        queries.push_back((UKey)ip);
    }

    Trace t = map_trace(path);
    if (t.n == 0) { fprintf(stderr, "traza vacia\n"); return 1; }

    const uint64_t t0 = t.r[0].ts_us;
    const uint64_t W_us = (uint64_t)(W_s * 1e6);
    const uint64_t p_us = (uint64_t)(delta_s * 1e6);
    if (W_us == 0 || p_us == 0 || W_us % p_us != 0) {
        fprintf(stderr, "W debe ser multiplo de delta\n"); return 2;
    }
    const uint32_t m = (uint32_t)(W_us / p_us);
    bool use_cs = (sketch_name == "cs");

    FILE *fo = fopen(out, "w");
    if (!fo) { perror("fopen out"); return 1; }

    if (mode == "estimate")
        fprintf(fo, "win,tau_us,t_rel_s,N,N_ring,key,exact,est\n");
    else if (mode == "detect")
        fprintf(fo, "win,tau_us,t_rel_s,N,N_ring,key,exact,est,thr,hh_exact,hh_sketch\n");
    else
        fprintf(fo, "win,tau_us,t_rel_s,N,N_ring,key,exact,est_cs,est_cmsmed,df_exact,df_cs,df_cmsmed\n");

    if (use_cs) {
        SlidingWindow<CountSketch> ring(m, d, w, t0, p_us);
        SlidingWindow<CountMinSketch> *ring_cms = nullptr;
        if (mode == "delta") ring_cms = new SlidingWindow<CountMinSketch>(m, d, w, t0, p_us);

        std::unordered_map<UKey, uint64_t, KeyHash> exact_cnt, prev_f;
        std::unordered_map<UKey, int64_t, KeyHash> prev_est_cs, prev_est_cms;
        uint64_t exactN = 0;
        size_t i = 0, lo = 0, win = 0;
        const uint64_t t_end = t.r[t.n - 1].ts_us;

        auto feed = [&](const Record &r) {
            UKey k = make_key(r, kind);
            exact_cnt[k] += 1; exactN += 1;
            ring.load_packet(k, r.ts_us);
            if (ring_cms) ring_cms->load_packet(k, r.ts_us);
        };

        // Precarga (t0, t0 + W]
        while (i < t.n && t.r[i].ts_us <= t0 + W_us) { feed(t.r[i]); i++; }

        for (uint64_t tau = t0 + W_us; tau <= t_end; tau += p_us) {
            // FIX #1: EXPIRAR primero, luego CARGAR (orden obligatorio del enunciado).
            int64_t q_tau = (int64_t)((tau - t0) / p_us);
            int64_t q_exp = q_tau - (int64_t)m;
            if (q_exp >= 1) {
                ring.expire_subwindow(q_exp);
                if (ring_cms) ring_cms->expire_subwindow(q_exp);
            }
            // 2) CARGAR paquetes hasta tau
            while (i < t.n && t.r[i].ts_us <= tau) { feed(t.r[i]); i++; }
            // 3) Mantener el contador exacto al dia
            while (lo < i && t.r[lo].ts_us <= tau - W_us) {
                UKey k = make_key(t.r[lo], kind);
                auto it = exact_cnt.find(k);
                if (it != exact_cnt.end() && --(it->second) == 0) exact_cnt.erase(it);
                exactN -= 1; lo++;
            }

            uint64_t thr = (uint64_t)std::ceil(phi * (double)exactN);
            if (thr == 0) thr = 1;

            for (UKey k : queries) {
                auto it = exact_cnt.find(k);
                uint64_t f = (it == exact_cnt.end()) ? 0 : it->second;
                int64_t e_cs  = ring.A.estimate(k);
                // para CMS en modo delta se usa estimate_median,
                // no estimate. Para detect/estimate se usa el minimo estandar.
                int64_t e_cms = ring_cms
                    ? (mode == "delta" ? ring_cms->A.estimate_median(k)
                                       : ring_cms->A.estimate(k))
                    : 0;

                if (mode == "estimate") {
                    fprintf(fo, "%zu,%" PRIu64 ",%.6f,%" PRIu64 ",%" PRIu64
                                ",%s,%" PRIu64 ",%" PRId64 "\n",
                            win, tau, (double)(tau - t0) / 1e6, exactN, ring.N,
                            key_to_string(k, kind).c_str(), f, e_cs);
                } else if (mode == "detect") {
                    fprintf(fo, "%zu,%" PRIu64 ",%.6f,%" PRIu64 ",%" PRIu64
                                ",%s,%" PRIu64 ",%" PRId64
                                ",%" PRIu64 ",%d,%d\n",
                            win, tau, (double)(tau - t0) / 1e6, exactN, ring.N,
                            key_to_string(k, kind).c_str(), f, e_cs, thr,
                            (f >= thr) ? 1 : 0, (e_cs >= (int64_t)thr) ? 1 : 0);
                } else {
                    auto itp = prev_f.find(k);
                    uint64_t fp = (itp == prev_f.end()) ? 0 : itp->second;
                    int64_t df_exact = (int64_t)f - (int64_t)fp;
                    int64_t df_cs  = e_cs  - prev_est_cs[k];
                    int64_t df_cms = e_cms - prev_est_cms[k];
                    // FIX: se imprime e_cs y e_cms (no e_cms dos veces).
                    fprintf(fo, "%zu,%" PRIu64 ",%.6f,%" PRIu64 ",%" PRIu64
                                ",%s,%" PRIu64
                                ",%" PRId64 ",%" PRId64
                                ",%" PRId64 ",%" PRId64 ",%" PRId64 "\n",
                            win, tau, (double)(tau - t0) / 1e6, exactN, ring.N,
                            key_to_string(k, kind).c_str(), f, e_cs, e_cms,
                            df_exact, df_cs, df_cms);
                }
                prev_est_cs[k]  = e_cs;
                prev_est_cms[k] = e_cms;
                prev_f[k] = f;
            }
            if (++win >= max_windows) break;
        }
        delete ring_cms;
    } else {
        SlidingWindow<CountMinSketch> ring(m, d, w, t0, p_us);
        SlidingWindow<CountSketch> *ring_cs = nullptr;
        if (mode == "delta") ring_cs = new SlidingWindow<CountSketch>(m, d, w, t0, p_us);

        std::unordered_map<UKey, uint64_t, KeyHash> exact_cnt, prev_f;
        std::unordered_map<UKey, int64_t, KeyHash> prev_est_cms, prev_est_cs;
        uint64_t exactN = 0;
        size_t i = 0, lo = 0, win = 0;
        const uint64_t t_end = t.r[t.n - 1].ts_us;

        auto feed = [&](const Record &r) {
            UKey k = make_key(r, kind);
            exact_cnt[k] += 1; exactN += 1;
            ring.load_packet(k, r.ts_us);
            if (ring_cs) ring_cs->load_packet(k, r.ts_us);
        };

        while (i < t.n && t.r[i].ts_us <= t0 + W_us) { feed(t.r[i]); i++; }

        for (uint64_t tau = t0 + W_us; tau <= t_end; tau += p_us) {
            // FIX #1: EXPIRAR antes de CARGAR.
            int64_t q_tau = (int64_t)((tau - t0) / p_us);
            int64_t q_exp = q_tau - (int64_t)m;
            if (q_exp >= 1) {
                ring.expire_subwindow(q_exp);
                if (ring_cs) ring_cs->expire_subwindow(q_exp);
            }
            while (i < t.n && t.r[i].ts_us <= tau) { feed(t.r[i]); i++; }
            // FIX #2: borde de salida con < estricto.
            while (lo < i && t.r[lo].ts_us < tau - W_us + 1) {
                UKey k = make_key(t.r[lo], kind);
                auto it = exact_cnt.find(k);
                if (it != exact_cnt.end() && --(it->second) == 0) exact_cnt.erase(it);
                exactN -= 1; lo++;
            }

            uint64_t thr = (uint64_t)std::ceil(phi * (double)exactN);
            if (thr == 0) thr = 1;

            for (UKey k : queries) {
                auto it = exact_cnt.find(k);
                uint64_t f = (it == exact_cnt.end()) ? 0 : it->second;
                // FIX #3: en modo delta, CMS usa estimate_median.
                int64_t e_cms = (mode == "delta")
                    ? ring.A.estimate_median(k)
                    : ring.A.estimate(k);
                int64_t e_cs  = ring_cs ? ring_cs->A.estimate(k) : 0;

                if (mode == "estimate") {
                    fprintf(fo, "%zu,%" PRIu64 ",%.6f,%" PRIu64 ",%" PRIu64
                                ",%s,%" PRIu64 ",%" PRId64 "\n",
                            win, tau, (double)(tau - t0) / 1e6, exactN, ring.N,
                            key_to_string(k, kind).c_str(), f, e_cms);
                } else if (mode == "detect") {
                    fprintf(fo, "%zu,%" PRIu64 ",%.6f,%" PRIu64 ",%" PRIu64
                                ",%s,%" PRIu64 ",%" PRId64
                                ",%" PRIu64 ",%d,%d\n",
                            win, tau, (double)(tau - t0) / 1e6, exactN, ring.N,
                            key_to_string(k, kind).c_str(), f, e_cms, thr,
                            (f >= thr) ? 1 : 0, (e_cms >= (int64_t)thr) ? 1 : 0);
                } else {
                    auto itp = prev_f.find(k);
                    uint64_t fp = (itp == prev_f.end()) ? 0 : itp->second;
                    int64_t df_exact = (int64_t)f - (int64_t)fp;
                    int64_t df_cs  = e_cs  - prev_est_cs[k];
                    int64_t df_cms = e_cms - prev_est_cms[k];
                    // FIX #4: se imprime e_cs y e_cms (antes se repetía e_cms).
                    fprintf(fo, "%zu,%" PRIu64 ",%.6f,%" PRIu64 ",%" PRIu64
                                ",%s,%" PRIu64
                                ",%" PRId64 ",%" PRId64
                                ",%" PRId64 ",%" PRId64 ",%" PRId64 "\n",
                            win, tau, (double)(tau - t0) / 1e6, exactN, ring.N,
                            key_to_string(k, kind).c_str(), f, e_cs, e_cms,
                            df_exact, df_cs, df_cms);
                }
                prev_est_cms[k] = e_cms;
                prev_est_cs[k]  = e_cs;
                prev_f[k] = f;
            }
            if (++win >= max_windows) break;
        }
        delete ring_cs;
    }

    fclose(fo);
    munmap(t.addr, t.bytes);
    return 0;
}