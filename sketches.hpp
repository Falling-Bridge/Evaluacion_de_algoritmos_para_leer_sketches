// ============================================================================
// sketches.hpp -- Count-Min Sketch y CountSketch para la Tarea 1 2026.
// ============================================================================
//
// DISEÑO
// ------
// Ambos sketches exponen la misma interfaz para que el driver de ventana
// deslizante (tarea1.cpp) sea genérico: un solo template sirve para los dos.
//
//   update(k, c)         : suma c al contador (c puede ser negativo cuando se
//                          resta una subventana del agregado)
//   estimate(k)          : valor puntual de la frecuencia de k
//                          CMS: min_j C[j][h_j(k)]   (sobreestima)
//                          CS : median_j s_j(k)*C[j][h_j(k)]  (insesgado)
//   estimate_median(k)   : mediana de las d celdas SIN deshacer signo
//                          (solo se usa en CMS para Δf, seccion 6.3)
//   estimate_signed(k)   : igual que estimate pero sin truncar a 0
//                          (solo se usa en CS para Δf)
//   clear()              : pone la matriz a cero (reutilizar una ranura)
//   add(other, sign)     : this += sign * other. Es LA operacion que hace
//                          posible la ventana deslizante por linealidad:
//                              A  <-  A  -  S_expira
//                              A  <-  A  +  S_nueva
//                          sin recorrer los paquetes de la ventana.
//
// HASH
// ----
// Las claves son de 128 bits (typedef UKey). libstdc++ NO define
// std::hash<__int128>, asi que todo hash se hace con splitmix64 sobre las
// dos mitades. Dos funciones:
//
//   hash_pos(k, r, w)   : posicion h_r(k) en [0, w)   (r = fila, 0..d-1)
//   hash_sign(k, r)     : signo s_r(k) en {-1, +1}    (solo CountSketch)
//
// Son deterministas y no dependen de la implementacion de la STL.
//
// MEMORIA
// -------
// CMS usa uint64_t por celda (necesario: al restar subventanas puede quedar
// temporalmente un valor "negativo" si la ventana esta mal alineada).
// CS usa int64_t porque el signo es parte del algoritmo.
// El anillo de 6 subventanas + el agregado son 7 * d * w celdas por sketch.

#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <algorithm>

typedef unsigned __int128 UKey;

// splitmix64: hash de 64 bits rapido y de calidad. Se usa como bloque basico.
static inline uint64_t splitmix64(uint64_t x) {
    x += 0x9E3779B97F4A7C15ull;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
    return x ^ (x >> 31);
}

// h_r(x) = posicion en [0, w) para la fila r (0-based).
static inline uint32_t hash_pos(UKey k, uint32_t r, uint32_t w) {
    uint64_t lo = (uint64_t)k;
    uint64_t hi = (uint64_t)(k >> 64);
    uint64_t h = splitmix64(lo ^ (0x9E3779B97F4A7C15ull * (uint64_t)(r + 1)));
    h ^= splitmix64(hi + 0xC2B2AE3D27D4EB4Full * (uint64_t)(r + 1));
    return (uint32_t)(h % w);
}

// s_r(x) = signo en {-1, +1} para la fila r. Solo CountSketch.
static inline int hash_sign(UKey k, uint32_t r) {
    uint64_t lo = (uint64_t)k;
    uint64_t hi = (uint64_t)(k >> 64);
    uint64_t h = splitmix64(lo ^ 0xA24BAED4963EE407ull ^ (uint64_t)r)
               ^ splitmix64(hi ^ 0x9FB21C651E98DF25ull ^ (uint64_t)r);
    return (h & 1ull) ? +1 : -1;
}

// ============================================================================
// Count-Min Sketch  (CMS)
// ============================================================================
//
// Matriz d x w de contadores sin signo. Actualizacion:
//     C[j][h_j(k)] += c        para j = 1..d
// Estimacion:
//     f_hat(k) = min_j C[j][h_j(k)]
//
// CMS sobreestima por colisiones. Con c=1 por paquete, esa sobreestimacion
// es exactamente el ruido de las otras claves que caen en las mismas celdas.

class CountMinSketch {
public:
    CountMinSketch(uint32_t d, uint32_t w)
        : d_(d), w_(w), C_((size_t)d * w, 0) {}

    void update(UKey k, int64_t c) {
        for (uint32_t r = 0; r < d_; ++r) {
            uint32_t j = hash_pos(k, r, w_);
            C_[(size_t)r * w_ + j] += c;
        }
    }

    // Estimador estandar: minimo de las d celdas, truncado a 0.
    // El truncamiento protege contra valores negativos que podrian aparecer
    // si la ventana no esta perfectamente alineada; en operacion normal
    // nunca deberia dispararse.
    int64_t estimate(UKey k) const {
        int64_t best = INT64_MAX;
        for (uint32_t r = 0; r < d_; ++r) {
            uint32_t j = hash_pos(k, r, w_);
            int64_t v = (int64_t)C_[(size_t)r * w_ + j];
            if (v < best) best = v;
        }
        return best < 0 ? 0 : best;
    }

    // Estimador mediana, SIN deshacer signo. Solo para Delta f en CMS
    // (seccion 6.3 del enunciado). No conserva las garantias de CMS.
    int64_t estimate_median(UKey k) const {
        std::vector<int64_t> v(d_);
        for (uint32_t r = 0; r < d_; ++r) {
            uint32_t j = hash_pos(k, r, w_);
            v[r] = (int64_t)C_[(size_t)r * w_ + j];
        }
        std::sort(v.begin(), v.end());
        return v[d_ / 2];
    }

    void clear() { std::fill(C_.begin(), C_.end(), 0); }

    // Linealidad: this <- this + sign*other. Con sign=-1 se "resta" una
    // subventana del agregado (A <- A - S_expira).
    void add(const CountMinSketch &other, int sign) {
        for (size_t i = 0; i < C_.size(); ++i)
            C_[i] += (uint64_t)(sign * (int64_t)other.C_[i]);
    }

    uint32_t d() const { return d_; }
    uint32_t w() const { return w_; }
    size_t memory_bytes() const { return C_.size() * sizeof(uint64_t); }

private:
    uint32_t d_, w_;
    std::vector<uint64_t> C_;
};

// ============================================================================
// CountSketch  (CS)
// ============================================================================
//
// Igual estructura que CMS, pero cada fila tiene tambien un hash de signo:
//     C[j][h_j(k)] += s_j(k) * c
// Estimacion (deshaciendo el signo, luego mediana):
//     z_j(k)  = s_j(k) * C[j][h_j(k)]
//     f_hat(k) = median_j z_j(k)
//
// El signo hace que las colisiones se cancelen en esperanza, asi que CS es
// insesgado. A cambio, tiene varianza: por eso se reporta la mediana (robusta)
// y no el minimo.

class CountSketch {
public:
    CountSketch(uint32_t d, uint32_t w)
        : d_(d), w_(w), C_((size_t)d * w, 0) {}

    void update(UKey k, int64_t c) {
        for (uint32_t r = 0; r < d_; ++r) {
            uint32_t j = hash_pos(k, r, w_);
            int s = hash_sign(k, r);
            C_[(size_t)r * w_ + j] += s * c;
        }
    }

    // Estimacion estandar: mediana de s_j(k)*C[j][h_j(k)].
    int64_t estimate(UKey k) const {
        std::vector<int64_t> z(d_);
        for (uint32_t r = 0; r < d_; ++r) {
            uint32_t j = hash_pos(k, r, w_);
            int s = hash_sign(k, r);
            z[r] = s * (int64_t)C_[(size_t)r * w_ + j];
        }
        std::sort(z.begin(), z.end());
        return z[d_ / 2];
    }

    // Para Delta f: mismo estimador, pero SIN truncar a cero (firmado).
    int64_t estimate_signed(UKey k) const { return estimate(k); }

    void clear() { std::fill(C_.begin(), C_.end(), 0); }

    void add(const CountSketch &other, int sign) {
        for (size_t i = 0; i < C_.size(); ++i)
            C_[i] += sign * other.C_[i];
    }

    uint32_t d() const { return d_; }
    uint32_t w() const { return w_; }
    size_t memory_bytes() const { return C_.size() * sizeof(int64_t); }

private:
    uint32_t d_, w_;
    std::vector<int64_t> C_;
};