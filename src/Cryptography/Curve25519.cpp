#include "Cryptography/Curve25519.h"

#include <cstring>
#include <iomanip>
#include <sstream>

namespace Xale::Cryptography
{
    // ----------------------------------------------------------------
    //  Field element helpers  (radix-2^51, 5 limbs)
    //
    //  p = 2^255 - 19
    //
    //  Each limb fits in 51 bits for lazy reduction; products fit
    //  in 128-bit intermediates (max ~2^102 per limb product).
    // ----------------------------------------------------------------

    static constexpr std::uint64_t MASK51 = (1ULL << 51) - 1;

    Curve25519::Fe Curve25519::feZero()
    {
        return Fe{{ 0, 0, 0, 0, 0 }};
    }

    Curve25519::Fe Curve25519::feOne()
    {
        return Fe{{ 1, 0, 0, 0, 0 }};
    }

    // ---------- little-endian 32 bytes → 5×51-bit limbs ----------
    Curve25519::Fe Curve25519::feFromBytes(const std::uint8_t in[32])
    {
        // Read 256 bits little-endian, split into 51-bit limbs.
        auto load8 = [](const std::uint8_t* p) -> std::uint64_t {
            return  static_cast<std::uint64_t>(p[0])
                 | (static_cast<std::uint64_t>(p[1]) << 8)
                 | (static_cast<std::uint64_t>(p[2]) << 16)
                 | (static_cast<std::uint64_t>(p[3]) << 24)
                 | (static_cast<std::uint64_t>(p[4]) << 32)
                 | (static_cast<std::uint64_t>(p[5]) << 40)
                 | (static_cast<std::uint64_t>(p[6]) << 48)
                 | (static_cast<std::uint64_t>(p[7]) << 56);
        };

        Fe f;
        f.v[0] =  load8(in)       & MASK51;
        f.v[1] = (load8(in +  6) >> 3) & MASK51;
        f.v[2] = (load8(in + 12) >> 6) & MASK51;
        f.v[3] = (load8(in + 19) >> 1) & MASK51;
        f.v[4] = (load8(in + 24) >> 12) & MASK51;
        return f;
    }

    // ---------- 5×51-bit limbs → little-endian 32 bytes ----------
    void Curve25519::feToBytes(std::uint8_t out[32], const Fe& h)
    {
        // Full reduction mod p = 2^255 - 19.
        Fe f = h;

        // Propagate carries
        for (int pass = 0; pass < 2; ++pass)
        {
            for (int i = 0; i < 4; ++i)
            {
                std::uint64_t carry = f.v[i] >> 51;
                f.v[i] &= MASK51;
                f.v[i + 1] += carry;
            }
            std::uint64_t carry = f.v[4] >> 51;
            f.v[4] &= MASK51;
            f.v[0] += carry * 19;
        }

        // Final carry chain
        for (int i = 0; i < 4; ++i)
        {
            std::uint64_t carry = f.v[i] >> 51;
            f.v[i] &= MASK51;
            f.v[i + 1] += carry;
        }
        std::uint64_t carry = f.v[4] >> 51;
        f.v[4] &= MASK51;
        f.v[0] += carry * 19;

        // Now subtract p if f >= p.
        // q = (f[0] + 19) >> 51  —  will be 1 if f >= p, else 0.
        std::uint64_t q = (f.v[0] + 19) >> 51;
        for (int i = 1; i < 5; ++i)
            q = (f.v[i] + q) >> 51;

        f.v[0] += 19 * q;

        // Propagate
        for (int i = 0; i < 4; ++i)
        {
            carry = f.v[i] >> 51;
            f.v[i] &= MASK51;
            f.v[i + 1] += carry;
        }
        f.v[4] &= MASK51;

        // Serialize to 32 bytes little-endian
        // 5 limbs × 51 bits = 255 bits
        // Limb layout: v[0] bits 0..50, v[1] bits 51..101, etc.
        std::uint64_t t[5];
        for (int i = 0; i < 5; ++i)
            t[i] = f.v[i];

        out[ 0] = static_cast<std::uint8_t>(t[0]);
        out[ 1] = static_cast<std::uint8_t>(t[0] >> 8);
        out[ 2] = static_cast<std::uint8_t>(t[0] >> 16);
        out[ 3] = static_cast<std::uint8_t>(t[0] >> 24);
        out[ 4] = static_cast<std::uint8_t>(t[0] >> 32);
        out[ 5] = static_cast<std::uint8_t>(t[0] >> 40);
        out[ 6] = static_cast<std::uint8_t>((t[0] >> 48) | (t[1] << 3));
        out[ 7] = static_cast<std::uint8_t>(t[1] >> 5);
        out[ 8] = static_cast<std::uint8_t>(t[1] >> 13);
        out[ 9] = static_cast<std::uint8_t>(t[1] >> 21);
        out[10] = static_cast<std::uint8_t>(t[1] >> 29);
        out[11] = static_cast<std::uint8_t>(t[1] >> 37);
        out[12] = static_cast<std::uint8_t>((t[1] >> 45) | (t[2] << 6));
        out[13] = static_cast<std::uint8_t>(t[2] >> 2);
        out[14] = static_cast<std::uint8_t>(t[2] >> 10);
        out[15] = static_cast<std::uint8_t>(t[2] >> 18);
        out[16] = static_cast<std::uint8_t>(t[2] >> 26);
        out[17] = static_cast<std::uint8_t>(t[2] >> 34);
        out[18] = static_cast<std::uint8_t>(t[2] >> 42);
        out[19] = static_cast<std::uint8_t>((t[2] >> 50) | (t[3] << 1));
        out[20] = static_cast<std::uint8_t>(t[3] >> 7);
        out[21] = static_cast<std::uint8_t>(t[3] >> 15);
        out[22] = static_cast<std::uint8_t>(t[3] >> 23);
        out[23] = static_cast<std::uint8_t>(t[3] >> 31);
        out[24] = static_cast<std::uint8_t>((t[3] >> 39) | (t[4] << 12));
        out[25] = static_cast<std::uint8_t>(t[4] >> 4);
        out[26] = static_cast<std::uint8_t>(t[4] >> 12);
        out[27] = static_cast<std::uint8_t>(t[4] >> 20);
        out[28] = static_cast<std::uint8_t>(t[4] >> 28);
        out[29] = static_cast<std::uint8_t>(t[4] >> 36);
        out[30] = static_cast<std::uint8_t>(t[4] >> 44);
        out[31] = static_cast<std::uint8_t>(t[4] >> 52);  // top 3 bits (255 - 4*51 = 51, but reduced < 2^255)
    }

    // ---------- field addition ----------
    Curve25519::Fe Curve25519::feAdd(const Fe& a, const Fe& b)
    {
        Fe r;
        for (int i = 0; i < 5; ++i)
            r.v[i] = a.v[i] + b.v[i];
        return r;
    }

    // ---------- field subtraction ----------
    Curve25519::Fe Curve25519::feSub(const Fe& a, const Fe& b)
    {
        // Add 2*p to avoid underflow before subtracting.
        // 2*p per limb: 2*(2^255 - 19) split over 5 limbs.
        static constexpr std::uint64_t two_p[5] = {
            0xFFFFFFFFFFFDA, // 2*(2^51 - 19) = 2^52 - 38
            0xFFFFFFFFFFFFE, // 2*(2^51 - 1)  = 2^52 - 2
            0xFFFFFFFFFFFFE,
            0xFFFFFFFFFFFFE,
            0xFFFFFFFFFFFFE
        };

        Fe r;
        for (int i = 0; i < 5; ++i)
            r.v[i] = (a.v[i] + two_p[i]) - b.v[i];
        return r;
    }

    // ---------- field multiplication ----------
    Curve25519::Fe Curve25519::feMul(const Fe& a, const Fe& b)
    {
        // Schoolbook multiply of 5×51-bit limbs with reduction by 19.
        // Products fit in 128 bits; using __uint128_t.
        using u128 = unsigned __int128;

        const std::uint64_t* f = a.v;
        const std::uint64_t* g = b.v;

        // Pre-multiply g[1..4] by 19 for modular wraparound
        std::uint64_t g19_1 = g[1] * 19;
        std::uint64_t g19_2 = g[2] * 19;
        std::uint64_t g19_3 = g[3] * 19;
        std::uint64_t g19_4 = g[4] * 19;

        u128 t0 = static_cast<u128>(f[0]) * g[0]
                 + static_cast<u128>(f[1]) * g19_4
                 + static_cast<u128>(f[2]) * g19_3
                 + static_cast<u128>(f[3]) * g19_2
                 + static_cast<u128>(f[4]) * g19_1;

        u128 t1 = static_cast<u128>(f[0]) * g[1]
                 + static_cast<u128>(f[1]) * g[0]
                 + static_cast<u128>(f[2]) * g19_4
                 + static_cast<u128>(f[3]) * g19_3
                 + static_cast<u128>(f[4]) * g19_2;

        u128 t2 = static_cast<u128>(f[0]) * g[2]
                 + static_cast<u128>(f[1]) * g[1]
                 + static_cast<u128>(f[2]) * g[0]
                 + static_cast<u128>(f[3]) * g19_4
                 + static_cast<u128>(f[4]) * g19_3;

        u128 t3 = static_cast<u128>(f[0]) * g[3]
                 + static_cast<u128>(f[1]) * g[2]
                 + static_cast<u128>(f[2]) * g[1]
                 + static_cast<u128>(f[3]) * g[0]
                 + static_cast<u128>(f[4]) * g19_4;

        u128 t4 = static_cast<u128>(f[0]) * g[4]
                 + static_cast<u128>(f[1]) * g[3]
                 + static_cast<u128>(f[2]) * g[2]
                 + static_cast<u128>(f[3]) * g[1]
                 + static_cast<u128>(f[4]) * g[0];

        // Carry propagation
        u128 c;
        c = t0 >> 51; t1 += c; t0 &= MASK51;
        c = t1 >> 51; t2 += c; t1 &= MASK51;
        c = t2 >> 51; t3 += c; t2 &= MASK51;
        c = t3 >> 51; t4 += c; t3 &= MASK51;
        c = t4 >> 51; t0 += c * 19; t4 &= MASK51;
        // One more carry from t0 in case c*19 overflowed into t0
        c = t0 >> 51; t1 += c; t0 &= MASK51;

        Fe r;
        r.v[0] = static_cast<std::uint64_t>(t0);
        r.v[1] = static_cast<std::uint64_t>(t1);
        r.v[2] = static_cast<std::uint64_t>(t2);
        r.v[3] = static_cast<std::uint64_t>(t3);
        r.v[4] = static_cast<std::uint64_t>(t4);
        return r;
    }

    // ---------- field squaring ----------
    Curve25519::Fe Curve25519::feSquare(const Fe& a)
    {
        using u128 = unsigned __int128;  
        const std::uint64_t* f = a.v;

        std::uint64_t f0_2 = 2 * f[0];
        std::uint64_t f1_2 = 2 * f[1];
        std::uint64_t f2_2 = 2 * f[2];
        std::uint64_t f3_2 = 2 * f[3];

        std::uint64_t f3_19 = 19 * f[3];
        std::uint64_t f4_19 = 19 * f[4];

        u128 t0 = static_cast<u128>(f[0])  * f[0]
                 + static_cast<u128>(f1_2)  * f4_19
                 + static_cast<u128>(f2_2)  * f3_19;

        u128 t1 = static_cast<u128>(f0_2)  * f[1]
                 + static_cast<u128>(f2_2)  * f4_19
                 + static_cast<u128>(f[3])  * f3_19;

        u128 t2 = static_cast<u128>(f0_2)  * f[2]
                 + static_cast<u128>(f[1])  * f[1]
                 + static_cast<u128>(f3_2)  * f4_19;

        u128 t3 = static_cast<u128>(f0_2)  * f[3]
                 + static_cast<u128>(f1_2)  * f[2]
                 + static_cast<u128>(f[4])  * f4_19;

        u128 t4 = static_cast<u128>(f0_2)  * f[4]
                 + static_cast<u128>(f1_2)  * f[3]
                 + static_cast<u128>(f[2])  * f[2];

        // Carry propagation
        u128 c;
        c = t0 >> 51; t1 += c; t0 &= MASK51;
        c = t1 >> 51; t2 += c; t1 &= MASK51;
        c = t2 >> 51; t3 += c; t2 &= MASK51;
        c = t3 >> 51; t4 += c; t3 &= MASK51;
        c = t4 >> 51; t0 += c * 19; t4 &= MASK51;
        c = t0 >> 51; t1 += c; t0 &= MASK51;

        Fe r;
        r.v[0] = static_cast<std::uint64_t>(t0);
        r.v[1] = static_cast<std::uint64_t>(t1);
        r.v[2] = static_cast<std::uint64_t>(t2);
        r.v[3] = static_cast<std::uint64_t>(t3);
        r.v[4] = static_cast<std::uint64_t>(t4);
        return r;
    }

    // ---------- field inversion via Fermat's little theorem ----------
    // z^(-1) = z^(p-2)  where p = 2^255 - 19
    // p - 2 = 2^255 - 21
    // Exponentiation chain from djb's ref10.
    Curve25519::Fe Curve25519::feInvert(const Fe& z)
    {
        Fe t0, t1, t2, t3;

        // Addition chain for z^(p-2), p-2 = 2^255 - 21

        // z^2
        t0 = feSquare(z);
        // z8  = z2^2          = z^4
        t1 = feSquare(t0);
        // z8  = z4^2          = z^8
        t1 = feSquare(t1);
        // z9  = z8 * z1       = z^9
        t1 = feMul(t1, z);
        // z11 = z9 * z2       = z^11
        t0 = feMul(t1, t0);
        // z22 = z11^2         = z^22
        t2 = feSquare(t0);
        // z_5_0 = z22 * z9    = z^(22+9) = z^31 = z^(2^5-1)
        t1 = feMul(t2, t1);

        // z^(2^10 - 1)
        t2 = feSquare(t1);
        for (int i = 1; i < 5; ++i)
            t2 = feSquare(t2);
        t1 = feMul(t2, t1); // z^(2^10-1)

        // z^(2^20 - 1)
        t2 = feSquare(t1);
        for (int i = 1; i < 10; ++i)
            t2 = feSquare(t2);
        t2 = feMul(t2, t1); // z^(2^20-1)

        // z^(2^40 - 1)
        t3 = feSquare(t2);
        for (int i = 1; i < 20; ++i)
            t3 = feSquare(t3);
        t2 = feMul(t3, t2); // z^(2^40-1)

        // z^(2^50 - 1)
        t2 = feSquare(t2);
        for (int i = 1; i < 10; ++i)
            t2 = feSquare(t2);
        t1 = feMul(t2, t1); // z^(2^50-1)

        // z^(2^100 - 1)
        t2 = feSquare(t1);
        for (int i = 1; i < 50; ++i)
            t2 = feSquare(t2);
        t2 = feMul(t2, t1); // z^(2^100-1)

        // z^(2^200 - 1)
        t3 = feSquare(t2);
        for (int i = 1; i < 100; ++i)
            t3 = feSquare(t3);
        t2 = feMul(t3, t2); // z^(2^200-1)

        // z^(2^250 - 1)
        t2 = feSquare(t2);
        for (int i = 1; i < 50; ++i)
            t2 = feSquare(t2);
        t1 = feMul(t2, t1); // z^(2^250-1)

        // z^(2^255 - 19) = z^(p-2)
        t1 = feSquare(t1);   // z^(2^251-2)
        t1 = feSquare(t1);   // z^(2^252-4)
        t1 = feSquare(t1);   // z^(2^253-8)
        t1 = feSquare(t1);   // z^(2^254-16)
        t1 = feSquare(t1);   // z^(2^255-32)
        t0 = feMul(t1, t0);  // z^(2^255-32+11) = z^(2^255-21) = z^(p-2)

        return t0;
    }

    // ----------------------------------------------------------------
    //  Scalar clamping (RFC 7748 §5)
    // ----------------------------------------------------------------
    void Curve25519::clampScalar(std::uint8_t s[32])
    {
        s[0]  &= 248;    // clear 3 low bits
        s[31] &= 127;    // clear high bit
        s[31] |= 64;     // set bit 254
    }

    // ----------------------------------------------------------------
    //  X25519 Montgomery ladder  (RFC 7748 §5)
    // ----------------------------------------------------------------
    std::array<std::uint8_t, Curve25519::_pointSize> Curve25519::x25519(
        const std::uint8_t* scalar,
        const std::uint8_t* point)
    {
        std::uint8_t k[32];
        std::memcpy(k, scalar, 32);
        clampScalar(k);

        Fe u = feFromBytes(point);
        Fe x_1 = u;
        Fe x_2 = feOne();
        Fe z_2 = feZero();
        Fe x_3 = u;
        Fe z_3 = feOne();
        std::uint8_t swap = 0;

        // Montgomery ladder, 255 iterations (bit 254 down to bit 0)
        for (int t = 254; t >= 0; --t)
        {
            std::uint8_t k_t = (k[t >> 3] >> (t & 7)) & 1;
            swap ^= k_t;

            // Constant-time conditional swap
            for (int i = 0; i < 5; ++i)
            {
                std::uint64_t mask = static_cast<std::uint64_t>(0) - static_cast<std::uint64_t>(swap);
                std::uint64_t dummy = mask & (x_2.v[i] ^ x_3.v[i]);
                x_2.v[i] ^= dummy;
                x_3.v[i] ^= dummy;
                dummy = mask & (z_2.v[i] ^ z_3.v[i]);
                z_2.v[i] ^= dummy;
                z_3.v[i] ^= dummy;
            }
            swap = k_t;

            Fe A  = feAdd(x_2, z_2);
            Fe AA = feSquare(A);
            Fe B  = feSub(x_2, z_2);
            Fe BB = feSquare(B);
            Fe E  = feSub(AA, BB);
            Fe C  = feAdd(x_3, z_3);
            Fe D  = feSub(x_3, z_3);
            Fe DA = feMul(D, A);
            Fe CB = feMul(C, B);

            x_3 = feSquare(feAdd(DA, CB));
            z_3 = feMul(x_1, feSquare(feSub(DA, CB)));
            x_2 = feMul(AA, BB);

            // a24 = 121666 for Curve25519 (a24 = (A-2)/4 where A=486662)
            Fe a24;
            a24.v[0] = 121666;
            a24.v[1] = 0;
            a24.v[2] = 0;
            a24.v[3] = 0;
            a24.v[4] = 0;

            z_2 = feMul(E, feAdd(AA, feMul(a24, E)));
        }

        // Final conditional swap
        for (int i = 0; i < 5; ++i)
        {
            std::uint64_t mask = static_cast<std::uint64_t>(0) - static_cast<std::uint64_t>(swap);
            std::uint64_t dummy = mask & (x_2.v[i] ^ x_3.v[i]);
            x_2.v[i] ^= dummy;
            x_3.v[i] ^= dummy;
            dummy = mask & (z_2.v[i] ^ z_3.v[i]);
            z_2.v[i] ^= dummy;
            z_3.v[i] ^= dummy;
        }

        // Result = x_2 / z_2 = x_2 * z_2^(-1)
        Fe result = feMul(x_2, feInvert(z_2));

        std::array<std::uint8_t, _pointSize> out;
        feToBytes(out.data(), result);
        return out;
    }

    std::array<std::uint8_t, Curve25519::_pointSize> Curve25519::x25519(
        const std::array<std::uint8_t, _scalarSize>& scalar,
        const std::array<std::uint8_t, _pointSize>& point)
    {
        return x25519(scalar.data(), point.data());
    }

    // ----------------------------------------------------------------
    //  X25519 base-point multiplication (base point u = 9)
    // ----------------------------------------------------------------
    std::array<std::uint8_t, Curve25519::_pointSize> Curve25519::x25519Base(
        const std::uint8_t* scalar)
    {
        static constexpr std::uint8_t basePoint[32] = {
            9, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0
        };
        return x25519(scalar, basePoint);
    }

    std::array<std::uint8_t, Curve25519::_pointSize> Curve25519::x25519Base(
        const std::array<std::uint8_t, _scalarSize>& scalar)
    {
        return x25519Base(scalar.data());
    }

    // ----------------------------------------------------------------
    //  Utility
    // ----------------------------------------------------------------
    std::string Curve25519::toHex(const std::array<std::uint8_t, _pointSize>& data)
    {
        std::ostringstream oss;
        for (std::size_t i = 0; i < data.size(); ++i)
            oss << std::hex << std::setfill('0') << std::setw(2)
                << static_cast<int>(data[i]);
        return oss.str();
    }
}

