/* csnippets (c) 2019-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef BINARY_SERIAL_H
#define BINARY_SERIAL_H

/**
 * @defgroup serial
 * @brief RFC 1982 Serial Number Arithmetic.
 * @details Wrap-around arithmetic and comparison for fixed-width serial
 * numbers, as used by DNS SOA serials, TCP sequence numbers, and similar
 * wire protocols. Each value is carried in a uint_fast*_t that may be wider
 * than the serial space, so every result is masked back to the low N bits.
 * Serial numbers form a circular space, so comparison is not a total order:
 * when two values are exactly half the space apart their ordering is
 * undefined (RFC 1982 §3.2), and these helpers report neither less-than nor
 * greater-than for that case.
 * @{
 */

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Add to a 16-bit serial number (RFC 1982 §3.1).
 * @param s The current serial number in [0, 2^16 - 1].
 * @param n The amount to add; results are only defined for n in
 * [0, 2^15 - 1].
 * @return (s + n) modulo 2^16.
 */
static inline uint_fast16_t
serial_add16(const uint_fast16_t s, const uint_fast16_t n)
{
	return (s + n) & UINT16_C(0xFFFF);
}

/**
 * @brief Test whether one 16-bit serial number precedes another
 * (RFC 1982 §3.2).
 * @return true if i1 < i2 in the circular serial space; false if i1 >= i2 or
 * the two are exactly 2^15 apart (undefined ordering).
 */
static inline bool serial_lt16(const uint_fast16_t i1, const uint_fast16_t i2)
{
	const uint_fast16_t d = (uint_fast16_t)(i2 - i1) & UINT16_C(0xFFFF);
	return d != 0 && d < (UINT16_C(1) << 15);
}

/**
 * @brief Test whether one 16-bit serial number follows another
 * (RFC 1982 §3.2).
 * @return true if i1 > i2 in the circular serial space; false if i1 <= i2 or
 * the two are exactly 2^15 apart (undefined ordering).
 */
static inline bool serial_gt16(const uint_fast16_t i1, const uint_fast16_t i2)
{
	return serial_lt16(i2, i1);
}

/**
 * @brief Add to a 32-bit serial number (RFC 1982 §3.1).
 * @param s The current serial number in [0, 2^32 - 1].
 * @param n The amount to add; results are only defined for n in
 * [0, 2^31 - 1].
 * @return (s + n) modulo 2^32.
 */
static inline uint_fast32_t
serial_add32(const uint_fast32_t s, const uint_fast32_t n)
{
	return (s + n) & UINT32_C(0xFFFFFFFF);
}

/**
 * @brief Test whether one 32-bit serial number precedes another
 * (RFC 1982 §3.2).
 * @return true if i1 < i2 in the circular serial space; false if i1 >= i2 or
 * the two are exactly 2^31 apart (undefined ordering).
 */
static inline bool serial_lt32(const uint_fast32_t i1, const uint_fast32_t i2)
{
	const uint_fast32_t d = (uint_fast32_t)(i2 - i1) & UINT32_C(0xFFFFFFFF);
	return d != 0 && d < (UINT32_C(1) << 31);
}

/**
 * @brief Test whether one 32-bit serial number follows another
 * (RFC 1982 §3.2).
 * @return true if i1 > i2 in the circular serial space; false if i1 <= i2 or
 * the two are exactly 2^31 apart (undefined ordering).
 */
static inline bool serial_gt32(const uint_fast32_t i1, const uint_fast32_t i2)
{
	return serial_lt32(i2, i1);
}

/** @} */

#endif /* BINARY_SERIAL_H */
