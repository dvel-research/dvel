#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <string>

#include "../../include/dvel_ffi.h"

namespace dvelsim
{
    enum class MsgType : uint8_t
    {
        Event = 1,
    };

    struct Message
    {
        MsgType type;
        uint32_t from;
        uint32_t to;
        dvel_event_t event;
    };

    struct WeightedTip
    {
        bool has_value = false;
        dvel_hash_t tip{};
        double weight = 0.0;
    };

    inline dvel_hash_t zero_hash()
    {
        dvel_hash_t h;
        std::memset(&h, 0, sizeof(h));
        return h;
    }

    inline bool is_zero_hash(const dvel_hash_t &h)
    {
        for (size_t i = 0; i < 32; i++)
            if (h.bytes[i] != 0)
                return false;
        return true;
    }

    inline dvel_hash_t make_secret(uint8_t tag)
    {
        dvel_hash_t s{};
        for (size_t i = 0; i < 32; i++)
            s.bytes[i] = static_cast<uint8_t>(tag + i);
        return s;
    }

    inline dvel_pubkey_t make_pubkey(uint8_t tag)
    {
        dvel_hash_t secret = make_secret(tag);
        dvel_pubkey_t pub{};
        if (!dvel_derive_pubkey_from_secret(&secret, &pub))
        {
            // deterministic filler if FFI derive fails
            for (size_t i = 0; i < 32; i++)
                pub.bytes[i] = static_cast<uint8_t>(tag + i);
        }
        return pub;
    }

    inline dvel_hash_t make_payload_hash(uint8_t tag)
    {
        dvel_hash_t h;
        for (size_t i = 0; i < 32; i++)
            h.bytes[i] = (uint8_t)(tag ^ (uint8_t)i);
        return h;
    }

    inline dvel_sig_t make_dummy_sig(uint8_t tag)
    {
        dvel_sig_t s;
        for (size_t i = 0; i < 64; i++)
            s.bytes[i] = (uint8_t)(tag + (uint8_t)i);
        return s;
    }

    inline std::string hash_to_hex(const dvel_hash_t &h)
    {
        char buf[65];
        for (int i = 0; i < 32; ++i)
        {
            std::sprintf(buf + i * 2, "%02x", h.bytes[i]);
        }
        buf[64] = '\0';
        return std::string(buf);
    }

    inline std::string pubkey_to_hex(const dvel_pubkey_t &pk)
    {
        char buf[65];
        for (int i = 0; i < 32; ++i)
        {
            std::sprintf(buf + i * 2, "%02x", pk.bytes[i]);
        }
        buf[64] = '\0';
        return std::string(buf);
    }

    inline void print_hash_prefix(const char *label, const dvel_hash_t &h)
    {
        std::printf("%s %02x%02x%02x%02x...\n", label, h.bytes[0], h.bytes[1], h.bytes[2], h.bytes[3]);
    }

    inline const char *validation_to_str(dvel_validation_result_t r)
    {
        switch (r)
        {
        case DVEL_OK:
            return "OK";
        case DVEL_ERR_INVALID_VERSION:
            return "ERR_INVALID_VERSION";
        case DVEL_ERR_INVALID_SIGNATURE:
            return "ERR_INVALID_SIGNATURE";
        case DVEL_ERR_TIMESTAMP_NON_MONOTONIC:
            return "ERR_TIMESTAMP_NON_MONOTONIC";
        default:
            return "ERR_UNKNOWN";
        }
    }

    static inline const char *link_to_str(dvel_link_result_t r)
    {
        switch (r)
        {
        case DVEL_LINK_OK:
            return "LINK_OK";
        case DVEL_LINK_ERR_DUPLICATE:
            return "LINK_ERR_DUPLICATE";
        case DVEL_LINK_ERR_MISSING_PARENT:
            return "LINK_ERR_MISSING_PARENT";
        default:
            return "LINK_ERR_UNKNOWN";
        }
    }

} // namespace dvelsim
