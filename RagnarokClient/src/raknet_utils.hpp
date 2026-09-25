#pragma once

#include "config.hpp"

#include "BitStream.h"
#include "MessageIdentifiers.h"
#include "RakNetTypes.h"

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>

namespace ragnarok
{
    constexpr unsigned char kUpperPacketId = 0xD2;

    enum : uint16_t
    {
        UPG_IDENTITY_ACK = 0x0002,
        UPG_AUTH_HELLO = 0x0003,
        UPG_READY = 0x0005,
        UPG_CHAT = 0x0010,
        UPG_COMMAND = 0x0011,
        UPG_STATE_ACK = 0x0014,
        UPG_SPAWN = 0x0015,
        UPG_DEATH = 0x0016,
        UPG_REMOTE_EVENT = 0x0023,
        UPG_AUTH_RESULT = 0x0037,
        UPG_IDENTITY = 0x0038,
        UPG_VOICE_TOGGLE = 0x0070,
        UPG_VOICE_REL = 0x0071,
        UPG_PROC_REQUEST = 0x0072,
        UPG_PROC_RESPONSE = 0x0074
    };

    inline std::string ToHex(const unsigned char* data, size_t size, size_t limit = 96)
    {
        std::ostringstream oss;

        for(size_t i = 0; i < size && i < limit; ++i)
        {
            if(i)
                oss << ' ';

            oss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                << static_cast<int>(data[i]);
        }

        if(size > limit)
            oss << " ...";

        return oss.str();
    }

    inline uint32_t ReadU32RawLE(const unsigned char* p)
    {
        return static_cast<uint32_t>(p[0])
            | (static_cast<uint32_t>(p[1]) << 8)
            | (static_cast<uint32_t>(p[2]) << 16)
            | (static_cast<uint32_t>(p[3]) << 24);
    }

    inline uint64_t ReadU64RawLE(const unsigned char* p)
    {
        return static_cast<uint64_t>(p[0])
            | (static_cast<uint64_t>(p[1]) << 8)
            | (static_cast<uint64_t>(p[2]) << 16)
            | (static_cast<uint64_t>(p[3]) << 24)
            | (static_cast<uint64_t>(p[4]) << 32)
            | (static_cast<uint64_t>(p[5]) << 40)
            | (static_cast<uint64_t>(p[6]) << 48)
            | (static_cast<uint64_t>(p[7]) << 56);
    }

    inline uint64_t Rotl64(uint64_t v, int r)
    {
        return (v << r) | (v >> (64 - r));
    }

    inline uint64_t XxHash64Round(uint64_t acc, uint64_t input)
    {
        constexpr uint64_t kPrime2 = 14029467366897019727ULL;
        constexpr uint64_t kPrime1 = 11400714785074694791ULL;
        acc += input * kPrime2;
        acc = Rotl64(acc, 31);
        acc *= kPrime1;
        return acc;
    }

    inline uint64_t XxHash64MergeRound(uint64_t acc, uint64_t val)
    {
        constexpr uint64_t kPrime1 = 11400714785074694791ULL;
        constexpr uint64_t kPrime4 = 9650029242287828579ULL;
        acc ^= XxHash64Round(0, val);
        acc = acc * kPrime1 + kPrime4;
        return acc;
    }

    inline uint64_t XxHash64(const std::string& text)
    {
        constexpr uint64_t kPrime1 = 11400714785074694791ULL;
        constexpr uint64_t kPrime2 = 14029467366897019727ULL;
        constexpr uint64_t kPrime3 = 1609587929392839161ULL;
        constexpr uint64_t kPrime4 = 9650029242287828579ULL;
        constexpr uint64_t kPrime5 = 2870177450012600261ULL;

        const unsigned char* p = reinterpret_cast<const unsigned char*>(text.data());
        const size_t len = text.size();
        size_t pos = 0;
        uint64_t h = 0;

        if(len >= 32)
        {
            uint64_t v1 = kPrime1 + kPrime2;
            uint64_t v2 = kPrime2;
            uint64_t v3 = 0;
            uint64_t v4 = 0 - kPrime1;

            while(pos + 32 <= len)
            {
                v1 = XxHash64Round(v1, ReadU64RawLE(p + pos));
                pos += 8;
                v2 = XxHash64Round(v2, ReadU64RawLE(p + pos));
                pos += 8;
                v3 = XxHash64Round(v3, ReadU64RawLE(p + pos));
                pos += 8;
                v4 = XxHash64Round(v4, ReadU64RawLE(p + pos));
                pos += 8;
            }

            h = Rotl64(v1, 1) + Rotl64(v2, 7) + Rotl64(v3, 12) + Rotl64(v4, 18);
            h = XxHash64MergeRound(h, v1);
            h = XxHash64MergeRound(h, v2);
            h = XxHash64MergeRound(h, v3);
            h = XxHash64MergeRound(h, v4);
        }
        else
        {
            h = kPrime5;
        }

        h += static_cast<uint64_t>(len);

        while(pos + 8 <= len)
        {
            uint64_t k1 = XxHash64Round(0, ReadU64RawLE(p + pos));
            h ^= k1;
            h = Rotl64(h, 27) * kPrime1 + kPrime4;
            pos += 8;
        }

        if(pos + 4 <= len)
        {
            h ^= static_cast<uint64_t>(ReadU32RawLE(p + pos)) * kPrime1;
            h = Rotl64(h, 23) * kPrime2 + kPrime3;
            pos += 4;
        }

        while(pos < len)
        {
            h ^= static_cast<uint64_t>(p[pos]) * kPrime5;
            h = Rotl64(h, 11) * kPrime1;
            ++pos;
        }

        h ^= h >> 33;
        h *= kPrime2;
        h ^= h >> 29;
        h *= kPrime3;
        h ^= h >> 32;
        return h;
    }

    inline std::string ToHex(const char* data, size_t size, size_t limit = 96)
    {
        return ToHex(reinterpret_cast<const unsigned char*>(data), size, limit);
    }

    inline std::string FormatSystemAddress(const RakNet::SystemAddress& address)
    {
        return address.ToString(true);
    }

    inline void WriteU16LE(RakNet::BitStream& bs, uint16_t value)
    {
        unsigned char raw[2] =
        {
            static_cast<unsigned char>(value & 0xFF),
            static_cast<unsigned char>((value >> 8) & 0xFF)
        };
        bs.WriteAlignedBytes(raw, 2);
    }

    inline void WriteU32LE(RakNet::BitStream& bs, uint32_t value)
    {
        unsigned char raw[4] =
        {
            static_cast<unsigned char>(value & 0xFF),
            static_cast<unsigned char>((value >> 8) & 0xFF),
            static_cast<unsigned char>((value >> 16) & 0xFF),
            static_cast<unsigned char>((value >> 24) & 0xFF)
        };
        bs.WriteAlignedBytes(raw, 4);
    }

    inline void WriteU64LE(RakNet::BitStream& bs, uint64_t value)
    {
        unsigned char raw[8];

        for(int i = 0; i < 8; ++i)
            raw[i] = static_cast<unsigned char>((value >> (i * 8)) & 0xFF);

        bs.WriteAlignedBytes(raw, 8);
    }

    inline unsigned char GetPacketIdentifier(const RakNet::Packet* packet)
    {
        if(packet == nullptr || packet->length == 0)
            return 0xFF;

        if(static_cast<unsigned char>(packet->data[0]) == ID_TIMESTAMP)
        {
            if(packet->length <= sizeof(RakNet::MessageID) + sizeof(RakNet::Time))
                return 0xFF;

            return static_cast<unsigned char>(packet->data[sizeof(RakNet::MessageID) + sizeof(RakNet::Time)]);
        }

        return static_cast<unsigned char>(packet->data[0]);
    }

    inline void WriteLenBytes(RakNet::BitStream& bs, const std::string& value)
    {
        auto take = std::min(value.size(), static_cast<size_t>(std::numeric_limits<uint16_t>::max()));
        WriteU16LE(bs, static_cast<uint16_t>(take));

        if(take != 0)
        {
            bs.WriteAlignedBytes(reinterpret_cast<const unsigned char*>(value.data()), static_cast<unsigned int>(take));
        }
    }

    inline void WriteUpperPacketHeader(RakNet::BitStream& bs, uint16_t family)
    {
        bs.Write(static_cast<RakNet::MessageID>(kUpperPacketId));
        WriteU16LE(bs, family);
    }

    inline void WriteAuthHelloPacket(RakNet::BitStream& bs, const RuntimeConfig& cfg)
    {
        WriteUpperPacketHeader(bs, UPG_AUTH_HELLO);
        WriteU32LE(bs, 13);
        bs.Write(static_cast<uint8_t>(0));
        WriteLenBytes(bs, cfg.serial);
        WriteLenBytes(bs, cfg.social);
        WriteU64LE(bs, static_cast<uint64_t>(cfg.rgsc_id));
        bs.Write(static_cast<uint8_t>(1));
        WriteU32LE(bs, static_cast<uint32_t>(cfg.rgsc_id & 0xFFFFFFFFULL));
    }

    inline void WriteIdentityPacket(RakNet::BitStream& bs, const RuntimeConfig& cfg, uint16_t local_port)
    {
        WriteUpperPacketHeader(bs, UPG_IDENTITY);
        WriteLenBytes(bs, cfg.player_name);
        WriteLenBytes(bs, cfg.serial);
        WriteLenBytes(bs, cfg.social);
        WriteU64LE(bs, static_cast<uint64_t>(cfg.rgsc_id));
        bs.Write(static_cast<uint8_t>(1));
        WriteU16LE(bs, local_port);
        bs.Write0();
    }

    inline void WriteReadyPacket(RakNet::BitStream& bs)
    {
        WriteUpperPacketHeader(bs, UPG_READY);
    }

    inline void WriteStateAckPacket(RakNet::BitStream& bs)
    {
        WriteUpperPacketHeader(bs, UPG_STATE_ACK);
    }

    inline void WriteSpawnLifecyclePacket(RakNet::BitStream& bs)
    {
        WriteUpperPacketHeader(bs, UPG_SPAWN);
    }

    inline void WriteRemoteEventPacket(RakNet::BitStream& bs, const std::string& event_name, const std::string& text)
    {
        WriteUpperPacketHeader(bs, UPG_REMOTE_EVENT);
        WriteU64LE(bs, XxHash64(event_name));
        WriteU16LE(bs, 1);
        bs.Write(static_cast<uint8_t>(0x13));
        WriteLenBytes(bs, text);
    }
}
