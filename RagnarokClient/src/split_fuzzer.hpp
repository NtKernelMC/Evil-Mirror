#pragma once

#include "config.hpp"
#include "logger.hpp"
#include "raknet_utils.hpp"

#include "BitStream.h"
#include "GetTime.h"
#include "PacketPriority.h"
#include "RakPeer.h"
#include "RakPeerInterface.h"
#include "RakNetTypes.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace ragnarok::split_fuzzer
{
    struct State
    {
        uint32_t datagram = 0x4000;
        uint32_t reliable = 0x4000;
        uint16_t split_id = 0x7100;
        uint64_t sent = 0;
        uint64_t next_status_ms = 0;
    };

    inline uint64_t SteadyMs()
    {
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    }

    inline uint32_t ClampSplitCount(uint32_t v)
    {
        return std::max<uint32_t>(1, std::min<uint32_t>(v, 0x51EC));
    }

    inline uint32_t ClampPayloadBytes(uint32_t v)
    {
        return std::max<uint32_t>(32, std::min<uint32_t>(v, 1300));
    }

    inline std::vector<unsigned char> BuildPayload(uint32_t bytes)
    {
        bytes = ClampPayloadBytes(bytes);
        std::vector<unsigned char> out(bytes, 'R');

        RakNet::BitStream bs;
        static const std::string event_name = "rag_split_stress";
        WriteUpperPacketHeader(bs, UPG_REMOTE_EVENT);
        WriteU64LE(bs, XxHash64(event_name));
        WriteU16LE(bs, 1);
        bs.Write(static_cast<uint8_t>(0x13));
        WriteU16LE(bs, static_cast<uint16_t>(bytes));

        unsigned char fill[128];
        memset(fill, 'A', sizeof(fill));
        for(uint32_t left = bytes; left != 0;)
        {
            unsigned int take = static_cast<unsigned int>(std::min<uint32_t>(left, sizeof(fill)));
            bs.WriteAlignedBytes(fill, take);
            left -= take;
        }

        size_t take = std::min<size_t>(bytes, bs.GetNumberOfBytesUsed());
        if(take)
            memcpy(out.data(), bs.GetData(), take);

        return out;
    }

    inline void WriteDataHeader(RakNet::BitStream& bs, uint32_t datagram)
    {
        bs.Write(true);
        bs.Write(false);
        bs.Write(false);
        bs.Write(false);
        bs.Write(false);
        bs.Write(false);
        bs.AlignWriteToByteBoundary();
        bs.Write(RakNet::uint24_t(datagram));
    }

    inline void WriteSplitPacket(
        RakNet::BitStream& bs,
        const std::vector<unsigned char>& payload,
        uint32_t reliable,
        uint32_t split_count,
        uint16_t split_id,
        uint32_t split_index)
    {
        unsigned char reliability = RELIABLE;
        bs.AlignWriteToByteBoundary();
        bs.WriteBits(&reliability, 3, true);
        bs.Write(true);
        bs.AlignWriteToByteBoundary();

        uint16_t bits = static_cast<uint16_t>(payload.size() * 8);
        bs.WriteAlignedVar16(reinterpret_cast<const char*>(&bits));
        bs.Write(RakNet::uint24_t(reliable));
        bs.AlignWriteToByteBoundary();

        bs.WriteAlignedVar32(reinterpret_cast<const char*>(&split_count));
        bs.WriteAlignedVar16(reinterpret_cast<const char*>(&split_id));
        bs.WriteAlignedVar32(reinterpret_cast<const char*>(&split_index));
        bs.WriteAlignedBytes(payload.data(), static_cast<unsigned int>(payload.size()));
    }

    inline void PutU16LE(unsigned char* p, uint16_t v)
    {
        p[0] = static_cast<unsigned char>(v);
        p[1] = static_cast<unsigned char>(v >> 8);
    }

    inline void PutU24LE(unsigned char* p, uint32_t v)
    {
        p[0] = static_cast<unsigned char>(v);
        p[1] = static_cast<unsigned char>(v >> 8);
        p[2] = static_cast<unsigned char>(v >> 16);
    }

    inline bool Stop(const std::atomic_bool& stop)
    {
        return stop.load(std::memory_order_relaxed);
    }

    inline uint32_t ClientQueueLimit(const RuntimeConfig& cfg)
    {
        if(cfg.split_stress_max_client_queue == 0)
            return 0;

        return std::max<uint32_t>(32, std::min<uint32_t>(cfg.split_stress_max_client_queue, 65536));
    }

    inline void Throttle(const RuntimeConfig& cfg, State& state)
    {
        if(cfg.split_stress_log_every && state.sent % cfg.split_stress_log_every == 0)
        {
            std::this_thread::yield();
        }

        if(cfg.split_stress_sleep_every == 0 || state.sent % cfg.split_stress_sleep_every != 0)
            return;

        if(cfg.split_stress_sleep_us)
            std::this_thread::sleep_for(std::chrono::microseconds(cfg.split_stress_sleep_us));
        else
            std::this_thread::yield();
    }

    inline bool WaitForClientQueue(
        RakNet::RakPeerInterface* peer,
        const RuntimeConfig& cfg,
        const std::atomic_bool& stop)
    {
        uint32_t limit = ClientQueueLimit(cfg);
        if(limit == 0)
            return true;

        while(!Stop(stop) && peer->GetBufferedCommandQueueSize() >= limit)
        {
            if(cfg.split_stress_queue_wait_ms)
                std::this_thread::sleep_for(std::chrono::milliseconds(cfg.split_stress_queue_wait_ms));
            else
                std::this_thread::yield();
        }

        return !Stop(stop);
    }

    inline void AdaptiveYield(RakNet::RakPeerInterface* peer, const RuntimeConfig& cfg, State& state)
    {
        uint32_t limit = ClientQueueLimit(cfg);
        if(limit == 0 || (state.sent & 0x3F) != 0)
            return;

        if(peer->GetBufferedCommandQueueSize() >= limit / 2)
            std::this_thread::yield();
    }

    inline bool SendFragment(
        Logger& log,
        RakNet::RakPeerInterface* peer,
        RakNet::SystemAddress server,
        State& state,
        const RuntimeConfig& cfg,
        const std::atomic_bool& stop,
        const std::vector<unsigned char>& payload,
        uint32_t split_count,
        uint16_t split_id,
        uint32_t split_index)
    {
        if(Stop(stop))
            return false;

        if(!WaitForClientQueue(peer, cfg, stop))
            return false;

        RakNet::BitStream bs;
        WriteDataHeader(bs, state.datagram++);
        WriteSplitPacket(bs, payload, state.reliable++, split_count, split_id, split_index);
        if(!peer->SendRawDatagram(&bs, server))
        {
            log.Push(LogLevel::Warn, "split stress raw send failed");
            return false;
        }

        ++state.sent;
        AdaptiveYield(peer, cfg, state);
        Throttle(cfg, state);
        return true;
    }

    inline void LogProgress(Logger& log, RakNet::RakPeerInterface* peer, const RuntimeConfig& cfg, State& state, const char* profile)
    {
        if(cfg.split_stress_log_every == 0 || state.sent % cfg.split_stress_log_every != 0)
            return;

        unsigned int queue = peer != nullptr ? peer->GetBufferedCommandQueueSize() : 0;
        std::ostringstream oss;
        oss << "split stress " << profile << " sent=" << state.sent << " queue=" << queue;
        log.Push(LogLevel::Warn, oss.str());
        log.Status("SENT " + std::to_string(state.sent) + " queue=" + std::to_string(queue));
    }

    inline void StatusProgress(Logger& log, RakNet::RakPeerInterface* peer, State& state)
    {
        uint64_t now = SteadyMs();
        if(state.next_status_ms != 0 && now < state.next_status_ms)
            return;

        state.next_status_ms = now + 1000;
        unsigned int queue = peer != nullptr ? peer->GetBufferedCommandQueueSize() : 0;
        log.Status("SENT " + std::to_string(state.sent) + " queue=" + std::to_string(queue));
    }

    inline void DuplicateCompletion(
        Logger& log,
        RakNet::RakPeerInterface* peer,
        RakNet::SystemAddress server,
        State& state,
        const RuntimeConfig& cfg,
        const std::atomic_bool& stop,
        const std::vector<unsigned char>& payload)
    {
        uint32_t count = ClampSplitCount(cfg.split_stress_split_count);
        uint16_t split_id = state.split_id++;
        log.Push(LogLevel::Warn, "split stress duplicate-completion set started count=" + std::to_string(count));

        for(uint32_t i = 0; i < count; ++i)
        {
            if(!SendFragment(log, peer, server, state, cfg, stop, payload, count, split_id, 0))
                break;
            LogProgress(log, peer, cfg, state, "duplicate-completion");
        }
    }

    inline void LargeCountPrealloc(
        Logger& log,
        RakNet::RakPeerInterface* peer,
        RakNet::SystemAddress server,
        State& state,
        const RuntimeConfig& cfg,
        const std::atomic_bool& stop,
        const std::vector<unsigned char>& payload)
    {
        uint32_t count = ClampSplitCount(cfg.split_stress_split_count);
        log.Push(LogLevel::Warn, "split stress large-count-prealloc batch started sets=" + std::to_string(cfg.split_stress_prealloc_sets));

        for(uint32_t i = 0; i < cfg.split_stress_prealloc_sets; ++i)
        {
            uint16_t split_id = state.split_id++;
            if(!SendFragment(log, peer, server, state, cfg, stop, payload, count, split_id, 0))
                break;
            LogProgress(log, peer, cfg, state, "large-count-prealloc");
        }
    }

    inline void LargeFragmentPayload(
        Logger& log,
        RakNet::RakPeerInterface* peer,
        RakNet::SystemAddress server,
        State& state,
        const RuntimeConfig& cfg,
        const std::atomic_bool& stop,
        const std::vector<unsigned char>& payload)
    {
        uint32_t count = ClampSplitCount(cfg.split_stress_split_count);
        uint16_t split_id = state.split_id++;
        log.Push(LogLevel::Warn, "split stress large-fragment-payload set started count=" + std::to_string(count));

        for(uint32_t i = 0; i < count; ++i)
        {
            if(!SendFragment(log, peer, server, state, cfg, stop, payload, count, split_id, 0))
                break;
            LogProgress(log, peer, cfg, state, "large-fragment-payload");
        }
    }

    inline void MixedDuplicateMissing(
        Logger& log,
        RakNet::RakPeerInterface* peer,
        RakNet::SystemAddress server,
        State& state,
        const RuntimeConfig& cfg,
        const std::atomic_bool& stop,
        const std::vector<unsigned char>& payload)
    {
        uint32_t count = ClampSplitCount(cfg.split_stress_mixed_count);
        uint16_t split_id = state.split_id++;
        log.Push(LogLevel::Warn, "split stress mixed-duplicate-missing set started count=" + std::to_string(count));

        for(uint32_t i = 0; i < count; ++i)
        {
            uint32_t index = (i / 2) % count;
            if(!SendFragment(log, peer, server, state, cfg, stop, payload, count, split_id, index))
                break;
            LogProgress(log, peer, cfg, state, "mixed-duplicate-missing");
        }
    }

    inline void ManySplitId(
        Logger& log,
        RakNet::RakPeerInterface* peer,
        RakNet::SystemAddress server,
        State& state,
        const RuntimeConfig& cfg,
        const std::atomic_bool& stop,
        const std::vector<unsigned char>& payload)
    {
        uint32_t count = ClampSplitCount(cfg.split_stress_split_count);
        log.Push(LogLevel::Warn, "split stress many-split-id batch started ids=" + std::to_string(cfg.split_stress_many_ids_per_round));

        for(uint32_t i = 0; i < cfg.split_stress_many_ids_per_round; ++i)
        {
            uint16_t split_id = state.split_id++;
            if(!SendFragment(log, peer, server, state, cfg, stop, payload, count, split_id, 0))
                break;
            LogProgress(log, peer, cfg, state, "many-split-id");
        }
    }

    inline void PumpPreallocQueued(
        Logger& log,
        RakNet::RakPeerInterface* peer,
        RakNet::SystemAddress server,
        State& state,
        const RuntimeConfig& cfg,
        const std::atomic_bool& stop,
        const std::vector<unsigned char>& payload,
        uint32_t budget)
    {
        if(Stop(stop) || peer == nullptr || server == RakNet::UNASSIGNED_SYSTEM_ADDRESS)
            return;

        uint32_t count = ClampSplitCount(cfg.split_stress_split_count);
        auto* rak_peer = static_cast<RakNet::RakPeer*>(peer);
        std::array<unsigned char, 2048> packet{};
        std::array<unsigned char, 2048> packet_template{};
        RakNet::BitStream template_bs;
        WriteDataHeader(template_bs, 0);
        WriteSplitPacket(template_bs, payload, 0, count, 0, 0);

        unsigned int packet_len = template_bs.GetNumberOfBytesUsed();
        if(packet_len + 64 > packet.size())
        {
            log.Push(LogLevel::Warn, "split stress raw template is too large");
            log.Status("STRESS_FAIL raw template is too large");
            return;
        }

        memcpy(packet_template.data(), template_bs.GetData(), packet_len);
        RakNet::BitStream bs(packet.data(), packet_len, false);
        bs.SetNumberOfBitsAllocated(static_cast<RakNet::BitSize_t>(packet.size() * 8));
        RakNet::TimeUS now = RakNet::GetTimeUS();

        for(uint32_t i = 0; i < budget && !Stop(stop); ++i)
        {
            uint32_t datagram = state.datagram++;
            uint32_t reliable = state.reliable++;
            uint16_t split_id = state.split_id++;

            memcpy(packet.data(), packet_template.data(), packet_len);
            PutU24LE(packet.data() + 1, datagram);
            PutU24LE(packet.data() + 7, reliable);
            PutU16LE(packet.data() + 14, split_id);
            bs.SetWriteOffset(static_cast<RakNet::BitSize_t>(packet_len * 8));
            bs.ResetReadPointer();

            if(state.sent == 0)
            {
                RakNet::BitStream check;
                WriteDataHeader(check, datagram);
                WriteSplitPacket(check, payload, reliable, count, split_id, 0);
                if(check.GetNumberOfBytesUsed() != packet_len || memcmp(check.GetData(), packet.data(), packet_len) != 0)
                {
                    log.Push(LogLevel::Warn, "split stress raw template mismatch");
                    log.Status("STRESS_FAIL raw template mismatch");
                    return;
                }
            }

            if(!rak_peer->SendRawDatagramImmediateMutable(&bs, server, now))
            {
                log.Push(LogLevel::Warn, "split stress update-thread fast raw send failed");
                log.Status("STRESS_FAIL fast raw send failed sent=" + std::to_string(state.sent));
                return;
            }

            ++state.sent;
            LogProgress(log, peer, cfg, state, "large-count-prealloc/update");
        }

        StatusProgress(log, peer, state);
    }

    inline bool AnyProfileEnabled(const RuntimeConfig& cfg)
    {
        return cfg.split_stress_duplicate_completion ||
            cfg.split_stress_large_count_prealloc ||
            cfg.split_stress_large_fragment_payload ||
            cfg.split_stress_mixed_duplicate_missing ||
            cfg.split_stress_many_split_id;
    }

    inline bool OnlyPreallocEnabled(const RuntimeConfig& cfg)
    {
        return cfg.split_stress_large_count_prealloc &&
            !cfg.split_stress_duplicate_completion &&
            !cfg.split_stress_large_fragment_payload &&
            !cfg.split_stress_mixed_duplicate_missing &&
            !cfg.split_stress_many_split_id;
    }

    inline void Run(
        Logger& log,
        RakNet::RakPeerInterface* peer,
        RakNet::SystemAddress server,
        const RuntimeConfig& cfg,
        const std::atomic_bool& stop)
    {
        if(!cfg.split_stress || peer == nullptr || server == RakNet::UNASSIGNED_SYSTEM_ADDRESS)
            return;

        if(!AnyProfileEnabled(cfg))
        {
            log.Push(LogLevel::Warn, "split stress skipped: all profile flags are off");
            return;
        }

        State state;
        auto small = BuildPayload(64);
        auto large = BuildPayload(cfg.split_stress_fragment_bytes);
        uint32_t rounds = cfg.split_stress_rounds;
        log.Push(LogLevel::Warn, "split stress started, rounds=" + std::to_string(rounds) + " (0 means until stop)");
        log.Status("STRESS split stress started");

        for(uint32_t round = 0; !Stop(stop) && (rounds == 0 || round < rounds); ++round)
        {
            log.Push(LogLevel::Warn, "split stress round " + std::to_string(round + 1));

            if(cfg.split_stress_duplicate_completion)
                DuplicateCompletion(log, peer, server, state, cfg, stop, small);
            if(cfg.split_stress_large_count_prealloc)
                LargeCountPrealloc(log, peer, server, state, cfg, stop, small);
            if(cfg.split_stress_large_fragment_payload)
                LargeFragmentPayload(log, peer, server, state, cfg, stop, large);
            if(cfg.split_stress_mixed_duplicate_missing)
                MixedDuplicateMissing(log, peer, server, state, cfg, stop, large);
            if(cfg.split_stress_many_split_id)
                ManySplitId(log, peer, server, state, cfg, stop, small);
        }

        log.Push(LogLevel::Warn, "split stress stopped, sent=" + std::to_string(state.sent));
        log.Status("STOP split stress stopped sent=" + std::to_string(state.sent));
    }
}
