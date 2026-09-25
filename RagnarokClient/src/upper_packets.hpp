#pragma once

#include "logger.hpp"
#include "raknet_utils.hpp"

#include <sstream>
#include <string>
#include <vector>
#include <windows.h>

namespace ragnarok
{
    namespace upper
    {
        inline bool ParseU16LE(const unsigned char* data, size_t size, size_t& off, uint16_t& out)
        {
            if(off + 2 > size)
                return false;

            out = static_cast<uint16_t>(data[off]) | (static_cast<uint16_t>(data[off + 1]) << 8);
            off += 2;
            return true;
        }

        inline bool ParseU32LE(const unsigned char* data, size_t size, size_t& off, uint32_t& out)
        {
            if(off + 4 > size)
                return false;

            out = static_cast<uint32_t>(data[off])
                | (static_cast<uint32_t>(data[off + 1]) << 8)
                | (static_cast<uint32_t>(data[off + 2]) << 16)
                | (static_cast<uint32_t>(data[off + 3]) << 24);
            off += 4;
            return true;
        }

        inline bool ParseU64LE(const unsigned char* data, size_t size, size_t& off, uint64_t& out)
        {
            if(off + 8 > size)
                return false;

            out = 0;
            for(int i = 0; i < 8; ++i)
                out |= static_cast<uint64_t>(data[off + i]) << (i * 8);

            off += 8;
            return true;
        }

        inline bool ParseU8(const unsigned char* data, size_t size, size_t& off, uint8_t& out)
        {
            if(off + 1 > size)
                return false;

            out = data[off++];
            return true;
        }

        inline bool ParseBitBool(const unsigned char* data, size_t size, size_t& off, bool& out)
        {
            if(off + 1 > size)
                return false;

            out = (data[off++] & 1) != 0;
            return true;
        }

        inline bool ParseLenString(const unsigned char* data, size_t size, size_t& off, std::string& out)
        {
            uint16_t len = 0;
            if(!ParseU16LE(data, size, off, len))
                return false;

            if(off + len > size)
                return false;

            out.assign(reinterpret_cast<const char*>(data + off), len);
            off += len;
            return true;
        }

        inline bool ParseUtf16String(const unsigned char* data, size_t size, size_t& off, std::string& out)
        {
            uint16_t chars = 0;
            if(!ParseU16LE(data, size, off, chars))
                return false;

            if(chars > 2048)
                return false;

            size_t bytes = static_cast<size_t>(chars) * 2;
            if(off + bytes > size)
                return false;

            if(bytes == 0)
            {
                out.clear();
                return true;
            }

            const wchar_t* w = reinterpret_cast<const wchar_t*>(data + off);
            int utf8 = WideCharToMultiByte(CP_UTF8, 0, w, chars, nullptr, 0, nullptr, nullptr);

            if(utf8 <= 0)
            {
                out.assign(reinterpret_cast<const char*>(data + off), bytes);
            }
            else
            {
                out.resize(static_cast<size_t>(utf8));
                WideCharToMultiByte(CP_UTF8, 0, w, chars, out.data(), utf8, nullptr, nullptr);
            }

            off += bytes;
            return true;
        }

        inline void ParseChatLike(Logger& log, uint16_t family, const unsigned char* data, size_t size)
        {
            size_t off = 0;
            std::string txt;
            if(!ParseUtf16String(data, size, off, txt))
            {
                log.Push(LogLevel::Warn, "upper chat/command parse failed");
                return;
            }

            if(family == UPG_CHAT)
                log.Push(LogLevel::Success, "[chat] " + txt);
            else
                log.Push(LogLevel::Success, "[command] " + txt);
        }

        inline void ParseIdentityPacket(Logger& log, const unsigned char* data, size_t size)
        {
            size_t off = 0;
            std::string name;
            std::string serial;
            std::string social;

            if(!ParseLenString(data, size, off, name) ||
                !ParseLenString(data, size, off, serial) ||
                !ParseLenString(data, size, off, social))
            {
                log.Push(LogLevel::Warn, "identity packet (0x38) parse failed on strings");
                return;
            }

            uint64_t rgsc = 0;
            uint8_t game_type = 0;
            uint16_t endpoint_port = 0;
            bool has_endpoint = false;

            if(!ParseU64LE(data, size, off, rgsc) ||
                !ParseU8(data, size, off, game_type) ||
                !ParseU16LE(data, size, off, endpoint_port) ||
                !ParseBitBool(data, size, off, has_endpoint))
            {
                log.Push(LogLevel::Warn, "identity packet (0x38) parse failed on fixed fields");
                return;
            }

            if(off < size)
            {
                log.Push(LogLevel::Warn, "identity packet (0x38) extra bytes: " + ToHex(data + off, size - off));
            }

            std::ostringstream oss;
            oss << "identity packet 0x38 => name=" << name
                << ", serial=" << serial
                << ", social=" << social
                << ", rgsc=" << rgsc
                << ", gameType=" << static_cast<int>(game_type)
                << ", epPort=" << endpoint_port
                << ", hasEndpoint=" << (has_endpoint ? "yes" : "no");
            log.Push(LogLevel::Success, oss.str());
        }

        inline void ParseDeathPacket(Logger& log, const unsigned char* data, size_t size)
        {
            size_t off = 0;
            uint32_t reason = 0;
            bool has_killer = false;
            uint16_t killer = 0;

            if(!ParseU32LE(data, size, off, reason))
            {
                log.Push(LogLevel::Warn, "death packet parse fail");
                return;
            }

            if(!ParseBitBool(data, size, off, has_killer))
            {
                log.Push(LogLevel::Warn, "death packet killer-flag parse fail");
                return;
            }

            if(has_killer && !ParseU16LE(data, size, off, killer))
            {
                log.Push(LogLevel::Warn, "death packet killer-id parse fail");
                return;
            }

            std::ostringstream oss;
            oss << "upper death 0x16 => reason=" << reason;
            if(has_killer)
                oss << ", killerId=" << killer;
            log.Push(LogLevel::Warn, oss.str());
        }

        inline void ParseRpcPacket(Logger& log, const unsigned char* data, size_t size)
        {
            size_t off = 0;
            uint64_t event_id = 0;
            uint16_t argc = 0;

            if(!ParseU64LE(data, size, off, event_id) || !ParseU16LE(data, size, off, argc))
            {
                log.Push(LogLevel::Warn, "rpc packet parse fail");
                return;
            }

            const char* event_name = nullptr;
            if(event_id == XxHash64(std::string("rag_test")))
                event_name = "rag_test";
            else if(event_id == XxHash64(std::string("rag_alpha")))
                event_name = "rag_alpha";
            else if(event_id == XxHash64(std::string("rag_beta42")))
                event_name = "rag_beta42";

            std::string arg0_desc;
            if(argc > 0 && off < size)
            {
                size_t save = off;
                uint8_t type = 0;
                if(ParseU8(data, size, off, type))
                {
                    if(type == 0x13)
                    {
                        std::string txt;
                        if(ParseLenString(data, size, off, txt))
                            arg0_desc = txt;
                        else
                            off = save;
                    }
                    else
                    {
                        std::ostringstream type_oss;
                        type_oss << "type=0x" << std::hex << static_cast<int>(type);
                        arg0_desc = type_oss.str();
                    }
                }
            }

            std::ostringstream oss;
            oss << "incoming RPC 0x23 => eventId=0x" << std::hex << event_id;
            if(event_name != nullptr)
                oss << " name=" << event_name;
            oss << " argc=" << std::dec << argc;
            if(!arg0_desc.empty())
                oss << " arg0=" << arg0_desc;
            if(off < size)
                oss << " remain=" << (size - off) << " bytes";
            log.Push(LogLevel::Info, oss.str());
        }

        inline void ParseProcRequestPacket(Logger& log, const unsigned char* data, size_t size)
        {
            size_t off = 0;
            uint64_t proc_id = 0;
            uint32_t request_id = 0;
            uint16_t argc = 0;

            if(!ParseU64LE(data, size, off, proc_id) ||
                !ParseU32LE(data, size, off, request_id) ||
                !ParseU16LE(data, size, off, argc))
            {
                log.Push(LogLevel::Warn, "proc request (0x72) parse fail");
                return;
            }

            std::ostringstream oss;
            oss << "proc request (0x72) => procId=0x" << std::hex << proc_id
                << " requestId=" << std::dec << request_id
                << " argc=" << argc
                << " remain=" << (size - off);
            log.Push(LogLevel::Info, oss.str());

            if(off < size)
                log.Push(LogLevel::Network, "proc request tail: " + ToHex(data + off, size - off));
        }

        inline void ParseProcResponsePacket(Logger& log, const unsigned char* data, size_t size)
        {
            size_t off = 0;
            uint32_t request_id = 0;
            uint8_t mode = 0;

            if(!ParseU32LE(data, size, off, request_id) || !ParseU8(data, size, off, mode))
            {
                log.Push(LogLevel::Warn, "proc response (0x74) parse fail");
                return;
            }

            std::ostringstream oss;
            oss << "proc response (0x74) => requestId=" << request_id
                << " mode=" << static_cast<int>(mode)
                << " remain=" << (size - off);
            log.Push(LogLevel::Info, oss.str());

            if(off < size)
                log.Push(LogLevel::Network, "proc response tail: " + ToHex(data + off, size - off));
        }

        inline void HandleUpperPacket(Logger& log, const unsigned char* data, size_t size)
        {
            if(size < 3 || data[0] != kUpperPacketId)
            {
                log.Push(LogLevel::Warn, "upper packet framing mismatch");
                return;
            }

            uint16_t family = static_cast<uint16_t>(data[1]) | (static_cast<uint16_t>(data[2]) << 8);
            const unsigned char* body = data + 3;
            size_t body_size = size - 3;

            if(family == UPG_IDENTITY_ACK)
            {
                log.Push(LogLevel::Info, "upper identity ack (0x02) received");
                log.Status("READY upper identity ack (0x02) received");
                if(body_size != 0)
                    log.Push(LogLevel::Network, "upper 0x02 payload: " + ToHex(body, body_size));
            }
            else if(family == UPG_AUTH_HELLO)
            {
                log.Push(LogLevel::Info, "upper auth hello/result (0x03) received");
                if(body_size != 0)
                    log.Push(LogLevel::Network, "upper 0x03 payload: " + ToHex(body, body_size));
            }
            else if(family == UPG_READY)
            {
                log.Push(LogLevel::Info, "upper ready (0x05) received");
                if(body_size != 0)
                    log.Push(LogLevel::Warn, "upper 0x05 has extra bytes: " + ToHex(body, body_size));
            }
            else if(family == UPG_CHAT || family == UPG_COMMAND)
            {
                ParseChatLike(log, family, body, body_size);
            }
            else if(family == UPG_STATE_ACK)
            {
                log.Push(LogLevel::Info, "upper state ack (0x14) received");
                if(body_size != 0)
                    log.Push(LogLevel::Warn, "upper 0x14 has extra bytes: " + ToHex(body, body_size));
            }
            else if(family == UPG_SPAWN)
            {
                log.Push(LogLevel::Info, "upper spawn/lifecycle (0x15) received");
                if(body_size != 0)
                    log.Push(LogLevel::Network, "upper 0x15 payload: " + ToHex(body, body_size));
            }
            else if(family == UPG_DEATH)
            {
                ParseDeathPacket(log, body, body_size);
            }
            else if(family == UPG_AUTH_RESULT)
            {
                log.Push(LogLevel::Info, "upper auth result (0x37) received");
                if(body_size != 0)
                    log.Push(LogLevel::Network, "upper 0x37 payload: " + ToHex(body, body_size));
            }
            else if(family == UPG_IDENTITY)
            {
                ParseIdentityPacket(log, body, body_size);
            }
            else if(family == UPG_REMOTE_EVENT)
            {
                ParseRpcPacket(log, body, body_size);
            }
            else if(family == UPG_PROC_REQUEST)
            {
                ParseProcRequestPacket(log, body, body_size);
            }
            else if(family == UPG_PROC_RESPONSE)
            {
                ParseProcResponsePacket(log, body, body_size);
            }
            else
            {
                std::ostringstream oss;
                oss << "upper family=0x" << std::hex << std::uppercase << family
                    << " raw=" << ToHex(body, body_size);
                log.Push(LogLevel::Warn, oss.str());
            }
        }
    }
}
