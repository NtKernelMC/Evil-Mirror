#pragma once

#include "logger.hpp"
#include "raknet_utils.hpp"

#include <windows.h>
#include <bcrypt.h>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace ragnarok
{
    class HeapDumpCollector
    {
        struct Pending
        {
            uint32_t total = 0;
            std::vector<std::vector<unsigned char>> parts;
            std::vector<bool> seen;
        };

        Logger* log = nullptr;
        std::filesystem::path directory;
        uint32_t expected_bytes = 0;
        bool direct_blob = false;
        uint64_t capture_number = 0;
        std::string session_id;
        std::map<uint32_t, Pending> pending;

        static bool ReadDecimal(std::string_view text, size_t& pos, uint32_t& value)
        {
            if(pos >= text.size() || text[pos] < '0' || text[pos] > '9')
                return false;

            value = 0;
            while(pos < text.size() && text[pos] >= '0' && text[pos] <= '9')
            {
                uint32_t digit = static_cast<uint32_t>(text[pos] - '0');
                if(value > (UINT32_MAX - digit) / 10)
                    return false;
                value = value * 10 + digit;
                ++pos;
            }
            return true;
        }

        static int HexNibble(char value)
        {
            if(value >= '0' && value <= '9')
                return value - '0';
            if(value >= 'a' && value <= 'f')
                return value - 'a' + 10;
            if(value >= 'A' && value <= 'F')
                return value - 'A' + 10;
            return -1;
        }

        static bool DecodeHex(std::string_view hex, std::vector<unsigned char>& out)
        {
            if(hex.size() % 2 != 0 || hex.size() > 131070)
                return false;

            out.clear();
            out.reserve(hex.size() / 2);
            for(size_t i = 0; i < hex.size(); i += 2)
            {
                int hi = HexNibble(hex[i]);
                int lo = HexNibble(hex[i + 1]);
                if(hi < 0 || lo < 0)
                    return false;
                out.push_back(static_cast<unsigned char>((hi << 4) | lo));
            }
            return true;
        }

        static bool Sha256(const std::vector<unsigned char>& data, std::string& hex)
        {
            BCRYPT_ALG_HANDLE algorithm = nullptr;
            NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
            if(status < 0)
                return false;

            std::array<unsigned char, 32> digest = {};
            status = BCryptHash(algorithm, nullptr, 0,
                const_cast<unsigned char*>(data.data()), static_cast<ULONG>(data.size()),
                digest.data(), static_cast<ULONG>(digest.size()));
            BCryptCloseAlgorithmProvider(algorithm, 0);
            if(status < 0)
                return false;

            std::ostringstream out;
            out << std::hex << std::setfill('0');
            for(unsigned char value : digest)
                out << std::setw(2) << static_cast<unsigned>(value);
            hex = out.str();
            return true;
        }

        static std::string UtcTime()
        {
            SYSTEMTIME now = {};
            GetSystemTime(&now);
            std::ostringstream out;
            out << std::setfill('0') << std::setw(4) << now.wYear << '-'
                << std::setw(2) << now.wMonth << '-' << std::setw(2) << now.wDay << 'T'
                << std::setw(2) << now.wHour << ':' << std::setw(2) << now.wMinute << ':'
                << std::setw(2) << now.wSecond << '.' << std::setw(3) << now.wMilliseconds << 'Z';
            return out.str();
        }

        bool Capture(const std::vector<unsigned char>& bytes)
        {
            if(bytes.size() != expected_bytes)
            {
                log->Push(LogLevel::Warn, "heap dump reply length mismatch, bytes=" + std::to_string(bytes.size()));
                return false;
            }

            std::string digest;
            if(!Sha256(bytes, digest))
            {
                log->Push(LogLevel::Error, "heap dump SHA-256 failed");
                return false;
            }

            std::filesystem::path name = digest + ".bin";
            std::filesystem::path final_path = directory / name;
            std::error_code ec;
            bool duplicate = std::filesystem::exists(final_path, ec);
            if(ec)
            {
                log->Push(LogLevel::Error, "heap dump output lookup failed");
                return false;
            }

            if(duplicate)
            {
                std::ifstream existing(final_path, std::ios::binary);
                std::vector<unsigned char> old(
                    (std::istreambuf_iterator<char>(existing)), std::istreambuf_iterator<char>());
                if(!existing.good() && !existing.eof())
                {
                    log->Push(LogLevel::Error, "heap dump existing file read failed");
                    return false;
                }
                if(old != bytes)
                {
                    log->Push(LogLevel::Error, "heap dump SHA-256 filename collision or corrupt file");
                    return false;
                }
            }
            else
            {
                std::filesystem::path temp_path = directory / (digest + ".tmp");
                {
                    std::ofstream temp(temp_path, std::ios::binary | std::ios::trunc);
                    temp.write(reinterpret_cast<const char*>(bytes.data()),
                        static_cast<std::streamsize>(bytes.size()));
                    temp.flush();
                    if(!temp.good())
                    {
                        log->Push(LogLevel::Error, "heap dump file write failed");
                        return false;
                    }
                }
                std::filesystem::rename(temp_path, final_path, ec);
                if(ec)
                {
                    log->Push(LogLevel::Error, "heap dump file rename failed");
                    return false;
                }
            }

            ++capture_number;
            std::ofstream manifest(directory / "captures.jsonl", std::ios::app);
            manifest << "{\"session\":\"" << session_id << "\""
                << ",\"number\":" << capture_number
                << ",\"utc\":\"" << UtcTime() << "\""
                << ",\"bytes\":" << bytes.size()
                << ",\"sha256\":\"" << digest << "\""
                << ",\"duplicate\":" << (duplicate ? "true" : "false")
                << ",\"file\":\"" << name.string() << "\"}\n";
            if(!manifest.good())
            {
                log->Push(LogLevel::Error, "heap dump manifest write failed");
                return false;
            }

            log->Push(LogLevel::Success, "heap dump captured number=" + std::to_string(capture_number)
                + " bytes=" + std::to_string(bytes.size()) + " sha256=" + digest
                + " duplicate=" + (duplicate ? "yes" : "no"));
            return true;
        }

        bool CaptureChunk(std::string_view text)
        {
            size_t pos = 8;
            uint32_t sequence = 0;
            uint32_t index = 0;
            uint32_t total = 0;
            if(!ReadDecimal(text, pos, sequence) || pos >= text.size() || text[pos++] != ':' ||
                !ReadDecimal(text, pos, index) || pos >= text.size() || text[pos++] != '/' ||
                !ReadDecimal(text, pos, total) || pos >= text.size() || text[pos++] != ':' ||
                total == 0 || total > 8 || index >= total)
            {
                log->Push(LogLevel::Warn, "heap dump chunk header invalid");
                return false;
            }

            std::vector<unsigned char> part;
            if(!DecodeHex(text.substr(pos), part) || part.empty() || part.size() > 8192)
            {
                log->Push(LogLevel::Warn, "heap dump chunk hex invalid");
                return false;
            }

            if(pending.find(sequence) == pending.end() && pending.size() >= 4)
                pending.erase(pending.begin());
            Pending& group = pending[sequence];
            if(group.total == 0)
            {
                group.total = total;
                group.parts.resize(total);
                group.seen.resize(total, false);
            }
            if(group.total != total || (group.seen[index] && group.parts[index] != part))
            {
                pending.erase(sequence);
                log->Push(LogLevel::Warn, "heap dump chunk conflict");
                return false;
            }
            group.parts[index] = std::move(part);
            group.seen[index] = true;
            for(bool seen : group.seen)
            {
                if(!seen)
                    return true;
            }

            std::vector<unsigned char> bytes;
            bytes.reserve(expected_bytes);
            for(const auto& item : group.parts)
            {
                if(bytes.size() + item.size() > expected_bytes)
                {
                    pending.erase(sequence);
                    log->Push(LogLevel::Warn, "heap dump chunks exceed requested length");
                    return false;
                }
                bytes.insert(bytes.end(), item.begin(), item.end());
            }
            pending.erase(sequence);
            return Capture(bytes);
        }

    public:
        bool Init(Logger& logger, const std::filesystem::path& output_dir, uint32_t size, bool native_blob = false)
        {
            log = &logger;
            directory = output_dir;
            expected_bytes = size;
            direct_blob = native_blob;
            session_id = UtcTime() + "/pid" + std::to_string(GetCurrentProcessId());
            std::error_code ec;
            std::filesystem::create_directories(directory, ec);
            if(ec || !std::filesystem::is_directory(directory, ec) || ec)
            {
                log->Push(LogLevel::Error, "heap dump output directory unavailable");
                return false;
            }
            log->Push(LogLevel::Info, "heap dump output directory: " + directory.string());
            return true;
        }

        bool HandleUpper(const unsigned char* data, size_t size)
        {
            if(size < 11 || data[0] != kUpperPacketId || data[1] != 0x23 || data[2] != 0)
                return false;

            uint64_t event_id = 0;
            for(size_t i = 0; i < 8; ++i)
                event_id |= static_cast<uint64_t>(data[3 + i]) << (8 * i);
            if(direct_blob)
            {
                if(event_id != XxHash64(std::string("biz.order.ans")))
                    return false;
                if(size < 21 || data[11] != 2 || data[12] != 0 || data[13] != 0x0F ||
                    data[18] != 0x18)
                {
                    log->Push(LogLevel::Warn, "business heap reply header invalid");
                    return true;
                }
                uint16_t length = static_cast<uint16_t>(data[19]) | (static_cast<uint16_t>(data[20]) << 8);
                if(length != expected_bytes || size != 21 + static_cast<size_t>(length) ||
                    length < 8 || std::string_view(reinterpret_cast<const char*>(data + 21), 8) != "RGXDUMP1")
                {
                    log->Push(LogLevel::Warn, "business heap reply length or marker mismatch");
                    return true;
                }
                Capture(std::vector<unsigned char>(data + 21, data + 21 + length));
                return true;
            }
            if(event_id != XxHash64(std::string("rag_heap_dump")))
                return false;

            if(size < 16)
            {
                log->Push(LogLevel::Warn, "heap dump reply header truncated");
                return true;
            }

            uint16_t argc = static_cast<uint16_t>(data[11]) | (static_cast<uint16_t>(data[12]) << 8);
            uint16_t text_len = static_cast<uint16_t>(data[14]) | (static_cast<uint16_t>(data[15]) << 8);
            if(argc != 1 || data[13] != 0x13 || size < 16 + text_len)
            {
                log->Push(LogLevel::Warn, "heap dump reply format invalid");
                return true;
            }

            std::string_view text(reinterpret_cast<const char*>(data + 16), text_len);
            if(text.substr(0, 7) == "A2DUMP:")
            {
                std::vector<unsigned char> bytes;
                if(!DecodeHex(text.substr(7), bytes))
                    log->Push(LogLevel::Warn, "heap dump reply hex invalid");
                else
                    Capture(bytes);
                return true;
            }
            if(text.substr(0, 8) == "A2CHUNK:")
            {
                CaptureChunk(text);
                return true;
            }
            log->Push(LogLevel::Warn, "heap dump reply prefix invalid");
            return true;
        }
    };
}
