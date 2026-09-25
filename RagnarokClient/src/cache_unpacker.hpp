#pragma once

#include "config.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

namespace ragnarok::fastdl
{
    struct List2Info
    {
        uint32_t magic = 0;
        uint32_t version = 0;
        bool has_first = false;
        std::string first;
        bool has_second = false;
        std::string second;
        uint8_t marker = 0;
        uint32_t file_count = 0;
        std::vector<unsigned char> wrapped_key;
        std::vector<unsigned char> encrypted_manifest;
    };

    inline std::wstring Wide(const std::string& v)
    {
        if(v.empty())
            return {};

        int need = MultiByteToWideChar(CP_UTF8, 0, v.data(), static_cast<int>(v.size()), nullptr, 0);
        if(need <= 0)
            return {};

        std::wstring out(static_cast<size_t>(need), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, v.data(), static_cast<int>(v.size()), out.data(), need);
        return out;
    }

    inline std::string SafePart(std::string v)
    {
        for(char& c : v)
        {
            if((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '_')
                continue;

            c = '_';
        }

        return v;
    }

    inline std::string Stamp()
    {
        SYSTEMTIME st = {};
        GetLocalTime(&st);

        char buf[64] = {};
        sprintf_s(
            buf,
            "%04u%02u%02u_%02u%02u%02u",
            st.wYear,
            st.wMonth,
            st.wDay,
            st.wHour,
            st.wMinute,
            st.wSecond);
        return buf;
    }

    inline uint16_t ReadU16(const unsigned char* p)
    {
        return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
    }

    inline uint32_t ReadU32(const unsigned char* p)
    {
        return static_cast<uint32_t>(p[0])
            | (static_cast<uint32_t>(p[1]) << 8)
            | (static_cast<uint32_t>(p[2]) << 16)
            | (static_cast<uint32_t>(p[3]) << 24);
    }

    inline bool WriteAll(const std::filesystem::path& path, const std::vector<unsigned char>& data)
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if(!out)
            return false;

        if(!data.empty())
            out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        return static_cast<bool>(out);
    }

    inline bool WriteText(const std::filesystem::path& path, const std::string& text)
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if(!out)
            return false;

        out << text;
        return static_cast<bool>(out);
    }

    inline bool HttpGet(const std::string& host, unsigned short port, const std::string& path, std::vector<unsigned char>& out)
    {
        out.clear();

        std::wstring whost = Wide(host);
        std::wstring wpath = Wide(path);
        if(whost.empty() || wpath.empty())
            return false;

        HINTERNET ses = WinHttpOpen(L"Ragnarok/fastdl-dump", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if(!ses)
            return false;

        WinHttpSetTimeouts(ses, 4000, 4000, 5000, 5000);

        HINTERNET con = WinHttpConnect(ses, whost.c_str(), port, 0);
        if(!con)
        {
            WinHttpCloseHandle(ses);
            return false;
        }

        HINTERNET req = WinHttpOpenRequest(con, L"GET", wpath.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if(!req)
        {
            WinHttpCloseHandle(con);
            WinHttpCloseHandle(ses);
            return false;
        }

        bool ok = false;
        if(WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
            && WinHttpReceiveResponse(req, nullptr))
        {
            DWORD status = 0;
            DWORD size = sizeof(status);
            if(WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX)
                && status == 200)
            {
                for(;;)
                {
                    DWORD avail = 0;
                    if(!WinHttpQueryDataAvailable(req, &avail))
                        break;

                    if(!avail)
                    {
                        ok = true;
                        break;
                    }

                    size_t old = out.size();
                    out.resize(old + avail);

                    DWORD read = 0;
                    if(!WinHttpReadData(req, out.data() + old, avail, &read))
                    {
                        out.resize(old);
                        break;
                    }

                    out.resize(old + read);
                }
            }
        }

        WinHttpCloseHandle(req);
        WinHttpCloseHandle(con);
        WinHttpCloseHandle(ses);
        return ok;
    }

    inline bool ParseList2(const std::vector<unsigned char>& data, List2Info& out)
    {
        out = {};
        if(data.size() < 4 + 4 + 1 + 1 + 1 + 4 + 128)
            return false;

        size_t p = 0;
        out.magic = ReadU32(data.data() + p);
        p += 4;
        out.version = ReadU32(data.data() + p);
        p += 4;

        out.has_first = data[p++] != 0;
        if(out.has_first)
        {
            if(p + 2 > data.size())
                return false;

            uint16_t len = ReadU16(data.data() + p);
            p += 2;
            if(p + len > data.size())
                return false;

            out.first.assign(reinterpret_cast<const char*>(data.data() + p), reinterpret_cast<const char*>(data.data() + p + len));
            p += len;
        }

        if(p >= data.size())
            return false;

        out.has_second = data[p++] != 0;
        if(out.has_second)
        {
            if(p + 2 > data.size())
                return false;

            uint16_t len = ReadU16(data.data() + p);
            p += 2;
            if(p + len > data.size())
                return false;

            out.second.assign(reinterpret_cast<const char*>(data.data() + p), reinterpret_cast<const char*>(data.data() + p + len));
            p += len;
        }

        if(p + 1 + 4 + 128 > data.size())
            return false;

        out.marker = data[p++];
        out.file_count = ReadU32(data.data() + p);
        p += 4;

        out.wrapped_key.assign(data.begin() + static_cast<std::ptrdiff_t>(p), data.begin() + static_cast<std::ptrdiff_t>(p + 128));
        p += 128;

        out.encrypted_manifest.assign(data.begin() + static_cast<std::ptrdiff_t>(p), data.end());
        return true;
    }

    inline void DumpCache(const std::string& host, unsigned short port, const std::filesystem::path& exe_dir)
    {
        std::filesystem::path root = exe_dir / "cache_dump" / (SafePart(host) + "_" + std::to_string(port)) / Stamp();
        std::filesystem::create_directories(root);

        std::ostringstream status;
        status << "host=" << host << "\n";
        status << "port=" << port << "\n";

        std::vector<unsigned char> list2;
        if(!HttpGet(host, port, "/list2", list2))
        {
            status << "list2=fetch_failed\n";
            WriteText(root / "status.txt", status.str());
            return;
        }

        WriteAll(root / "list2.bin", list2);
        status << "list2_bytes=" << list2.size() << "\n";

        List2Info info;
        if(!ParseList2(list2, info))
        {
            status << "list2_parse=failed\n";
            WriteText(root / "status.txt", status.str());
            return;
        }

        WriteAll(root / "list2_wrapped_key.bin", info.wrapped_key);
        WriteAll(root / "list2_manifest_encrypted.bin", info.encrypted_manifest);

        status << "magic=0x" << std::hex << std::uppercase << info.magic << std::dec << "\n";
        status << "version=" << info.version << "\n";
        status << "has_first=" << (info.has_first ? 1 : 0) << "\n";
        status << "first=" << info.first << "\n";
        status << "has_second=" << (info.has_second ? 1 : 0) << "\n";
        status << "second=" << info.second << "\n";
        status << "marker=" << static_cast<unsigned int>(info.marker) << "\n";
        status << "file_count=" << info.file_count << "\n";
        status << "wrapped_key_bytes=" << info.wrapped_key.size() << "\n";
        status << "manifest_encrypted_bytes=" << info.encrypted_manifest.size() << "\n";

        uint32_t file_count = info.file_count;
        if(file_count > 10000)
            file_count = 10000;

        for(uint32_t i = 0; i < file_count; ++i)
        {
            std::vector<unsigned char> blob;
            std::string path = "/file/" + std::to_string(i);
            if(!HttpGet(host, port, path, blob))
            {
                status << "file_" << i << "=fetch_failed\n";
                continue;
            }

            std::ostringstream name;
            name << "file_" << i << ".bin";
            WriteAll(root / name.str(), blob);
            status << "file_" << i << "_bytes=" << blob.size() << "\n";
        }

        WriteText(root / "status.txt", status.str());
    }

    inline void StartCacheDumpAsync(const std::string& host, unsigned short port, const std::filesystem::path& exe_dir)
    {
        std::thread([host, port, exe_dir]()
        {
            DumpCache(host, port, exe_dir);
        }).detach();
    }
}
