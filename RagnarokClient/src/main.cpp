#include "config.hpp"
#include "logger.hpp"
#include "ragnarok_client.hpp"

#include <string>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

int wmain(int argc, wchar_t** argv)
{
    SetConsoleTitleW(L"Ragnarok");

    ragnarok::Logger logger;
    auto exe_dir = ragnarok::ExeDir();
    auto log_path = exe_dir / L"Ragnarok.log";
    logger.Start(log_path);

    ragnarok::RuntimeConfig cfg;
    auto cfg_path = exe_dir / L"Ragnarok.config";
    if(!ragnarok::LoadConfig(cfg_path, cfg))
    {
        logger.Push(ragnarok::LogLevel::Warn, "failed to read config, default created");
    }

    std::string override_server;
    if(argc > 1)
    {
        int wslen = WideCharToMultiByte(CP_UTF8, 0, argv[1], -1, nullptr, 0, nullptr, nullptr);
        if(wslen > 1)
        {
            override_server.resize(static_cast<size_t>(wslen - 1));
            WideCharToMultiByte(CP_UTF8, 0, argv[1], -1, override_server.data(), wslen, nullptr, nullptr);
        }
    }

    if(argc > 2)
    {
        int wslen = WideCharToMultiByte(CP_UTF8, 0, argv[2], -1, nullptr, 0, nullptr, nullptr);
        if(wslen > 1)
        {
            cfg.audit_probe.resize(static_cast<size_t>(wslen - 1));
            WideCharToMultiByte(CP_UTF8, 0, argv[2], -1, cfg.audit_probe.data(), wslen, nullptr, nullptr);
        }
    }

    if(cfg.audit_probe == "heap_dump" || cfg.audit_probe == "heap_dump_remote" ||
        cfg.audit_probe == "biz_order_dump_remote")
    {
        auto read_number = [&](int index, uint32_t& value) -> bool
        {
            if(argc <= index)
                return true;
            try
            {
                std::wstring raw(argv[index]);
                size_t used = 0;
                unsigned long parsed = std::stoul(raw, &used, 10);
                if(used != raw.size())
                    return false;
                value = static_cast<uint32_t>(parsed);
                return true;
            }
            catch(...)
            {
                return false;
            }
        };

        if(!read_number(3, cfg.heap_dump_bytes) ||
            !read_number(4, cfg.heap_dump_interval_ms))
        {
            logger.Push(ragnarok::LogLevel::Error, "heap dump byte count or interval is invalid");
            return 1;
        }
        if(argc > 5)
            cfg.heap_dump_dir = argv[5];
        if(cfg.heap_dump_bytes == 0 || cfg.heap_dump_bytes > 65535 ||
            (cfg.audit_probe == "biz_order_dump_remote" && cfg.heap_dump_bytes < 8))
        {
            logger.Push(ragnarok::LogLevel::Error,
                cfg.audit_probe == "biz_order_dump_remote"
                    ? "business heap dump requires 8..65535 bytes"
                    : "heap dump requires 1..65535 bytes");
            return 1;
        }
    }

    if(cfg.audit_probe == "repo_event_scan")
    {
        if(argc > 3)
            cfg.event_scan_file = argv[3];
        if(argc > 4)
        {
            try
            {
                std::wstring raw(argv[4]);
                size_t used = 0;
                unsigned long value = std::stoul(raw, &used, 10);
                if(used != raw.size() || value < 250 || value > 10000)
                    return 1;
                cfg.event_scan_interval_ms = static_cast<uint32_t>(value);
            }
            catch(...)
            {
                return 1;
            }
        }
        if(argc > 5)
        {
            try
            {
                std::wstring raw(argv[5]);
                size_t used = 0;
                unsigned long value = std::stoul(raw, &used, 10);
                if(used != raw.size() || value < 8 || value > 65535)
                    return 1;
                cfg.event_scan_claimed_bytes = static_cast<uint32_t>(value);
            }
            catch(...)
            {
                return 1;
            }
        }
    }

    logger.Push(ragnarok::LogLevel::Info, "config file: " + cfg_path.string());
    logger.Push(ragnarok::LogLevel::Info, "log file: " + log_path.string());
    logger.Push(ragnarok::LogLevel::Info, "press q or ESC for stop");
    logger.Push(ragnarok::LogLevel::Info, "audit probe: " + (cfg.audit_probe.empty() ? "legacy" : cfg.audit_probe));
    if(cfg.audit_probe == "heap_dump" || cfg.audit_probe == "heap_dump_remote" ||
        cfg.audit_probe == "biz_order_dump_remote")
    {
        logger.Push(ragnarok::LogLevel::Info, "heap dump claimed bytes=" + std::to_string(cfg.heap_dump_bytes)
            + ", interval_ms=" + std::to_string(cfg.heap_dump_interval_ms));
    }

    ragnarok::RagnarokClient client;
    if(!client.Init(std::move(logger), cfg, override_server))
        return 1;

    return client.Run();
}
