#pragma once

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <windows.h>

namespace ragnarok
{
    enum class LogLevel
    {
        Info,
        Success,
        Warn,
        Error,
        Network
    };

    struct Logger
    {
        HANDLE console = INVALID_HANDLE_VALUE;
        std::ofstream file;
        std::filesystem::path status_path;

        static std::string NowStamp()
        {
            SYSTEMTIME st = {};
            GetLocalTime(&st);

            std::ostringstream oss;
            oss << std::setfill('0')
                << std::setw(4) << st.wYear << '-'
                << std::setw(2) << st.wMonth << '-'
                << std::setw(2) << st.wDay << ' '
                << std::setw(2) << st.wHour << ':'
                << std::setw(2) << st.wMinute << ':'
                << std::setw(2) << st.wSecond << '.'
                << std::setw(3) << st.wMilliseconds;
            return oss.str();
        }

        void Start(const std::filesystem::path& log_path)
        {
            console = GetStdHandle(STD_OUTPUT_HANDLE);
            std::filesystem::remove(log_path);
            file.open(log_path, std::ios::binary | std::ios::trunc);

            status_path = log_path;
            status_path.replace_extension(".status");
            std::filesystem::remove(status_path);
        }

        void Push(LogLevel level, const std::string& msg)
        {
            static std::mutex push_mutex;
            std::lock_guard<std::mutex> lock(push_mutex);

            WORD color = 7;
            const char* prefix = "[i]";

            if(level == LogLevel::Success)
            {
                color = 10;
                prefix = "[+]";
            }
            else if(level == LogLevel::Warn)
            {
                color = 14;
                prefix = "[!]";
            }
            else if(level == LogLevel::Error)
            {
                color = 12;
                prefix = "[-]";
            }
            else if(level == LogLevel::Network)
            {
                color = 11;
                prefix = "[n]";
            }

            std::string line = NowStamp() + " " + prefix + " " + msg + "\n";

            if(console != INVALID_HANDLE_VALUE)
            {
                SetConsoleTextAttribute(console, color);
                std::cout << line;
                SetConsoleTextAttribute(console, 7);
            }

            if(file.good())
            {
                file << line;
                file.flush();
            }
        }

        void Status(const std::string& msg)
        {
            if(status_path.empty())
                return;

            static std::mutex status_mutex;
            std::lock_guard<std::mutex> lock(status_mutex);

            std::ofstream out(status_path, std::ios::binary | std::ios::app);
            if(out.good())
                out << NowStamp() << " " << msg << "\n";
        }
    };
}
