#pragma once

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <windows.h>

namespace ragnarok
{
    struct RuntimeConfig
    {
        std::string server = "127.0.0.1:22005";
        std::string player_name = "RagnarokPlayer";
        std::string serial = "rage-mp";
        std::string social = "rsc";
        std::string password = "";
        std::string audit_probe = "";
        std::filesystem::path event_scan_file;
        uint32_t event_scan_interval_ms = 500;
        uint32_t event_scan_claimed_bytes = 256;
        std::filesystem::path heap_dump_dir;
        uint32_t heap_dump_bytes = 65535;
        uint32_t heap_dump_interval_ms = 5000;
        uint64_t rgsc_id = 0x1122334455667788ULL;
        bool split_stress = false;
        bool split_stress_duplicate_completion = true;
        bool split_stress_large_count_prealloc = false;
        bool split_stress_large_fragment_payload = false;
        bool split_stress_mixed_duplicate_missing = false;
        bool split_stress_many_split_id = false;
        uint32_t split_stress_after_event_delay_ms = 250;
        uint32_t split_stress_rounds = 0;
        uint32_t split_stress_split_count = 0x51EC;
        uint32_t split_stress_fragment_bytes = 1200;
        uint32_t split_stress_prealloc_sets = 2048;
        uint32_t split_stress_many_ids_per_round = 2048;
        uint32_t split_stress_mixed_count = 4096;
        uint32_t split_stress_sleep_every = 0;
        uint32_t split_stress_sleep_us = 0;
        uint32_t split_stress_log_every = 50000;
        uint32_t split_stress_max_client_queue = 1024;
        uint32_t split_stress_queue_wait_ms = 0;
    };

    inline std::string Trim(std::string v)
    {
        while(!v.empty() && (v.back() == '\n' || v.back() == '\r' || v.back() == ' ' || v.back() == '\t'))
            v.pop_back();

        size_t p = 0;
        while(p < v.size() && (v[p] == ' ' || v[p] == '\t'))
            ++p;

        return p ? v.substr(p) : v;
    }

    inline std::filesystem::path ExeDir()
    {
        std::wstring buf(32768, L'\0');
        DWORD len = GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
        if(!len)
            return {};

        buf.resize(len);
        return std::filesystem::path(buf).parent_path();
    }

    inline bool ParseBoolConfig(std::string v)
    {
        std::transform(v.begin(), v.end(), v.begin(), [](unsigned char c)
        {
            return static_cast<char>(std::tolower(c));
        });

        return v == "1" || v == "true" || v == "yes" || v == "on";
    }

    inline void ReadU32Config(const std::string& value, uint32_t& out)
    {
        try
        {
            out = static_cast<uint32_t>(std::stoul(value, nullptr, 0));
        }
        catch(...)
        {
        }
    }

    inline bool LoadConfig(const std::filesystem::path& path, RuntimeConfig& cfg)
    {
        if(!std::filesystem::exists(path))
        {
            std::ofstream out(path, std::ios::binary | std::ios::trunc);
            out << "# Ragnarok client config\n";
            out << "server=127.0.0.1:22005\n";
            out << "name=RagnarokPlayer\n";
            out << "serial=rage-mp\n";
            out << "social=rsc\n";
            out << "rgsc=1122334455667788\n";
            out << "password=\n";
            out << "split_stress=0\n";
            out << "split_stress_duplicate_completion=1\n";
            out << "split_stress_large_count_prealloc=0\n";
            out << "split_stress_large_fragment_payload=0\n";
            out << "split_stress_mixed_duplicate_missing=0\n";
            out << "split_stress_many_split_id=0\n";
            out << "split_stress_after_event_delay_ms=250\n";
            out << "split_stress_rounds=0\n";
            out << "split_stress_split_count=0x51EC\n";
            out << "split_stress_fragment_bytes=1200\n";
            out << "split_stress_prealloc_sets=2048\n";
            out << "split_stress_many_ids_per_round=2048\n";
            out << "split_stress_mixed_count=4096\n";
            out << "split_stress_sleep_every=0\n";
            out << "split_stress_sleep_us=0\n";
            out << "split_stress_log_every=50000\n";
            out << "split_stress_max_client_queue=1024\n";
            out << "split_stress_queue_wait_ms=0\n";
            return true;
        }

        std::ifstream in(path);
        if(!in)
            return false;

        for(std::string line; std::getline(in, line);)
        {
            line = Trim(line);
            if(line.empty() || line[0] == '#')
                continue;

            auto eq = line.find('=');
            if(eq == std::string::npos)
                continue;

            std::string key = Trim(line.substr(0, eq));
            std::string val = Trim(line.substr(eq + 1));

            if(key == "server")
            {
                if(!val.empty())
                    cfg.server = val;
            }
            else if(key == "name")
            {
                cfg.player_name = val;
            }
            else if(key == "serial")
            {
                cfg.serial = val;
            }
            else if(key == "social")
            {
                cfg.social = val;
            }
            else if(key == "password")
            {
                cfg.password = val;
            }
            else if(key == "rgsc")
            {
                try
                {
                    cfg.rgsc_id = std::stoull(val, nullptr, 16);
                }
                catch(...)
                {
                    cfg.rgsc_id = 0;
                }
            }
            else if(key == "split_stress")
                cfg.split_stress = ParseBoolConfig(val);
            else if(key == "split_stress_duplicate_completion")
                cfg.split_stress_duplicate_completion = ParseBoolConfig(val);
            else if(key == "split_stress_large_count_prealloc")
                cfg.split_stress_large_count_prealloc = ParseBoolConfig(val);
            else if(key == "split_stress_large_fragment_payload")
                cfg.split_stress_large_fragment_payload = ParseBoolConfig(val);
            else if(key == "split_stress_mixed_duplicate_missing")
                cfg.split_stress_mixed_duplicate_missing = ParseBoolConfig(val);
            else if(key == "split_stress_many_split_id")
                cfg.split_stress_many_split_id = ParseBoolConfig(val);
            else if(key == "split_stress_after_event_delay_ms")
                ReadU32Config(val, cfg.split_stress_after_event_delay_ms);
            else if(key == "split_stress_rounds")
                ReadU32Config(val, cfg.split_stress_rounds);
            else if(key == "split_stress_split_count")
                ReadU32Config(val, cfg.split_stress_split_count);
            else if(key == "split_stress_fragment_bytes")
                ReadU32Config(val, cfg.split_stress_fragment_bytes);
            else if(key == "split_stress_prealloc_sets")
                ReadU32Config(val, cfg.split_stress_prealloc_sets);
            else if(key == "split_stress_many_ids_per_round")
                ReadU32Config(val, cfg.split_stress_many_ids_per_round);
            else if(key == "split_stress_mixed_count")
                ReadU32Config(val, cfg.split_stress_mixed_count);
            else if(key == "split_stress_sleep_every")
                ReadU32Config(val, cfg.split_stress_sleep_every);
            else if(key == "split_stress_sleep_us")
                ReadU32Config(val, cfg.split_stress_sleep_us);
            else if(key == "split_stress_log_every")
                ReadU32Config(val, cfg.split_stress_log_every);
            else if(key == "split_stress_max_client_queue")
                ReadU32Config(val, cfg.split_stress_max_client_queue);
            else if(key == "split_stress_queue_wait_ms")
                ReadU32Config(val, cfg.split_stress_queue_wait_ms);
        }

        return true;
    }

    inline std::mt19937_64& IdentityRng()
    {
        static std::mt19937_64 rng(
            (static_cast<uint64_t>(std::random_device{}()) << 32)
            ^ static_cast<uint64_t>(GetTickCount64())
            ^ 0xC0DEC0FFEEULL);
        return rng;
    }

    inline char RandomFrom(const char* alphabet, size_t len)
    {
        std::uniform_int_distribution<size_t> dist(0, len - 1);
        return alphabet[dist(IdentityRng())];
    }

    inline std::string RandomToken(size_t len, const char* alphabet)
    {
        std::string out;
        size_t alpha_len = 0;

        while(alphabet[alpha_len] != '\0')
            ++alpha_len;

        out.reserve(len);
        for(size_t i = 0; i < len; ++i)
            out.push_back(RandomFrom(alphabet, alpha_len));

        return out;
    }

    inline std::string BuildHumanWord(bool upper_first)
    {
        static constexpr const char* kStarts[] =
        {
            "al","an","ar","ash","av","be","br","cal","cor","da","de","dr",
            "el","em","er","fa","fi","ga","ha","ja","ka","ke","le","li",
            "ma","mi","na","no","ol","or","ra","re","sa","se","ta","te",
            "va","ve","wi","za"
        };
        static constexpr const char* kMids[] =
        {
            "bar","bel","cor","dan","den","dor","fal","gan","har","kas","kel",
            "lan","len","lor","mar","mon","nar","nor","ran","ren","ros","sel",
            "tan","tor","val","ver","vin","wen","yor","zen"
        };
        static constexpr const char* kEnds[] =
        {
            "a","ac","al","an","ar","as","en","er","es","i","ik","in","ir",
            "is","o","on","or","os","us","yn"
        };
        std::uniform_int_distribution<size_t> start_dist(0, (sizeof(kStarts) / sizeof(kStarts[0])) - 1);
        std::uniform_int_distribution<size_t> mid_dist(0, (sizeof(kMids) / sizeof(kMids[0])) - 1);
        std::uniform_int_distribution<size_t> end_dist(0, (sizeof(kEnds) / sizeof(kEnds[0])) - 1);
        std::uniform_int_distribution<int> mid_count_dist(0, 1);

        std::string out = kStarts[start_dist(IdentityRng())];
        int mids = mid_count_dist(IdentityRng());

        for(int i = 0; i < mids; ++i)
            out += kMids[mid_dist(IdentityRng())];

        out += kEnds[end_dist(IdentityRng())];

        if(upper_first && !out.empty())
            out[0] = static_cast<char>(toupper(static_cast<unsigned char>(out[0])));

        return out;
    }

    inline std::string RandomName()
    {
        std::uniform_int_distribution<int> style_dist(0, 2);
        std::uniform_int_distribution<int> number_dist(11, 99);
        int style = style_dist(IdentityRng());
        std::string first = BuildHumanWord(true);
        std::string second = BuildHumanWord(true);

        if(style == 0)
            return first;

        if(style == 1)
            return first + second;

        return first + std::to_string(number_dist(IdentityRng()));
    }

    inline std::string RandomSerial()
    {
        static constexpr char kHex[] = "0123456789ABCDEF";
        return RandomToken(32, kHex);
    }

    inline std::string RandomSocial()
    {
        std::uniform_int_distribution<int> style_dist(0, 3);
        std::uniform_int_distribution<int> year_dist(72, 99);
        std::uniform_int_distribution<int> num_dist(2, 999);
        int style = style_dist(IdentityRng());
        std::string first = BuildHumanWord(false);
        std::string second = BuildHumanWord(false);

        if(style == 0)
            return first + second;

        if(style == 1)
            return first + std::to_string(year_dist(IdentityRng()));

        if(style == 2)
            return first + second.substr(0, std::min<size_t>(4, second.size())) + std::to_string(num_dist(IdentityRng()));

        return first + second;
    }

    inline uint64_t RandomRgscId()
    {
        std::uniform_int_distribution<uint64_t> dist(100000000ULL, 4294967295ULL);
        return dist(IdentityRng());
    }

    inline void NormalizeIdentity(RuntimeConfig& cfg)
    {
        if(cfg.player_name.empty() || cfg.player_name == "RagnarokPlayer")
            cfg.player_name = RandomName();

        if(cfg.serial.empty() || cfg.serial == "rage-mp")
            cfg.serial = RandomSerial();

        if(cfg.social.empty() || cfg.social == "rsc")
            cfg.social = RandomSocial();

        if(cfg.rgsc_id == 0 || cfg.rgsc_id == 0x1122334455667788ULL)
            cfg.rgsc_id = RandomRgscId();
    }

    inline bool ParseIpPort(const std::string& server, std::string& host, unsigned short& port)
    {
        std::string value = Trim(server);
        auto p = value.find(':');
        if(p == std::string::npos)
            return false;

        host = Trim(value.substr(0, p));
        if(host.empty())
            return false;

        try
        {
            int v = std::stoi(Trim(value.substr(p + 1)));
            if(v <= 0 || v > 65535)
                return false;

            port = static_cast<unsigned short>(v);
            return true;
        }
        catch(...)
        {
            return false;
        }
    }
}
