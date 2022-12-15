
#include "higu_debug.hpp"

#include <iostream>
#include <iomanip>
#include <cstring>
#include <set>
#include <thread>

#include "common/Logger.hpp"

#include "interfaces/ITwibDeviceInterface.hpp"

namespace twili::twib::tool {

const uint64_t higurashi_title_id = 0x100f6a00a684000;
const std::array<uint8_t, 32> higurashi_main_build_id = {12, 40, 177, 33, 186, 199, 128, 28, 61, 207, 249, 59, 129, 130, 11, 250,
                                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
const uint64_t higurashi_debugout_hook_offset = 0xadc0;
const std::array<uint8_t, 4> aarch64_brk = {0x00, 0x00, 0x20, 0xd4};

const auto higurashi_wait_init = std::chrono::seconds(4);

template<size_t N>
static void PrintTable(std::vector<std::array<std::string, N>> rows) {
    std::array<int, N> lengths = {0};
    for(auto r : rows) {
        for(size_t i = 0; i < N; i++) {
            if(r[i].size() > lengths[i]) {
                lengths[i] = r[i].size();
            }
        }
    }
    for(auto r : rows) {
        for(size_t i = 0; i < N; i++) {
            printf("%-*s%s", lengths[i], r[i].c_str(), (i + 1 == N) ? "\n" : " | ");
        }
    }
}

template<typename T>
static std::string ToHex(T num, int width, bool prefix) {
    std::stringstream stream;
    stream << (prefix ? "0x" : "") << std::setfill('0') << std::setw(width) << std::hex << num;
    return stream.str();
}

static std::string BuildIdToString(uint8_t* build_id) {
    std::stringstream stream;
    for (int i = 0; i < 32; i++) {
        stream << ToHex(uint32_t(build_id[i]), 2, false);
    }
    return stream.str();
}

static void print_modules_info(std::vector<nx::LoadedModuleInfo>& modules) {
    std::vector<std::array<std::string, 3>> rows;
    rows.push_back({"Base Address", "Size", "Build ID"});
    for (auto module : modules) {
        rows.push_back({ToHex(module.base_addr, 16, true),
                        ToHex(module.size, 6, true),
                        BuildIdToString(module.build_id)});
    }
    PrintTable(rows);
}

static std::optional<nx::LoadedModuleInfo> find_main_module(std::vector<nx::LoadedModuleInfo>&& modules) {
    for (auto module : modules) {
        if (memcmp(module.build_id, higurashi_main_build_id.data(), 32) == 0) {
            return module;
        }
    }
    return {};
}

class Breakpoint {
private:
    ITwibDebugger& debugger;
    std::array<uint8_t, 4> old_instruction{};
    uint64_t address;
    bool is_set;

    template<size_t N>
    void write_memory(uint64_t dst_address, std::array<uint8_t, N> data) {
        std::vector<uint8_t> vect(data.begin(), data.end());
        debugger.WriteMemory(dst_address, vect);
    }
public:
    Breakpoint(ITwibDebugger& debugger, uint64_t address)
            : debugger(debugger), address(address), is_set(true)
    {
        auto old_instr_vect = debugger.ReadMemory(address, 4);
        for (int i = 0; i < 4; i++)
            old_instruction[i] = old_instr_vect[i];

        write_memory(address, aarch64_brk);
    }

    void set() {
        if (!is_set) {
            write_memory(address, aarch64_brk);
        }
    }

    void unset() {
        if (is_set) {
            write_memory(address, old_instruction);
        }
    }
};


struct DEBUGOUT_param {
    uint64_t pstring;
    uint32_t argument_count;
    int32_t arguments[5];
} __attribute__((packed));

class HiguDebugger {
    ITwibDebugger debugger;
    uint64_t main_module_base;
    std::set<uint64_t> threads;
    std::vector<Breakpoint> breakpoints;

    void continue_execution() {
        std::vector<uint64_t> threads_vect(threads.begin(), threads.end());
        debugger.ContinueDebugEvent(7, threads_vect);
    }

    static void debugout(std::string& str, std::vector<int32_t>& arguments) {

        std::string formatted;

        int argument_index = 0;

        for (int i = 0; i < str.length(); i++) {
            if (str[i] == '%') {
                i++;
                if (str[i] == '%') {
                    formatted += '%';
                } else if (str[i] == 'd') {
                    formatted += std::to_string(arguments[argument_index++]);
                } else if (str[i] == 'x') {
                    formatted += ToHex(arguments[argument_index++], 0, false);
                } else {
                    formatted += "{WTF}";
                    argument_index++;
                }
            } else {
                formatted += str[i];
            }
        }

        std::cout << "DEBUGOUT: " << formatted << std::endl;
    }

    void handle_debugout_hook(ThreadContext& tc) {
        uint64_t pDEBUGOUT_param = tc.x[1];
        uint64_t pstr_size = tc.x[2] - 1;

        tc.pc += 4;

        auto DEBUGOUT_param_data = debugger.ReadMemory(pDEBUGOUT_param, sizeof(DEBUGOUT_param));
        auto param = reinterpret_cast<const DEBUGOUT_param*>(DEBUGOUT_param_data.data());
        auto string_data = debugger.ReadMemory(param->pstring, pstr_size);
        auto string_value = std::string(string_data.begin(), string_data.end());
        std::vector<int32_t> arguments;
        arguments.reserve(param->argument_count);
        for (int i = 0; i < param->argument_count; i++) {
            arguments.emplace_back(param->arguments[i]);
        }

        debugout(string_value, arguments);
    }

    void handle_breakpoint(uint64_t thread_id) {
        ThreadContext ctx = debugger.GetThreadContext(thread_id);
        uint64_t pc = ctx.pc;
        if (pc == main_module_base + higurashi_debugout_hook_offset) {
            handle_debugout_hook(ctx);
            debugger.SetThreadContext(thread_id, ctx);
        } else {
            LogMessage(Error, "Unexpected breakpoint");
            throw std::exception();
        }
    }

public:
    explicit HiguDebugger(ITwibDebugger debugger) : debugger(debugger) {
        auto main_module = find_main_module(debugger.GetNsoInfos());
        if (!main_module.has_value()) {
            LogMessage(Error, "Cannot find expected higurashi mso in the address space");
            throw std::exception();
        }
        main_module_base = main_module->base_addr;
    }

    int run_loop() {
        breakpoints.emplace_back(debugger, main_module_base + higurashi_debugout_hook_offset);

        do {
            auto event_box = debugger.GetDebugEvent();
            if (event_box.has_value()) {
                auto event = event_box.value();
                if (event.event_type == nx::DebugEvent::EventType::AttachThread) {
                    threads.emplace(event.thread_id);
                } else if (event.event_type == nx::DebugEvent::EventType::AttachProcess) {
                } else if (event.event_type == nx::DebugEvent::EventType::ExitProcess) {
                    return 0;
                } else if (event.event_type == nx::DebugEvent::EventType::ExitThread) {
                    threads.erase(event.thread_id);
                } else if (event.event_type == nx::DebugEvent::EventType::Exception) {
                    switch (event.exception.exception_type) {
                        case nx::DebugEvent::ExceptionType::DebuggerAttached:
                            LogMessage(Warning, "debugger attached");
                            break;
                        case nx::DebugEvent::ExceptionType::Trap:
                            handle_breakpoint(event.thread_id);
                            break;
                        case nx::DebugEvent::ExceptionType::BreakPoint:
                        case nx::DebugEvent::ExceptionType::InstructionAbort:
                        case nx::DebugEvent::ExceptionType::DataAbortMisc:
                        case nx::DebugEvent::ExceptionType::PcSpAlignmentFault:
                        case nx::DebugEvent::ExceptionType::UserBreak:
                        case nx::DebugEvent::ExceptionType::DebuggerBreak:
                        case nx::DebugEvent::ExceptionType::BadSvcId:
                        case nx::DebugEvent::ExceptionType::SError:
                            LogMessage(Error, "Unexpected exception");
                            return 1;
                    }
                }
                continue_execution();
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        } while (true);
    }
};

std::optional<uint64_t> find_higurashi_process(tool::ITwibDeviceInterface& itdi) {
    auto processes = itdi.ListProcesses();
    for (auto p : processes) {
        if (p.title_id == higurashi_title_id) {
            return p.process_id;
        }
    }
    return {};
}

uint64_t wait_for_higurashi_process(tool::ITwibDeviceInterface& itdi) {
    while (true) {
        auto higurashi_pid_opt = find_higurashi_process(itdi);
        if (higurashi_pid_opt.has_value())
            return higurashi_pid_opt.value();
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
}

int run_higu_debug(tool::ITwibDeviceInterface& itdi) {
    auto higurashi_pid_opt = find_higurashi_process(itdi);
    uint64_t higurashi_pid;
    if (!higurashi_pid_opt.has_value()) {
        std::cout << "Cannot find running higurashi process, waiting" << std::endl;
        higurashi_pid = wait_for_higurashi_process(itdi);
        std::this_thread::sleep_for(higurashi_wait_init);
    } else {
        higurashi_pid = higurashi_pid_opt.value();
    }

    while (true) {
        std::cout << "higurashi_pid = " << higurashi_pid << std::endl;

        {
            HiguDebugger h_debugger(std::move(itdi.OpenActiveDebugger(higurashi_pid)));
            int r = h_debugger.run_loop();
            if (r != 0)
                return r;
        }

        std::cout << "Waiting for higurashi process again..." << std::endl;
        higurashi_pid = wait_for_higurashi_process(itdi);
        std::this_thread::sleep_for(higurashi_wait_init);
    }
}

}

