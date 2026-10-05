#include "test_harness.h"
#include <brocas/hash.h>
#include <brocas/manifest.h>
#include <brocas/socket_transport.h>
#include <brocas/store.h>
#include <brocas/sync.h>

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#else
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

using namespace bro::cas;
using namespace bro::cas::test;

namespace {

std::filesystem::path get_self_exe() {
#if defined(_WIN32)
    char buf[MAX_PATH];
    GetModuleFileNameA(NULL, buf, MAX_PATH);
    return std::filesystem::path(buf);
#elif defined(__APPLE__)
    char buf[1024];
    uint32_t size = sizeof(buf);
    if (_NSGetExecutablePath(buf, &size) == 0) {
        return std::filesystem::canonical(buf);
    }
    return "";
#else
    char buf[1024];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len > 0) {
        buf[len] = '\0';
        return std::filesystem::path(buf);
    }
    return "";
#endif
}

struct ChildProcess {
#if defined(_WIN32)
    PROCESS_INFORMATION pi{};
#else
    pid_t pid = -1;
#endif

    bool spawn(const std::vector<std::string>& args) {
#if defined(_WIN32)
        std::string cmd;
        for (size_t i = 0; i < args.size(); ++i) {
            if (i > 0) cmd += " ";
            cmd += "\"" + args[i] + "\"";
        }
        STARTUPINFOA si{};
        si.cb = sizeof(si);
        std::vector<char> cmd_buf(cmd.begin(), cmd.end());
        cmd_buf.push_back('\0');
        BOOL ok = CreateProcessA(NULL, cmd_buf.data(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
        return ok != FALSE;
#else
        pid = fork();
        if (pid == 0) {
            std::vector<char*> c_args;
            for (const auto& a : args) {
                c_args.push_back(const_cast<char*>(a.c_str()));
            }
            c_args.push_back(nullptr);
            execv(c_args[0], c_args.data());
            _exit(127);
        }
        return pid > 0;
#endif
    }

    void kill() {
#if defined(_WIN32)
        if (pi.hProcess) {
            TerminateProcess(pi.hProcess, 1);
            WaitForSingleObject(pi.hProcess, 3000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            pi.hProcess = NULL;
            pi.hThread = NULL;
        }
#else
        if (pid > 0) {
            ::kill(pid, SIGKILL);
            waitpid(pid, nullptr, 0);
            pid = -1;
        }
#endif
    }

    int wait() {
#if defined(_WIN32)
        if (pi.hProcess) {
            WaitForSingleObject(pi.hProcess, INFINITE);
            DWORD code = 0;
            GetExitCodeProcess(pi.hProcess, &code);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            pi.hProcess = NULL;
            pi.hThread = NULL;
            return static_cast<int>(code);
        }
        return -1;
#else
        if (pid > 0) {
            int status = 0;
            waitpid(pid, &status, 0);
            pid = -1;
            if (WIFEXITED(status)) return WEXITSTATUS(status);
            return -1;
        }
        return -1;
#endif
    }
};

// Limiting proxy transport used by worker when --exit-after-chunks is set
class CrashAfterNChunksTransport : public ITransport {
public:
    CrashAfterNChunksTransport(ITransport& inner, size_t max_chunks)
        : inner_(inner), max_chunks_(max_chunks) {}

    bool send_frame(const Frame& f) override {
        if (f.type == MessageType::ChunkData) {
            chunks_sent_++;
            if (chunks_sent_ > max_chunks_) {
                // Abruptly exit process mid-transfer
                std::cerr << "[worker] Abruptly crashing process after sending " << max_chunks_ << " chunk(s)\n";
                std::exit(42);
            }
        }
        return inner_.send_frame(f);
    }

    std::optional<Frame> recv_frame() override { return inner_.recv_frame(); }
    void close() override { inner_.close(); }
    bool is_connected() const override { return inner_.is_connected(); }

private:
    ITransport& inner_;
    size_t max_chunks_;
    size_t chunks_sent_ = 0;
};

int run_worker(const std::filesystem::path& store_dir, const std::string& port_filename, size_t max_chunks) {
    Store store(store_dir);

    auto server = SocketTransport::Server::listen(0);
    if (!server) {
        std::cerr << "[worker] Failed to listen on socket\n";
        return 1;
    }

    uint16_t port = server->port();
    auto port_file = store_dir / port_filename;
    {
        std::ofstream ofs(port_file);
        ofs << port << "\n";
    }

    auto client_sock = server->accept_client(15000);
    if (!client_sock) {
        std::cerr << "[worker] Accept timeout\n";
        return 2;
    }

    SyncSender sender(store);
    if (max_chunks > 0) {
        CrashAfterNChunksTransport crash_t(*client_sock, max_chunks);
        sender.run(crash_t);
    } else {
        sender.run(*client_sock);
    }

    return 0;
}

uint16_t wait_for_port(const std::filesystem::path& port_file) {
    for (int i = 0; i < 200; ++i) { // Up to 10 seconds
        if (std::filesystem::exists(port_file)) {
            std::ifstream ifs(port_file);
            uint16_t port = 0;
            if (ifs >> port && port > 0) {
                return port;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return 0;
}

} // namespace

void test_sync_cross_process_interruption_and_resume() {
    auto self_exe = get_self_exe();
    TEST_CHECK_FALSE(self_exe.empty());
    std::cout << "Running cross-process sync test via executable: " << self_exe.string() << std::endl;

    ScopedTempDir src_dir("test_proc_src");
    ScopedTempDir dst_dir("test_proc_dst");
    ScopedTempDir sender_store_dir("test_proc_sender_store");
    ScopedTempDir receiver_store_dir("test_proc_recv_store");

    Store sender_store(sender_store_dir.path());
    Store receiver_store(receiver_store_dir.path());

    // Generate rich dataset with multiple files and chunks
    src_dir.create_file("small1.txt", "Hello world from brocas cross-process sync!");
    src_dir.create_file("small2.txt", "Another small configuration file.");
    src_dir.create_dir("nested");
    src_dir.create_binary_file("nested/chunked1.bin", 128 * 1024, 0xAA);
    src_dir.create_binary_file("nested/chunked2.bin", 256 * 1024, 0xBB);

    IngestOptions opts;
    opts.chunk_threshold = 32 * 1024;
    opts.chunk_options.min_size = 4096;
    opts.chunk_options.avg_size = 16384;
    opts.chunk_options.max_size = 65536;

    Hash256 root_hash = ingest_directory(sender_store, src_dir.path(), opts);
    TEST_CHECK_FALSE(root_hash.is_zero());

    // Count total unique chunks needed
    auto all_hashes = collect_manifest_reachable_hashes(sender_store, root_hash);
    std::cout << "Dataset has " << all_hashes.size() << " reachable CAS chunks/manifests.\n";
    TEST_CHECK_TRUE(all_hashes.size() >= 5);

    // --- PHASE 1: Interrupted Transfer across Process Boundary ---
    std::cout << "Phase 1: Starting worker with crash limit (max 1 chunk)...\n";
    ChildProcess worker1;
    std::vector<std::string> args1 = {
        self_exe.string(),
        "--worker",
        sender_store_dir.path().string(),
        "port1.txt",
        "--exit-after-chunks",
        "1"
    };

    TEST_CHECK_TRUE(worker1.spawn(args1));

    uint16_t port1 = wait_for_port(sender_store_dir.path() / "port1.txt");
    TEST_CHECK_TRUE(port1 > 0);
    std::cout << "Phase 1: Connected to worker on port " << port1 << "\n";

    auto client1 = SocketTransport::connect("127.0.0.1", port1);
    TEST_CHECK_TRUE(client1 != nullptr);

    SyncReceiver receiver(receiver_store);
    SyncStats stats1;
    bool ok1 = receiver.sync_manifest(*client1, root_hash, &stats1);

    // Sync MUST fail because the worker crashed abruptly after 1 chunk!
    TEST_CHECK_FALSE(ok1);
    std::cout << "Phase 1: Transfer interrupted as expected! Chunks received before crash: "
              << stats1.chunks_received << std::endl;
    TEST_CHECK_EQ(stats1.chunks_received, 1U);

    client1->close();
    int exit_code1 = worker1.wait();
    std::cout << "Phase 1: Worker exited with code " << exit_code1 << " (expected 42)\n";
    TEST_CHECK_EQ(exit_code1, 42);

    // Verify receiver store has exactly 1 data chunk plus manifest chunks received so far
    size_t partial_count = 0;
    for (const auto& h : all_hashes) {
        if (receiver_store.has_chunk(h)) {
            partial_count++;
        }
    }
    TEST_CHECK_TRUE(partial_count >= 1);
    TEST_CHECK_TRUE(partial_count < all_hashes.size());

    // --- PHASE 2: Resumption across Process Boundary ---
    std::cout << "Phase 2: Starting new worker for resumption (no crash limit)...\n";
    ChildProcess worker2;
    std::vector<std::string> args2 = {
        self_exe.string(),
        "--worker",
        sender_store_dir.path().string(),
        "port2.txt"
    };

    TEST_CHECK_TRUE(worker2.spawn(args2));

    uint16_t port2 = wait_for_port(sender_store_dir.path() / "port2.txt");
    TEST_CHECK_TRUE(port2 > 0);
    std::cout << "Phase 2: Connected to worker on port " << port2 << "\n";

    auto client2 = SocketTransport::connect("127.0.0.1", port2);
    TEST_CHECK_TRUE(client2 != nullptr);

    SyncStats stats2;
    bool ok2 = receiver.sync_manifest(*client2, root_hash, &stats2);
    TEST_CHECK_TRUE(ok2);
    std::cout << "Phase 2: Resume completed successfully! Resumed chunks transferred: "
              << stats2.chunks_received << ", bytes: " << stats2.bytes_transferred << std::endl;

    // The resumed run should only have requested what was missing!
    TEST_CHECK_EQ(stats2.chunks_received, all_hashes.size() - partial_count);

    client2->close();
    worker2.wait();

    std::cout << "Phase 3: Checking out synced tree and verifying byte-exactness...\n";
    auto cstats = checkout_directory(receiver_store, root_hash, dst_dir.path());
    TEST_CHECK_TRUE(cstats.files_created >= 4);

    // Verify small files
    auto read_file = [](const std::filesystem::path& p) -> std::string {
        std::ifstream f(p, std::ios::binary);
        return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    };

    TEST_CHECK_EQ(read_file(dst_dir.path() / "small1.txt"), "Hello world from brocas cross-process sync!");
    TEST_CHECK_EQ(read_file(dst_dir.path() / "small2.txt"), "Another small configuration file.");

    // Verify binary files
    std::string bin1_orig = read_file(src_dir.path() / "nested" / "chunked1.bin");
    std::string bin1_sync = read_file(dst_dir.path() / "nested" / "chunked1.bin");
    TEST_CHECK_EQ(bin1_orig.size(), bin1_sync.size());
    TEST_CHECK_EQ(bin1_orig, bin1_sync);

    std::string bin2_orig = read_file(src_dir.path() / "nested" / "chunked2.bin");
    std::string bin2_sync = read_file(dst_dir.path() / "nested" / "chunked2.bin");
    TEST_CHECK_EQ(bin2_orig.size(), bin2_sync.size());
    TEST_CHECK_EQ(bin2_orig, bin2_sync);

    std::cout << "Phase 3: All checked-out files match byte-for-byte with source!\n";
}

int main(int argc, char** argv) {
    if (argc >= 4 && std::string(argv[1]) == "--worker") {
        std::filesystem::path store_dir = argv[2];
        std::string port_file = argv[3];
        size_t max_chunks = 0;
        if (argc >= 6 && std::string(argv[4]) == "--exit-after-chunks") {
            max_chunks = std::stoull(argv[5]);
        }
        return run_worker(store_dir, port_file, max_chunks);
    }

    test_sync_cross_process_interruption_and_resume();
    std::cout << "All cross-process sync tests passed!" << std::endl;
    return 0;
}
