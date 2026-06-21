#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
using socket_t = SOCKET;
using gbp_socklen_t = int;
inline socket_t invalid_socket() { return INVALID_SOCKET; }
inline bool is_invalid_socket(socket_t fd) { return fd == INVALID_SOCKET; }
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
using socket_t = int;
using gbp_socklen_t = socklen_t;
inline socket_t invalid_socket() { return -1; }
inline bool is_invalid_socket(socket_t fd) { return fd < 0; }
#endif

namespace gbp {

constexpr uint32_t GBP_BATCH_PAGE_NUM = 100;
constexpr uint32_t GBP_PAGE_SIZE = 8192;
constexpr uint32_t GBP_MSG_LEN = 64;
constexpr uint32_t GBP_META_CHUNK_NUM = 1024;
constexpr uint32_t OG_GBP_SESSION_COUNT = 8;
constexpr uint32_t LOG_POINT_SIZE = 24;
constexpr uint32_t LOG_POINT_ALIGN = 8;

constexpr uint32_t GBP_REQ_PAGE_READ = 20000;
constexpr uint32_t GBP_REQ_PAGE_WRITE = 20100;
constexpr uint32_t GBP_REQ_BATCH_PAGE_READ = 21000;
constexpr uint32_t GBP_REQ_READ_META_CHUNK = 22000;
constexpr uint32_t GBP_REQ_BATCH_PAGE_READ_SELECTED = 23000;
constexpr uint32_t GBP_REQ_READ_CKPT = 31000;
constexpr uint32_t GBP_REQ_NOTIFY_MSG = 41000;
constexpr uint32_t GBP_REQ_SHAKE_HAND = 51000;
constexpr uint32_t GBP_REQ_CLOSE_CONN = 61000;

constexpr uint32_t MSG_GBP_INVALID = 0;
constexpr uint32_t MSG_GBP_READ_BEGIN = 1;
constexpr uint32_t MSG_GBP_READ_END = 2;
constexpr uint32_t ACK_GBP_INVALID = 0;
constexpr uint32_t ACK_GBP_READ_BEGIN = 1;

constexpr uint32_t GBP_READ_RESULT_OK = 0;
constexpr uint32_t GBP_READ_RESULT_NOPAGE = 1;
constexpr uint32_t GBP_READ_RESULT_ERROR = 2;

constexpr uint32_t OG_PROTO_CODE = 0x98BADCFE;
constexpr uint32_t CS_HANDSHAKE_VERSION = 23;
constexpr uint16_t CS_FLAG_DN_CONN = 0x8000;

constexpr uint64_t INF_LFN = (1ULL << 46) - 1;

struct page_id_t {
    uint32_t page;
    uint16_t file;
    uint16_t aligned;
};

struct log_point_t {
    uint32_t asn;
    uint32_t block_id;
    uint64_t rst_id : 18;
    uint64_t lfn : 46;
    uint64_t lsn;
};

struct gbp_msg_hdr_t {
    uint32_t msg_type;
    uint32_t msg_length;
    uint32_t queue_id;
    int32_t msg_fd;
};

struct gbp_msg_ack_t {
    gbp_msg_hdr_t header;
    uint32_t ack_type;
    uint32_t ack_data;
};

struct gbp_page_item_t {
    page_id_t page_id;
    uint32_t session_id;
    uint32_t writer_inst_id;
    uint64_t writer_global_seq;
    log_point_t gbp_trunc_point;
    log_point_t gbp_lrp_point;
    char block[GBP_PAGE_SIZE];
};

struct gbp_read_req_t {
    gbp_msg_hdr_t header;
    page_id_t page_id;
    uint16_t buf_pool_id;
    uint16_t reserved[3];
};

struct gbp_batch_read_req_t {
    gbp_msg_hdr_t header;
    log_point_t gbp_skip_point;
};

struct gbp_meta_item_t {
    page_id_t page_id;
    uint64_t page_lsn;
    uint32_t page_pcn;
    uint32_t source_node;
    uint32_t queue_id;
    uint32_t reserved;
};

struct gbp_read_meta_req_t {
    gbp_msg_hdr_t header;
    uint64_t epoch;
    uint64_t cursor;
    uint32_t max_count;
    uint32_t reserved;
};

struct gbp_read_meta_resp_t {
    gbp_msg_hdr_t header;
    uint32_t result;
    uint32_t count;
    uint64_t epoch;
    uint64_t cursor;
    uint64_t next_cursor;
    uint64_t total_count;
    uint32_t done;
    uint32_t reserved;
    gbp_meta_item_t items[GBP_META_CHUNK_NUM];
};

struct gbp_selected_page_req_t {
    page_id_t page_id;
    uint64_t selected_lsn;
};

struct gbp_batch_selected_read_req_t {
    gbp_msg_hdr_t header;
    uint32_t count;
    uint32_t reserved;
    gbp_selected_page_req_t pages[GBP_BATCH_PAGE_NUM];
};

struct gbp_write_req_t {
    gbp_msg_hdr_t header;
    uint32_t page_num;
    log_point_t batch_begin_point;
    log_point_t batch_trunc_point;
    log_point_t batch_lrp_point;
    gbp_page_item_t pages[GBP_BATCH_PAGE_NUM];
    uint32_t page_num_tail;
};

struct gbp_read_ckpt_req_t {
    gbp_msg_hdr_t header;
    uint32_t check_end_point;
    uint32_t _pad;
    log_point_t aly_end_point;
};

struct gbp_read_resp_t {
    gbp_msg_hdr_t header;
    uint32_t result;
    uint32_t unused;
    page_id_t pageid;
    log_point_t gbp_trunc_point;
    char block[GBP_PAGE_SIZE];
};

struct gbp_batch_read_resp_t {
    gbp_msg_hdr_t header;
    uint32_t result;
    uint32_t count;
    char msg[GBP_MSG_LEN];
    gbp_page_item_t pages[GBP_BATCH_PAGE_NUM];
};

struct gbp_read_ckpt_resp_t {
    gbp_msg_hdr_t header;
    uint32_t gbp_unsafe;
    uint32_t _pad;
    log_point_t begin_point;
    log_point_t rcy_point;
    log_point_t lrp_point;
    uint64_t max_lsn;
    char unsafe_reason[GBP_MSG_LEN];
};

constexpr size_t HDR_SIZE = sizeof(gbp_msg_hdr_t);
constexpr size_t GBP_PAGE_ITEM_SIZE = sizeof(gbp_page_item_t);
constexpr size_t GBP_READ_RESP_SIZE = sizeof(gbp_read_resp_t);
constexpr size_t BATCH_READ_RESP_SIZE = sizeof(gbp_batch_read_resp_t);
constexpr size_t READ_META_RESP_SIZE = sizeof(gbp_read_meta_resp_t);
constexpr size_t CKPT_READ_RESP_SIZE = sizeof(gbp_read_ckpt_resp_t);
constexpr size_t GBP_META_ITEM_SIZE = sizeof(gbp_meta_item_t);
constexpr size_t SHAKE_BODY_SIZE = 16;

constexpr size_t WRITE_BODY_SIZE_ALIGNED =
    ((4 + LOG_POINT_ALIGN - 1) / LOG_POINT_ALIGN) * LOG_POINT_ALIGN + 3 * LOG_POINT_SIZE +
    GBP_BATCH_PAGE_NUM * GBP_PAGE_ITEM_SIZE + 4;
constexpr size_t WRITE_BODY_SIZE_TIGHT =
    4 + 3 * LOG_POINT_SIZE + GBP_BATCH_PAGE_NUM * GBP_PAGE_ITEM_SIZE + 4;

inline constexpr size_t align_up(size_t v, size_t a) {
    return ((v + a - 1) / a) * a;
}

constexpr size_t WRITE_BODY_SIZE_ALIGNED_PAD8 =
    align_up(WRITE_BODY_SIZE_ALIGNED, LOG_POINT_ALIGN);
constexpr size_t WRITE_BODY_SIZE_TIGHT_PAD8 =
    align_up(WRITE_BODY_SIZE_TIGHT, LOG_POINT_ALIGN);

class QuietDisconnect : public std::runtime_error {
public:
    explicit QuietDisconnect(const std::string& msg) : std::runtime_error(msg) {}
};

inline bool recv_full(socket_t fd, void* buf, size_t size) {
    auto* p = static_cast<char*>(buf);
    size_t got = 0;
    while (got < size) {
#if defined(_WIN32)
        const int n = recv(fd, p + got, static_cast<int>(size - got), 0);
#else
        const ssize_t n = recv(fd, p + got, size - got, 0);
#endif
        if (n <= 0) return false;
        got += static_cast<size_t>(n);
    }
    return true;
}

inline bool send_full(socket_t fd, const void* buf, size_t size) {
    const auto* p = static_cast<const char*>(buf);
    size_t sent = 0;
    while (sent < size) {
#if defined(_WIN32)
        const int n = send(fd, p + sent, static_cast<int>(size - sent), 0);
#else
        const ssize_t n = send(fd, p + sent, size - sent, MSG_NOSIGNAL);
#endif
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

inline void send_full_or_disconnect(socket_t fd, const void* buf, size_t size, const char* what = "send") {
    if (!send_full(fd, buf, size)) {
        throw QuietDisconnect(std::string("send failed: ") + what);
    }
}

inline std::pair<int, int> write_pages_offset_candidates() {
    const int tight = static_cast<int>(4 + 3 * LOG_POINT_SIZE);
    const int aligned = static_cast<int>(align_up(4, LOG_POINT_ALIGN) + 3 * LOG_POINT_SIZE);
    return {aligned, tight};
}

inline int resolve_write_pages_offset(const uint8_t* body, size_t body_len, uint32_t page_num) {
    const uint32_t pn = std::min(page_num, GBP_BATCH_PAGE_NUM);
    const auto candidates = write_pages_offset_candidates();
    if (pn == 0) return candidates.first;
    const size_t min_expect = std::min(WRITE_BODY_SIZE_ALIGNED, WRITE_BODY_SIZE_TIGHT);
    const size_t max_expect = std::max(WRITE_BODY_SIZE_ALIGNED_PAD8, WRITE_BODY_SIZE_TIGHT_PAD8);
    if (body_len < min_expect || body_len > max_expect) return -1;
    const int offsets[2] = {candidates.first, candidates.second};
    for (int off : offsets) {
        const size_t need_fixed = static_cast<size_t>(off) + GBP_BATCH_PAGE_NUM * GBP_PAGE_ITEM_SIZE;
        if (need_fixed + 4 <= body_len) {
            uint32_t tail_fixed = 0;
            std::memcpy(&tail_fixed, body + need_fixed, 4);
            if (tail_fixed == page_num) return off;
        }
        const size_t need_var = static_cast<size_t>(off) + pn * GBP_PAGE_ITEM_SIZE;
        if (need_var + 4 <= body_len) {
            uint32_t tail_var = 0;
            std::memcpy(&tail_var, body + need_var, 4);
            if (tail_var == page_num) return off;
        }
    }
    return -1;
}

inline void parse_write_batch_points(const uint8_t* body, size_t body_len, int pages_off,
                                     log_point_t& batch_begin, log_point_t& batch_trunc, log_point_t& batch_lrp) {
    batch_begin = batch_trunc = batch_lrp = log_point_t{};
    const auto candidates = write_pages_offset_candidates();
    size_t base = 0;
    if (pages_off == candidates.second) base = 4;
    else if (pages_off == candidates.first) base = align_up(4, LOG_POINT_ALIGN);
    else return;
    if (body_len < base + 3 * LOG_POINT_SIZE) return;
    std::memcpy(&batch_begin, body + base, LOG_POINT_SIZE);
    std::memcpy(&batch_trunc, body + base + LOG_POINT_SIZE, LOG_POINT_SIZE);
    std::memcpy(&batch_lrp, body + base + 2 * LOG_POINT_SIZE, LOG_POINT_SIZE);
}

static_assert(sizeof(page_id_t) == 8, "page_id_t size");
static_assert(sizeof(log_point_t) == 24, "log_point_t size");
static_assert(sizeof(gbp_page_item_t) == 8264, "gbp_page_item_t size");
static_assert(sizeof(gbp_read_resp_t) == 8248, "gbp_read_resp_t size");
static_assert(sizeof(gbp_batch_read_resp_t) ==
                  sizeof(gbp_msg_hdr_t) + sizeof(uint32_t) * 2 + GBP_MSG_LEN +
                      GBP_BATCH_PAGE_NUM * sizeof(gbp_page_item_t),
              "gbp_batch_read_resp_t size");
static_assert(sizeof(gbp_read_meta_resp_t) == 32832, "gbp_read_meta_resp_t size");
static_assert(sizeof(gbp_read_ckpt_resp_t) == 168, "gbp_read_ckpt_resp_t size");
static_assert(offsetof(gbp_read_ckpt_resp_t, begin_point) == 24, "ckpt begin offset");
static_assert(offsetof(gbp_page_item_t, block) == 72, "page_item block offset");

inline uint64_t page_id_key(uint32_t page, uint16_t file) {
    page_id_t pid{};
    pid.page = page;
    pid.file = file;
    pid.aligned = 0;
    uint64_t key;
    static_assert(sizeof(key) >= sizeof(pid));
    std::memcpy(&key, &pid, sizeof(pid));
    return key;
}

inline uint64_t page_id_key_from_raw(const page_id_t& raw) {
    return page_id_key(raw.page, raw.file);
}

}  // namespace gbp
