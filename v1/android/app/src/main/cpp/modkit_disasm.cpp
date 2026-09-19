#include <jni.h>
#include <capstone/capstone.h>

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace {

constexpr jsize kMaxCodeBytes = 2 * 1024 * 1024;
constexpr jint kMaxInstructions = 16384;

std::string json_escape(const char *value) {
    std::ostringstream out;
    const unsigned char *p = reinterpret_cast<const unsigned char *>(value ? value : "");
    for (; *p; ++p) {
        switch (*p) {
            case '"': out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\b': out << "\\b"; break;
            case '\f': out << "\\f"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (*p < 0x20) {
                    out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<unsigned>(*p) << std::dec << std::setfill(' ');
                } else {
                    out << static_cast<char>(*p);
                }
        }
    }
    return out.str();
}

bool map_arch(const std::string &name, bool thumb, cs_arch *arch, cs_mode *mode) {
    if (!arch || !mode) return false;
    if (name == "x86") {
        *arch = CS_ARCH_X86;
        *mode = CS_MODE_32;
        return true;
    }
    if (name == "x86_64") {
        *arch = CS_ARCH_X86;
        *mode = CS_MODE_64;
        return true;
    }
    if (name == "arm") {
        *arch = CS_ARCH_ARM;
        *mode = thumb ? CS_MODE_THUMB : CS_MODE_ARM;
        return true;
    }
    if (name == "aarch64" || name == "arm64") {
        *arch = CS_ARCH_ARM64;
        *mode = CS_MODE_ARM;
        return true;
    }
    return false;
}

bool immediate_target(cs_arch arch, const cs_insn &insn, int64_t *value) {
    if (!value || !insn.detail) return false;
    if (arch == CS_ARCH_X86) {
        const cs_x86 &detail = insn.detail->x86;
        for (uint8_t i = 0; i < detail.op_count; ++i) {
            if (detail.operands[i].type == X86_OP_IMM) {
                *value = detail.operands[i].imm;
                return true;
            }
        }
    } else if (arch == CS_ARCH_ARM) {
        const cs_arm &detail = insn.detail->arm;
        for (uint8_t i = 0; i < detail.op_count; ++i) {
            if (detail.operands[i].type == ARM_OP_IMM) {
                *value = detail.operands[i].imm;
                return true;
            }
        }
    } else if (arch == CS_ARCH_ARM64) {
        const cs_arm64 &detail = insn.detail->arm64;
        for (uint8_t i = 0; i < detail.op_count; ++i) {
            if (detail.operands[i].type == ARM64_OP_IMM) {
                *value = detail.operands[i].imm;
                return true;
            }
        }
    }
    return false;
}

void append_registers(std::ostringstream &out, csh handle, const cs_insn &insn,
                      bool read_side) {
    cs_regs read_regs{}, write_regs{};
    uint8_t read_count = 0, write_count = 0;
    const cs_err err = cs_regs_access(
        handle, &insn, read_regs, &read_count, write_regs, &write_count);
    out << "[";
    if (err == CS_ERR_OK) {
        const uint16_t *regs = read_side ? read_regs : write_regs;
        const uint8_t count = read_side ? read_count : write_count;
        for (uint8_t i = 0; i < count; ++i) {
            if (i) out << ",";
            const char *name = cs_reg_name(handle, regs[i]);
            out << "\"" << json_escape(name ? name : "") << "\"";
        }
    }
    out << "]";
}


void append_x86_operands(std::ostringstream &out, csh handle, const cs_insn &insn) {
    out << "[";
    if (insn.detail) {
        const cs_x86 &detail = insn.detail->x86;
        for (uint8_t i = 0; i < detail.op_count; ++i) {
            if (i) out << ",";
            const cs_x86_op &op = detail.operands[i];
            out << "{\"size\":" << static_cast<unsigned>(op.size)
                << ",\"access\":" << static_cast<unsigned>(op.access);
            if (op.type == X86_OP_REG) {
                const char *name = cs_reg_name(handle, op.reg);
                out << ",\"type\":\"REG\",\"reg\":\""
                    << json_escape(name ? name : "") << "\"";
            } else if (op.type == X86_OP_IMM) {
                out << ",\"type\":\"IMM\",\"imm\":" << op.imm;
            } else if (op.type == X86_OP_MEM) {
                const char *segment = cs_reg_name(handle, op.mem.segment);
                const char *base = cs_reg_name(handle, op.mem.base);
                const char *index = cs_reg_name(handle, op.mem.index);
                out << ",\"type\":\"MEM\",\"mem\":{"
                    << "\"segment\":\"" << json_escape(segment ? segment : "") << "\","
                    << "\"base\":\"" << json_escape(base ? base : "") << "\","
                    << "\"index\":\"" << json_escape(index ? index : "") << "\","
                    << "\"scale\":" << op.mem.scale << ","
                    << "\"disp\":" << op.mem.disp << "}";
            } else {
                out << ",\"type\":\"INVALID\"";
            }
            out << "}";
        }
    }
    out << "]";
}

jstring result(JNIEnv *env, const std::string &value) {
    return env->NewStringUTF(value.c_str());
}

std::string error_json(const char *message) {
    std::ostringstream out;
    out << "{\"schema\":\"modkit-capstone-disasm-1.0\","
        << "\"available\":false,\"error\":\"" << json_escape(message) << "\"}";
    return out.str();
}

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_dev_modkit_mobile_NativeDisasmBridge_capstoneVersion(
        JNIEnv *env, jclass) {
    int major = 0, minor = 0;
    cs_version(&major, &minor);
    std::ostringstream out;
    out << major << "." << minor;
    return result(env, out.str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_dev_modkit_mobile_NativeDisasmBridge_disassemble(
        JNIEnv *env, jclass, jbyteArray code, jlong address,
        jstring architecture, jboolean thumb, jint max_instructions) {
    if (!code || !architecture) return result(env, error_json("missing-input"));
    const jsize size = env->GetArrayLength(code);
    if (size <= 0 || size > kMaxCodeBytes) {
        return result(env, error_json("code-size-out-of-range"));
    }

    const char *arch_chars = env->GetStringUTFChars(architecture, nullptr);
    if (!arch_chars) return result(env, error_json("architecture-read-failed"));
    const std::string arch_name(arch_chars);
    env->ReleaseStringUTFChars(architecture, arch_chars);

    cs_arch arch{};
    cs_mode mode{};
    if (!map_arch(arch_name, thumb == JNI_TRUE, &arch, &mode)) {
        return result(env, error_json("unsupported-architecture"));
    }

    std::vector<uint8_t> bytes(static_cast<size_t>(size));
    env->GetByteArrayRegion(
        code, 0, size, reinterpret_cast<jbyte *>(bytes.data()));
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return result(env, error_json("byte-array-read-failed"));
    }

    csh handle = 0;
    const cs_err open_err = cs_open(arch, mode, &handle);
    if (open_err != CS_ERR_OK) return result(env, error_json(cs_strerror(open_err)));
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    if (arch == CS_ARCH_X86) cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

    const size_t count_limit = static_cast<size_t>(
        std::max<jint>(1, std::min<jint>(max_instructions, kMaxInstructions)));
    cs_insn *instructions = nullptr;
    const size_t count = cs_disasm(
        handle, bytes.data(), bytes.size(), static_cast<uint64_t>(address),
        count_limit, &instructions);

    int version_major = 0, version_minor = 0;
    cs_version(&version_major, &version_minor);
    std::ostringstream out;
    out << "{\"schema\":\"modkit-capstone-disasm-1.0\","
        << "\"available\":true,"
        << "\"engine\":\"capstone\","
        << "\"version\":\"" << version_major << "." << version_minor << "\","
        << "\"arch\":\"" << json_escape(arch_name.c_str()) << "\","
        << "\"thumb\":" << (thumb == JNI_TRUE ? "true" : "false") << ","
        << "\"requestedBytes\":" << size << ","
        << "\"instructionCount\":" << count << ","
        << "\"instructions\":[";

    for (size_t i = 0; i < count; ++i) {
        const cs_insn &insn = instructions[i];
        if (i) out << ",";
        const bool is_call = cs_insn_group(handle, &insn, CS_GRP_CALL);
        const bool is_jump = cs_insn_group(handle, &insn, CS_GRP_JUMP);
        const bool is_ret = cs_insn_group(handle, &insn, CS_GRP_RET);
        int64_t imm = 0;
        const bool has_imm = (is_call || is_jump) && immediate_target(arch, insn, &imm);

        std::ostringstream byte_hex;
        for (uint16_t b = 0; b < insn.size; ++b) {
            if (b) byte_hex << " ";
            byte_hex << std::hex << std::setw(2) << std::setfill('0')
                     << static_cast<unsigned>(insn.bytes[b]);
        }

        out << "{\"address\":" << insn.address
            << ",\"size\":" << insn.size
            << ",\"bytes\":\"" << byte_hex.str() << "\""
            << ",\"id\":" << insn.id
            << ",\"mnemonic\":\"" << json_escape(insn.mnemonic) << "\""
            << ",\"opStr\":\"" << json_escape(insn.op_str) << "\""
            << ",\"isCall\":" << (is_call ? "true" : "false")
            << ",\"isJump\":" << (is_jump ? "true" : "false")
            << ",\"isRet\":" << (is_ret ? "true" : "false")
            << ",\"hasImmediateTarget\":" << (has_imm ? "true" : "false");
        if (has_imm) out << ",\"immediateTarget\":" << imm;
        out << ",\"regsRead\":";
        append_registers(out, handle, insn, true);
        out << ",\"regsWrite\":";
        append_registers(out, handle, insn, false);
        if (arch == CS_ARCH_X86) {
            out << ",\"operands\":";
            append_x86_operands(out, handle, insn);
        }
        out << "}";
    }
    out << "]}";

    if (instructions) cs_free(instructions, count);
    cs_close(&handle);
    return result(env, out.str());
}
