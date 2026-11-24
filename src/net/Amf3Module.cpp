#include "Amf3Module.h"

extern "C" {
#include "lauxlib.h"
#include "lua.h"
}

#include <cmath>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

// AMF3 type markers (Adobe Action Message Format 3 specification)
constexpr uint8_t kAmf3Undefined = 0x00;
constexpr uint8_t kAmf3Null      = 0x01;
constexpr uint8_t kAmf3False     = 0x02;
constexpr uint8_t kAmf3True      = 0x03;
constexpr uint8_t kAmf3Integer   = 0x04;
constexpr uint8_t kAmf3Double    = 0x05;
constexpr uint8_t kAmf3String    = 0x06;
constexpr uint8_t kAmf3XmlDoc    = 0x07;
constexpr uint8_t kAmf3Date      = 0x08;
constexpr uint8_t kAmf3Array     = 0x09;
constexpr uint8_t kAmf3Object    = 0x0A;
constexpr uint8_t kAmf3Xml       = 0x0B;
constexpr uint8_t kAmf3ByteArray = 0x0C;

constexpr int32_t kAmf3IntMin = -268435456; // -2^28
constexpr int32_t kAmf3IntMax =  268435455; //  2^28 - 1
constexpr int kMaxRecursionDepth = 64;

inline size_t luaRawLength(lua_State* L, int idx) {
#if LUA_VERSION_NUM == 501
    return lua_objlen(L, idx);
#else
    return lua_rawlen(L, idx);
#endif
}

inline int toAbsIndex(lua_State* L, int idx) {
    if (idx > 0 || idx <= LUA_REGISTRYINDEX) {
        return idx;
    }
    return lua_gettop(L) + idx + 1;
}

// ============================================================================
// AMF3 Encoder
// ============================================================================

struct ObjectRefEntry {
    uint32_t refIdx = 0;
    uint8_t marker = kAmf3Object;
};

struct Amf3Encoder {
    lua_State* L = nullptr;
    std::string out;
    std::unordered_map<std::string, uint32_t> stringRefs;
    std::unordered_map<const void*, ObjectRefEntry> objectRefs;
    char errorBuf[256] = {};
    bool hasError = false;

    void setError(const char* fmt, ...) {
        if (hasError) {
            return;
        }
        hasError = true;
        va_list args;
        va_start(args, fmt);
        std::vsnprintf(errorBuf, sizeof(errorBuf), fmt, args);
        va_end(args);
    }

    void writeByte(uint8_t b) {
        out.push_back(static_cast<char>(b));
    }

    void writeBytes(const char* data, size_t len) {
        if (len > 0) {
            out.append(data, len);
        }
    }

    void writeU29(uint32_t v) {
        v &= 0x1FFFFFFFu;
        if (v < 0x80u) {
            writeByte(static_cast<uint8_t>(v));
        } else if (v < 0x4000u) {
            writeByte(static_cast<uint8_t>(((v >> 7) & 0x7Fu) | 0x80u));
            writeByte(static_cast<uint8_t>(v & 0x7Fu));
        } else if (v < 0x200000u) {
            writeByte(static_cast<uint8_t>(((v >> 14) & 0x7Fu) | 0x80u));
            writeByte(static_cast<uint8_t>(((v >> 7) & 0x7Fu) | 0x80u));
            writeByte(static_cast<uint8_t>(v & 0x7Fu));
        } else {
            writeByte(static_cast<uint8_t>(((v >> 22) & 0x7Fu) | 0x80u));
            writeByte(static_cast<uint8_t>(((v >> 15) & 0x7Fu) | 0x80u));
            writeByte(static_cast<uint8_t>(((v >> 8) & 0x7Fu) | 0x80u));
            writeByte(static_cast<uint8_t>(v & 0xFFu));
        }
    }

    void writeDoubleBE(double d) {
        uint64_t bits = 0;
        static_assert(sizeof(double) == sizeof(uint64_t), "IEEE-754 64-bit double required");
        std::memcpy(&bits, &d, sizeof(bits));
        uint8_t buf[8];
        buf[0] = static_cast<uint8_t>((bits >> 56) & 0xFFu);
        buf[1] = static_cast<uint8_t>((bits >> 48) & 0xFFu);
        buf[2] = static_cast<uint8_t>((bits >> 40) & 0xFFu);
        buf[3] = static_cast<uint8_t>((bits >> 32) & 0xFFu);
        buf[4] = static_cast<uint8_t>((bits >> 24) & 0xFFu);
        buf[5] = static_cast<uint8_t>((bits >> 16) & 0xFFu);
        buf[6] = static_cast<uint8_t>((bits >> 8) & 0xFFu);
        buf[7] = static_cast<uint8_t>(bits & 0xFFu);
        writeBytes(reinterpret_cast<const char*>(buf), sizeof(buf));
    }

    bool writeUtf8Vr(const char* str, size_t len) {
        // Empty string is always 0x01 and is NEVER stored in the string reference table.
        if (len == 0) {
            writeByte(0x01u);
            return true;
        }

        std::string key(str, len);
        auto it = stringRefs.find(key);
        if (it != stringRefs.end()) {
            writeU29(it->second << 1); // bit 0 = 0 => reference
            return true;
        }

        if (len > static_cast<size_t>(kAmf3IntMax)) {
            setError("amf3.encode: string length exceeds U29 limit");
            return false;
        }

        const uint32_t refIdx = static_cast<uint32_t>(stringRefs.size());
        if (refIdx <= static_cast<uint32_t>(kAmf3IntMax)) {
            stringRefs.emplace(std::move(key), refIdx);
        }

        writeU29((static_cast<uint32_t>(len) << 1) | 1u); // bit 0 = 1 => inline
        writeBytes(str, len);
        return true;
    }

    void encodeNumber(double d) {
        if (std::isfinite(d) && d >= static_cast<double>(kAmf3IntMin) &&
            d <= static_cast<double>(kAmf3IntMax)) {
            const int32_t iv = static_cast<int32_t>(d);
            // Preserve -0.0 as double rather than integer 0.
            if (static_cast<double>(iv) == d && !(d == 0.0 && std::signbit(d))) {
                writeByte(kAmf3Integer);
                writeU29(static_cast<uint32_t>(iv) & 0x1FFFFFFFu);
                return;
            }
        }
        writeByte(kAmf3Double);
        writeDoubleBE(d);
    }

    bool encodeTable(int idx, int depth) {
        if (depth > kMaxRecursionDepth) {
            setError("amf3.encode: maximum nesting depth exceeded");
            return false;
        }
        if (!lua_checkstack(L, 8)) {
            setError("amf3: Lua stack overflow");
            return false;
        }

        const int absIdx = toAbsIndex(L, idx);
        const void* ptr = lua_topointer(L, absIdx);

        // Check object reference table for shared/cyclic tables, preserving 0x09 vs 0x0A marker.
        if (ptr != nullptr) {
            auto refIt = objectRefs.find(ptr);
            if (refIt != objectRefs.end()) {
                writeByte(refIt->second.marker);
                writeU29(refIt->second.refIdx << 1);
                return true;
            }
        }

        // Classify keys: contiguous 1..denseLen integers vs associative/sparse keys.
        const size_t rawLen = luaRawLength(L, absIdx);
        size_t denseCount = 0;
        bool hasNonDenseKeys = false;

        // Verify dense prefix 1..rawLen has no nil holes.
        for (size_t i = 1; i <= rawLen; ++i) {
            lua_rawgeti(L, absIdx, static_cast<int>(i));
            const bool isNil = lua_isnil(L, -1) != 0;
            lua_pop(L, 1);
            if (isNil) {
                break;
            }
            denseCount = i;
        }

        // Scan all table keys.
        lua_pushnil(L);
        while (lua_next(L, absIdx) != 0) {
            const int keyType = lua_type(L, -2);
            if (keyType == LUA_TNUMBER) {
                const double kd = lua_tonumber(L, -2);
                const size_t ki = static_cast<size_t>(kd);
                if (!(kd >= 1.0 && static_cast<double>(ki) == kd && ki <= denseCount)) {
                    hasNonDenseKeys = true;
                }
            } else {
                hasNonDenseKeys = true;
            }
            lua_pop(L, 1); // pop value, keep key
        }

        // Pure string-keyed or sparse integer-keyed map (denseCount == 0 && hasNonDenseKeys):
        // encode as dynamic AMF3 Object (0x0A) matching BabelTime's amfext.
        const bool encodeAsObject = (denseCount == 0 && hasNonDenseKeys);
        const uint8_t tableMarker = encodeAsObject ? kAmf3Object : kAmf3Array;

        const uint32_t refIdx = static_cast<uint32_t>(objectRefs.size());
        if (ptr != nullptr) {
            objectRefs.emplace(ptr, ObjectRefEntry{refIdx, tableMarker});
        }

        if (encodeAsObject) {
            writeByte(kAmf3Object);
            // U29O-traits: bit0=1 (inline obj), bit1=1 (inline traits), bit2=0 (not ext), bit3=1 (dynamic), count=0 => 0x0B
            writeU29(0x0Bu);
            writeByte(0x01u); // empty class name (anonymous object)

            lua_pushnil(L);
            while (lua_next(L, absIdx) != 0) {
                if (!lua_checkstack(L, 8)) {
                    lua_pop(L, 2);
                    setError("amf3: Lua stack overflow");
                    return false;
                }
                const int keyType = lua_type(L, -2);
                if (keyType == LUA_TSTRING) {
                    size_t klen = 0;
                    const char* kstr = lua_tolstring(L, -2, &klen);
                    if (klen > 0) {
                        if (!writeUtf8Vr(kstr, klen) || !encodeValue(-1, depth + 1)) {
                            lua_pop(L, 2);
                            return false;
                        }
                    }
                } else if (keyType == LUA_TNUMBER) {
                    // Convert numeric key to string without mutating key on stack.
                    lua_pushvalue(L, -2);
                    size_t klen = 0;
                    const char* kstr = lua_tolstring(L, -1, &klen);
                    if (kstr != nullptr && klen > 0) {
                        if (!writeUtf8Vr(kstr, klen) || !encodeValue(-2, depth + 1)) {
                            lua_pop(L, 3);
                            return false;
                        }
                    }
                    lua_pop(L, 1);
                }
                lua_pop(L, 1);
            }
            writeByte(0x01u); // terminate dynamic members
            return true;
        }

        // Dense array, empty table {}, or mixed array+associative table: encode as AMF3 Array.
        writeByte(kAmf3Array);
        writeU29((static_cast<uint32_t>(denseCount) << 1) | 1u);

        // Associative portion (any keys outside dense 1..denseCount)
        if (hasNonDenseKeys) {
            lua_pushnil(L);
            while (lua_next(L, absIdx) != 0) {
                if (!lua_checkstack(L, 8)) {
                    lua_pop(L, 2);
                    setError("amf3: Lua stack overflow");
                    return false;
                }
                const int keyType = lua_type(L, -2);
                bool isDenseKey = false;
                if (keyType == LUA_TNUMBER) {
                    const double kd = lua_tonumber(L, -2);
                    const size_t ki = static_cast<size_t>(kd);
                    if (kd >= 1.0 && static_cast<double>(ki) == kd && ki <= denseCount) {
                        isDenseKey = true;
                    }
                }
                if (!isDenseKey) {
                    if (keyType == LUA_TSTRING) {
                        size_t klen = 0;
                        const char* kstr = lua_tolstring(L, -2, &klen);
                        if (klen > 0) {
                            if (!writeUtf8Vr(kstr, klen) || !encodeValue(-1, depth + 1)) {
                                lua_pop(L, 2);
                                return false;
                            }
                        }
                    } else if (keyType == LUA_TNUMBER) {
                        lua_pushvalue(L, -2);
                        size_t klen = 0;
                        const char* kstr = lua_tolstring(L, -1, &klen);
                        if (kstr != nullptr && klen > 0) {
                            if (!writeUtf8Vr(kstr, klen) || !encodeValue(-2, depth + 1)) {
                                lua_pop(L, 3);
                                return false;
                            }
                        }
                        lua_pop(L, 1);
                    }
                }
                lua_pop(L, 1);
            }
        }
        writeByte(0x01u); // terminate associative section

        // Dense portion (1..denseCount)
        for (size_t i = 1; i <= denseCount; ++i) {
            if (!lua_checkstack(L, 8)) {
                setError("amf3: Lua stack overflow");
                return false;
            }
            lua_rawgeti(L, absIdx, static_cast<int>(i));
            if (!encodeValue(-1, depth + 1)) {
                lua_pop(L, 1);
                return false;
            }
            lua_pop(L, 1);
        }
        return true;
    }

    bool encodeValue(int idx, int depth) {
        if (!lua_checkstack(L, 8)) {
            setError("amf3: Lua stack overflow");
            return false;
        }

        const int type = lua_type(L, idx);
        switch (type) {
            case LUA_TNIL:
            case LUA_TLIGHTUSERDATA:
                writeByte(kAmf3Null);
                return true;
            case LUA_TBOOLEAN:
                writeByte(lua_toboolean(L, idx) ? kAmf3True : kAmf3False);
                return true;
            case LUA_TNUMBER:
                encodeNumber(lua_tonumber(L, idx));
                return true;
            case LUA_TSTRING: {
                size_t len = 0;
                const char* s = lua_tolstring(L, idx, &len);
                writeByte(kAmf3String);
                return writeUtf8Vr(s, len);
            }
            case LUA_TTABLE:
                return encodeTable(idx, depth);
            default:
                setError("amf3.encode: unsupported Lua type '%s'", lua_typename(L, type));
                return false;
        }
    }
};

// ============================================================================
// AMF3 Decoder
// ============================================================================

struct Amf3TraitInfo {
    std::string className;
    bool externalizable = false;
    bool dynamic = false;
    std::vector<std::string> sealedMembers;
};

struct Amf3Decoder {
    lua_State* L = nullptr;
    const uint8_t* data = nullptr;
    size_t length = 0;
    size_t pos = 0;

    std::vector<std::string> stringRefs;
    std::vector<Amf3TraitInfo> traitRefs;
    int objRefTableIdx = 0; // Lua table on stack storing decoded objects/bytearrays by 1-based index
    int objRefCount = 0;
    char errorBuf[256] = {};
    bool hasError = false;

    void setError(const char* fmt, ...) {
        if (hasError) {
            return;
        }
        hasError = true;
        va_list args;
        va_start(args, fmt);
        std::vsnprintf(errorBuf, sizeof(errorBuf), fmt, args);
        va_end(args);
    }

    bool ensureAvailable(size_t n) {
        if (n > length || pos > length - n) {
            setError("amf3.decode: unexpected end of input at offset %d", static_cast<int>(pos));
            return false;
        }
        return true;
    }

    bool readByte(uint8_t& out) {
        if (!ensureAvailable(1)) {
            return false;
        }
        out = data[pos++];
        return true;
    }

    bool readU29(uint32_t& out) {
        uint32_t result = 0;
        for (int i = 0; i < 3; ++i) {
            uint8_t b = 0;
            if (!readByte(b)) {
                return false;
            }
            result = (result << 7) | (b & 0x7Fu);
            if ((b & 0x80u) == 0) {
                out = result;
                return true;
            }
        }
        uint8_t last = 0;
        if (!readByte(last)) {
            return false;
        }
        out = (result << 8) | last;
        return true;
    }

    bool readDoubleBE(double& out) {
        if (!ensureAvailable(8)) {
            return false;
        }
        uint64_t bits = 0;
        for (int i = 0; i < 8; ++i) {
            bits = (bits << 8) | static_cast<uint64_t>(data[pos++]);
        }
        double d = 0.0;
        std::memcpy(&d, &bits, sizeof(d));
        out = d;
        return true;
    }

    bool readUtf8Vr(std::string& out) {
        uint32_t header = 0;
        if (!readU29(header)) {
            return false;
        }
        if ((header & 1u) == 0u) {
            const uint32_t idx = header >> 1;
            if (idx >= stringRefs.size()) {
                setError("amf3.decode: invalid string reference index %d", static_cast<int>(idx));
                return false;
            }
            out = stringRefs[idx];
            return true;
        }

        const size_t len = static_cast<size_t>(header >> 1);
        if (len == 0) {
            out.clear();
            return true;
        }

        if (!ensureAvailable(len)) {
            return false;
        }
        out.assign(reinterpret_cast<const char*>(data + pos), len);
        pos += len;
        stringRefs.push_back(out);
        return true;
    }

    bool pushObjectRef(uint32_t idx) {
        if (idx >= static_cast<uint32_t>(objRefCount)) {
            setError("amf3.decode: invalid object reference index %d", static_cast<int>(idx));
            return false;
        }
        lua_rawgeti(L, objRefTableIdx, static_cast<int>(idx) + 1);
        return true;
    }

    void registerTopObjectRef() {
        ++objRefCount;
        lua_pushvalue(L, -1);
        lua_rawseti(L, objRefTableIdx, objRefCount);
    }

    bool decodeXmlOrByteArray() {
        uint32_t header = 0;
        if (!readU29(header)) {
            return false;
        }
        if ((header & 1u) == 0u) {
            return pushObjectRef(header >> 1);
        }
        const size_t len = static_cast<size_t>(header >> 1);
        if (!ensureAvailable(len)) {
            return false;
        }
        lua_pushlstring(L, reinterpret_cast<const char*>(data + pos), len);
        pos += len;
        registerTopObjectRef();
        return true;
    }

    bool decodeDate() {
        uint32_t header = 0;
        if (!readU29(header)) {
            return false;
        }
        if ((header & 1u) == 0u) {
            return pushObjectRef(header >> 1);
        }
        double ms = 0.0;
        if (!readDoubleBE(ms)) {
            return false;
        }
        lua_pushnumber(L, ms);
        registerTopObjectRef();
        return true;
    }

    bool decodeArray(int depth) {
        uint32_t header = 0;
        if (!readU29(header)) {
            return false;
        }
        if ((header & 1u) == 0u) {
            return pushObjectRef(header >> 1);
        }

        const uint32_t denseCount = header >> 1;
        const int preAlloc = denseCount > 65536u ? 65536 : static_cast<int>(denseCount);
        lua_createtable(L, preAlloc, 0);
        registerTopObjectRef();

        // Associative portion (string keys until empty string)
        std::string key;
        for (;;) {
            if (!readUtf8Vr(key)) {
                return false;
            }
            if (key.empty()) {
                break;
            }
            if (!lua_checkstack(L, 8)) {
                setError("amf3: Lua stack overflow");
                return false;
            }
            lua_pushlstring(L, key.data(), key.size());
            if (!decodeValue(depth + 1)) {
                return false;
            }
            lua_rawset(L, -3);
        }

        // Dense portion (1-based Lua sequence)
        for (uint32_t i = 1; i <= denseCount; ++i) {
            if (!lua_checkstack(L, 8)) {
                setError("amf3: Lua stack overflow");
                return false;
            }
            if (!decodeValue(depth + 1)) {
                return false;
            }
            lua_rawseti(L, -2, static_cast<int>(i));
        }
        return true;
    }

    bool decodeObject(int depth) {
        uint32_t header = 0;
        if (!readU29(header)) {
            return false;
        }
        if ((header & 1u) == 0u) {
            return pushObjectRef(header >> 1);
        }

        Amf3TraitInfo traits;
        if ((header & 0x02u) == 0u) {
            // Trait reference
            const uint32_t traitIdx = header >> 2;
            if (traitIdx >= traitRefs.size()) {
                setError("amf3.decode: invalid trait reference index %d", static_cast<int>(traitIdx));
                return false;
            }
            traits = traitRefs[traitIdx];
        } else {
            traits.externalizable = ((header & 0x04u) != 0u);
            traits.dynamic = ((header & 0x08u) != 0u);
            const uint32_t sealedCount = header >> 4;
            if (!readUtf8Vr(traits.className)) {
                return false;
            }
            traits.sealedMembers.reserve(sealedCount > 1024u ? 1024u : sealedCount);
            for (uint32_t i = 0; i < sealedCount; ++i) {
                std::string member;
                if (!readUtf8Vr(member)) {
                    return false;
                }
                traits.sealedMembers.push_back(std::move(member));
            }
            traitRefs.push_back(traits);
        }

        const int nrec = traits.sealedMembers.size() > 65536u
            ? 65536
            : static_cast<int>(traits.sealedMembers.size());
        lua_createtable(L, 0, nrec);
        registerTopObjectRef();

        if (traits.externalizable) {
            if (!decodeValue(depth + 1)) {
                return false;
            }
            lua_setfield(L, -2, "_external");
            return true;
        }

        // Sealed member values in declared order
        for (const auto& memberName : traits.sealedMembers) {
            if (!lua_checkstack(L, 8)) {
                setError("amf3: Lua stack overflow");
                return false;
            }
            lua_pushlstring(L, memberName.data(), memberName.size());
            if (!decodeValue(depth + 1)) {
                return false;
            }
            lua_rawset(L, -3);
        }

        // Dynamic member key-value pairs until empty string
        if (traits.dynamic) {
            std::string key;
            for (;;) {
                if (!readUtf8Vr(key)) {
                    return false;
                }
                if (key.empty()) {
                    break;
                }
                if (!lua_checkstack(L, 8)) {
                    setError("amf3: Lua stack overflow");
                    return false;
                }
                lua_pushlstring(L, key.data(), key.size());
                if (!decodeValue(depth + 1)) {
                    return false;
                }
                lua_rawset(L, -3);
            }
        }
        return true;
    }

    bool decodeValue(int depth) {
        if (!lua_checkstack(L, 8)) {
            setError("amf3: Lua stack overflow");
            return false;
        }
        if (depth > kMaxRecursionDepth) {
            setError("amf3.decode: maximum nesting depth exceeded");
            return false;
        }

        uint8_t marker = 0;
        if (!readByte(marker)) {
            return false;
        }

        switch (marker) {
            case kAmf3Undefined:
            case kAmf3Null:
                lua_pushnil(L);
                return true;
            case kAmf3False:
                lua_pushboolean(L, 0);
                return true;
            case kAmf3True:
                lua_pushboolean(L, 1);
                return true;
            case kAmf3Integer: {
                uint32_t raw = 0;
                if (!readU29(raw)) {
                    return false;
                }
                // Sign-extend 29-bit signed integer.
                const int32_t val = (raw & 0x10000000u) != 0u
                    ? static_cast<int32_t>(raw | 0xE0000000u)
                    : static_cast<int32_t>(raw);
                lua_pushinteger(L, static_cast<lua_Integer>(val));
                return true;
            }
            case kAmf3Double: {
                double d = 0.0;
                if (!readDoubleBE(d)) {
                    return false;
                }
                lua_pushnumber(L, d);
                return true;
            }
            case kAmf3String: {
                std::string s;
                if (!readUtf8Vr(s)) {
                    return false;
                }
                lua_pushlstring(L, s.data(), s.size());
                return true;
            }
            case kAmf3XmlDoc:
            case kAmf3Xml:
            case kAmf3ByteArray:
                return decodeXmlOrByteArray();
            case kAmf3Date:
                return decodeDate();
            case kAmf3Array:
                return decodeArray(depth);
            case kAmf3Object:
                return decodeObject(depth);
            default:
                setError("amf3.decode: unsupported AMF3 type marker 0x%02X at offset %d",
                         static_cast<unsigned>(marker), static_cast<int>(pos - 1));
                return false;
        }
    }
};

} // namespace

extern "C" {

int amf3_encode(lua_State* L) {
    if (!lua_checkstack(L, 8)) {
        return luaL_error(L, "amf3: Lua stack overflow");
    }
    luaL_checkany(L, 1);
    lua_settop(L, 1);

    char errBuf[256] = {};
    bool ok = false;
    {
        Amf3Encoder encoder;
        encoder.L = L;
        encoder.out.reserve(128);
        ok = encoder.encodeValue(1, 0);
        if (ok) {
            lua_pushlstring(L, encoder.out.data(), encoder.out.size());
        } else {
            std::memcpy(errBuf, encoder.errorBuf, sizeof(errBuf));
        }
    }
    if (!ok) {
        return luaL_error(L, "%s", errBuf);
    }
    return 1;
}

int amf3_decode(lua_State* L) {
    if (!lua_checkstack(L, 8)) {
        return luaL_error(L, "amf3: Lua stack overflow");
    }
    size_t len = 0;
    const char* str = luaL_checklstring(L, 1, &len);
    const lua_Integer posArg = luaL_optinteger(L, 2, 0);
    if (posArg < 0) {
        return luaL_argerror(L, 2, "position may not be negative");
    }

    lua_settop(L, 1);
    lua_createtable(L, 0, 0); // object reference table at stack index 2

    char errBuf[256] = {};
    bool ok = false;
    size_t finalPos = 0;
    {
        Amf3Decoder decoder;
        decoder.L = L;
        decoder.data = reinterpret_cast<const uint8_t*>(str);
        decoder.length = len;
        decoder.pos = static_cast<size_t>(posArg);
        decoder.objRefTableIdx = 2;

        ok = decoder.decodeValue(0);
        finalPos = decoder.pos;
        if (!ok) {
            std::memcpy(errBuf, decoder.errorBuf, sizeof(errBuf));
        }
    }
    if (!ok) {
        return luaL_error(L, "%s", errBuf);
    }

    lua_pushinteger(L, static_cast<lua_Integer>(finalPos));
    return 2;
}

int luaopen_amf3(lua_State* L) {
    static const luaL_Reg kAmf3Funcs[] = {
        {"encode", amf3_encode},
        {"decode", amf3_decode},
        {nullptr, nullptr}
    };

    lua_createtable(L, 0, 2);
#if LUA_VERSION_NUM == 501
    luaL_register(L, nullptr, kAmf3Funcs);
#else
    luaL_setfuncs(L, kAmf3Funcs, 0);
#endif
    return 1;
}

int luaopen_amf3_extensions(lua_State* L) {
    lua_getglobal(L, "package");
    if (lua_istable(L, -1)) {
        lua_getfield(L, -1, "preload");
        if (lua_istable(L, -1)) {
            lua_pushcfunction(L, luaopen_amf3);
            lua_setfield(L, -2, "amf3");
        }
        lua_pop(L, 1); // pop preload
    }
    lua_pop(L, 1); // pop package
    return 0;
}

} // extern "C"
