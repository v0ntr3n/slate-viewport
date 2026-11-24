#!/usr/bin/env python3
"""
patch_cocos2dx.py — Idempotently patches stock Cocos2d-x 2.2.6 for Win32 Client Win32:
  1. Babeltime setDecrypt / setDecryptor / doDecrypt 0xFEFEFEFE asset hook, Win32 UTF-8 binary _wfopen
     prior to BTXOR decryption (+1 null-terminated byte), NDEBUG null guards, and thread-safe CCFileUtils
  2. Pure-C++ software Android ETC1 (.pkm) + companion _alpha channel decoder on Win32
  3. CCTextureCache::addImage multi-extension fallback (.pvr.ccz, .pkm, .png, .webp) & addImageAsync
     failed-load .pkm rescue + uninitialized texture cache guard
  4. Spine 3.2 multi-page .pkm/.webp atlas loading, size: header, deform/ffd, inheritRotation/Scale,
     weightedmesh/mesh rendering, mesh boundingBox(), & null skeleton/boneCount guards
  5. CCClippingNode null stencil guards, UIWidget::addChild non-Widget routing, UITouchGroup/UIHelper
     dynamic_cast safety, NDEBUG CCAssert guards across CCNode/CCSprite/CCActionInterval/Armature/
     UIRichText/CCParticleSystem, Win32 SimpleAudioEngine/MciPlayer (--mute, .ogg skip, 0xFEFEFEFE
     audio cache decrypt, wide mciSendCommandW, GWLP_USERDATA teardown), CCLuaStack/tolua_push stack
     safety, CCImageCommon_cpp.h +4 tail padding & JCS_RGB fix, and VS 2015+/2022 UCRT shims
"""
import os
import re
import sys

MARKER = "GCLIENT_BT_DECRYPT_HOOK"
FILEDATA_GUARD_MARKER = "GCLIENT_GETFILEDATA_BINARY_UTF8_GUARD"
THREADSAFE_MARKER = "GCLIENT_FILEUTILS_THREADSAFE"
POPUP_GUARD_MARKER = "GCLIENT_POPUP_NOTIFY_THREADSAFE"
ETC1_MARKER = "GCLIENT_ETC1_PKM_DECODER"
TEX2D_ETC_MARKER = "GCLIENT_ETC1_TEXTURE2D_FIX"
TEXCACHE_MARKER = "GCLIENT_TEXTURECACHE_PKM_ASYNC_FIX"
TEXCACHE_V2_MARKER = "GCLIENT_TEXTURECACHE_MULTIEXT_V2"
ATLAS_SIZE_MARKER = "GCLIENT_SPINE_ATLAS_SIZE_FIX"
SPINE_MULTIEXT_MARKER = "GCLIENT_SPINE_COCOS2DX_MULTIEXT_FIX"
SPINE_BBOX_MARKER = "GCLIENT_SPINE_MESH_BBOX_FIX"
SPINE_DEFORM_INHERIT_MARKER = "GCLIENT_SPINE_DEFORM_AND_INHERIT_FIX"
CLIPPING_MARKER = "GCLIENT_CLIPPING_STENCIL_GUARD"
UIWIDGET_ADDCHILD_MARKER = "GCLIENT_UIWIDGET_ADDCHILD_GUARD"
UITOUCHGROUP_MARKER = "GCLIENT_UITOUCHGROUP_GUARD"
UIHELPER_MARKER = "GCLIENT_UIHELPER_GUARD"
CCNODE_GUARD_MARKER = "GCLIENT_CCNODE_NDEBUG_GUARD"
CCSPRITE_GUARD_MARKER = "GCLIENT_CCSPRITE_NDEBUG_GUARD"
CCACTION_GUARD_MARKER = "GCLIENT_CCACTION_NDEBUG_GUARD"
ARMATURE_GUARD_MARKER = "GCLIENT_ARMATURE_NDEBUG_GUARD"
RICHTEXT_GUARD_MARKER = "GCLIENT_RICHTEXT_NDEBUG_GUARD"
PARTICLE_GUARD_MARKER = "GCLIENT_PARTICLE_NDEBUG_GUARD"
SPINE_GUARD_MARKER = "GCLIENT_SPINE_SKELETON_NDEBUG_GUARD"
AUDIO_GUARD_MARKER = "GCLIENT_AUDIO_WIN32_GUARD"
LUA_GUARD_MARKER = "GCLIENT_LUA_PUSH_GUARD"
IMAGE_GUARD_MARKER = "GCLIENT_IMAGE_COMMON_GUARD"


def _mask_cpp_comments_and_strings(src: str) -> str:
    out = list(src)
    n = len(src)
    i = 0
    while i < n:
        ch = src[i]
        if ch == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                out[i] = " "
                i += 1
        elif ch == "/" and i + 1 < n and src[i + 1] == "*":
            out[i] = " "
            out[i + 1] = " "
            i += 2
            while i < n:
                if src[i] == "*" and i + 1 < n and src[i + 1] == "/":
                    out[i] = " "
                    out[i + 1] = " "
                    i += 2
                    break
                if src[i] != "\n":
                    out[i] = " "
                i += 1
        elif ch in ('"', "'"):
            quote = ch
            out[i] = " "
            i += 1
            while i < n:
                c = src[i]
                if c == "\\" and i + 1 < n:
                    if src[i] != "\n":
                        out[i] = " "
                    if src[i + 1] != "\n":
                        out[i + 1] = " "
                    i += 2
                    continue
                if c != "\n":
                    out[i] = " "
                i += 1
                if c == quote:
                    break
        else:
            i += 1
    return "".join(out)


def _find_method_spans_with_sig(src: str, qualified_method: str) -> list[tuple[int, int, int, int]]:
    masked = _mask_cpp_comments_and_strings(src)
    qm = qualified_method.strip()
    if "::" in qm:
        parts = [re.escape(p.strip()) for p in qm.split("::")]
        q_pat = r"\s*::\s*".join(parts)
    else:
        q_pat = re.escape(qm)
    lead = r"\b" if (qm and (qm[0].isalnum() or qm[0] == "_")) else ""
    pattern = re.compile(lead + q_pat + r"\s*\(")
    spans: list[tuple[int, int, int, int]] = []
    n = len(masked)

    for m in pattern.finditer(masked):
        paren_open = masked.find("(", m.start())
        if paren_open == -1:
            continue
        p_depth = 0
        i = paren_open
        paren_close = -1
        while i < n:
            if masked[i] == "(":
                p_depth += 1
            elif masked[i] == ")":
                p_depth -= 1
                if p_depth == 0:
                    paren_close = i
                    i += 1
                    break
            i += 1
        if p_depth != 0 or paren_close == -1:
            continue

        # Advance past const/noexcept/initializer-list up to '{' or ';'
        brace_open = -1
        while i < n:
            c = masked[i]
            if c == ";":
                break
            if c == "{":
                brace_open = i
                break
            if c == "(":
                sub = 1
                i += 1
                while i < n and sub > 0:
                    if masked[i] == "(":
                        sub += 1
                    elif masked[i] == ")":
                        sub -= 1
                    i += 1
                continue
            i += 1

        if brace_open == -1:
            continue

        b_depth = 0
        j = brace_open
        while j < n:
            if masked[j] == "{":
                b_depth += 1
            elif masked[j] == "}":
                b_depth -= 1
                if b_depth == 0:
                    spans.append((paren_open, paren_close + 1, brace_open, j + 1))
                    break
            j += 1
    return spans


def _find_method_body_spans(src: str, qualified_method: str) -> list[tuple[int, int]]:
    return [(b_start, b_end) for _, _, b_start, b_end in _find_method_spans_with_sig(src, qualified_method)]


def _split_top_level_params(sig_inner: str) -> list[str]:
    params: list[str] = []
    cur: list[str] = []
    depth = 0
    for ch in sig_inner:
        if ch in "(<":
            depth += 1
            cur.append(ch)
        elif ch in ")>":
            if depth > 0:
                depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            item = "".join(cur).strip()
            if item:
                params.append(item)
            cur = []
        else:
            cur.append(ch)
    tail = "".join(cur).strip()
    if tail and tail != "void":
        params.append(tail)
    return params


def _extract_param_ident(param_decl: str, fallback: str) -> str:
    decl = param_decl.split("=")[0].strip()
    decl = re.sub(r"/\*.*?\*/", " ", decl)
    m = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?\s*$", decl)
    return m.group(1) if m else fallback


def _insert_before_ns_cc_begin(txt: str, snippet: str) -> str:
    m = re.search(r"^[ \t]*NS_CC_BEGIN\b", txt, re.MULTILINE)
    if m:
        return txt[:m.start()] + snippet + "\n" + txt[m.start():]
    m_ext = re.search(r"^[ \t]*NS_CC_EXT_BEGIN\b", txt, re.MULTILINE)
    if m_ext:
        return txt[:m_ext.start()] + snippet + "\n" + txt[m_ext.start():]
    m_ns = re.search(r"^[ \t]*namespace\s+(?:cocos2d|CocosDenshion)\b", txt, re.MULTILINE)
    if m_ns:
        return txt[:m_ns.start()] + snippet + "\n" + txt[m_ns.start():]
    return snippet + "\n" + txt


def _inject_after_open_brace(body: str, stmt_with_comment: str, indent: str = "    ") -> str:
    rest = body[1:]
    if rest.startswith("\n") or rest.startswith("\r\n"):
        return "{\n" + indent + stmt_with_comment + rest
    return "{\n" + indent + stmt_with_comment + "\n" + indent + rest.lstrip(" \t")


def _prepend_to_method_body(txt: str, qualified_method: str, guard_code: str, marker: str) -> str:
    for _, _, b_start, b_end in reversed(_find_method_spans_with_sig(txt, qualified_method)):
        body = txt[b_start:b_end]
        if marker in body or guard_code.strip() in body:
            continue
        patched_body = _inject_after_open_brace(body, guard_code + " // " + marker)
        txt = txt[:b_start] + patched_body + txt[b_end:]
    return txt


def patch_header(path: str) -> None:
    txt = open(path, "r", encoding="utf-8", errors="replace").read()
    orig_txt = txt

    if MARKER not in txt:
        hook = (
            "\n    // " + MARKER + "\n"
            "    typedef bool (*BtDecryptFn)(unsigned char* data, unsigned long* size);\n"
            "    void setDecrypt(BtDecryptFn fn) { m_btDecryptFn = fn; }\n"
            "    void setDecryptor(BtDecryptFn fn) { m_btDecryptFn = fn; }\n"
            "    bool doDecrypt(unsigned char* data, unsigned long* size) {\n"
            "        return m_btDecryptFn ? m_btDecryptFn(data, size) : false;\n"
            "    }\n"
            "protected:\n"
            "    BtDecryptFn m_btDecryptFn;\n"
            "public:\n"
        )
        anchor = "virtual unsigned char* getFileData("
        if anchor not in txt:
            raise RuntimeError(f"Anchor not found in {path}")
        txt = txt.replace(anchor, hook + "    " + anchor, 1)

    if THREADSAFE_MARKER not in txt:
        ts_decl = (
            "\n    // " + THREADSAFE_MARKER + "\n"
            "    static void lockFileUtilsMutex();\n"
            "    static void unlockFileUtilsMutex();\n"
        )
        anchor = "virtual unsigned char* getFileData("
        if anchor not in txt:
            raise RuntimeError(f"Anchor not found in {path}")
        txt = txt.replace(anchor, ts_decl + "    " + anchor, 1)

    if txt == orig_txt:
        print(f"[skip] Already patched: {path}")
        return

    open(path, "w", encoding="utf-8", newline="\n").write(txt)
    print(f"[ok] Patched header: {path}")


def patch_fileutils_decrypt(txt: str) -> str:
    # Self-heal any legacy run that accidentally injected MARKER inside getFileDataFromZip.
    for zip_method in ("CCFileUtils::getFileDataFromZip", "CCFileUtilsWin32::getFileDataFromZip"):
        for b_start, b_end in reversed(_find_method_body_spans(txt, zip_method)):
            body = txt[b_start:b_end]
            if MARKER in body:
                healed = re.sub(
                    r"[ \t]*if \([A-Za-z_][A-Za-z0-9_]* && [A-Za-z_][A-Za-z0-9_]*[^\n]*m_btDecryptFn[^\n]*// "
                    + re.escape(MARKER)
                    + r"\n",
                    "",
                    body,
                )
                txt = txt[:b_start] + healed + txt[b_end:]

    # 1. Initialize m_btDecryptFn = NULL inside CCFileUtils::CCFileUtils() body (avoids -Wreorder).
    for b_start, b_end in reversed(_find_method_body_spans(txt, "CCFileUtils::CCFileUtils")):
        body = txt[b_start:b_end]
        if "m_btDecryptFn" not in body and "m_btDecryptFn" not in txt[max(0, b_start - 160):b_start]:
            injected_body = _inject_after_open_brace(body, "m_btDecryptFn = NULL; // " + MARKER)
            txt = txt[:b_start] + injected_body + txt[b_end:]

    # 2. Scope getFileData null guard, binary UTF-8 _wfopen, +1 byte alloc, decryption & '\0' termination
    #    strictly inside CCFileUtils::getFileData / CCFileUtilsWin32::getFileData.
    ret_re = re.compile(r"(^[ \t]*)(return\s+([A-Za-z_][A-Za-z0-9_]*)\s*;)", re.MULTILINE)
    null_tokens = {"NULL", "nullptr", "0", "false"}
    needs_binary_fopen_helper = False

    for method_name in ("CCFileUtils::getFileData", "CCFileUtilsWin32::getFileData"):
        for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, method_name)):
            body = txt[b_start:b_end]
            masked_body = _mask_cpp_comments_and_strings(body)
            if method_name == "CCFileUtilsWin32::getFileData" and "CCFileUtils::getFileData" in masked_body:
                # Pure base-class delegation already decrypts inside CCFileUtils::getFileData.
                continue

            sig_inner = txt[p_open + 1:p_close - 1]
            params = _split_top_level_params(sig_inner)
            file_var = _extract_param_ident(params[0], "pszFileName") if len(params) >= 1 else "pszFileName"
            size_match = re.search(r"unsigned\s+long\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)", sig_inner)
            size_var = size_match.group(1) if size_match else (
                _extract_param_ident(params[2], "pSize") if len(params) >= 3 else "pSize"
            )

            patched_body = body

            # 2a. Open files in binary mode ("rb" / L"rb" via UTF-8 _wfopen on _WIN32) BEFORE m_btDecryptFn
            #     so 0x1A (Ctrl+Z) and \r\n inside 0xFEFEFEFE ciphertext are NEVER truncated or translated.
            masked_cur = _mask_cpp_comments_and_strings(patched_body)
            if re.search(r"\bfopen\s*\(", masked_cur) and "gclientFopenBinaryRead" not in patched_body:
                patched_body, n_fopen = re.subn(
                    r"\bfopen\s*\(([^,]+),\s*[^)]+\)",
                    r"gclientFopenBinaryRead(\1)",
                    patched_body,
                )
                if n_fopen > 0:
                    needs_binary_fopen_helper = True
            elif "gclientFopenBinaryRead" in patched_body:
                needs_binary_fopen_helper = True

            # 2b. Ensure heap buffer allocation inside getFileData has +1 byte for safe pBuffer[*pSize] = '\0'.
            has_alloc = False
            alloc_re = re.compile(r"(new\s+unsigned\s+char\s*\[\s*)([^\]]+?)(\s*\])")

            def _pad_plus_one(m_alloc: re.Match) -> str:
                nonlocal has_alloc
                has_alloc = True
                expr = m_alloc.group(2).strip()
                if re.search(r"\+\s*1\b", expr):
                    return m_alloc.group(0)
                if expr == f"*{size_var}":
                    return f"{m_alloc.group(1)}*{size_var} + 1{m_alloc.group(3)}"
                return f"{m_alloc.group(1)}({expr}) + 1{m_alloc.group(3)}"

            patched_body = alloc_re.sub(_pad_plus_one, patched_body)
            if "new unsigned char" in patched_body:
                has_alloc = True

            # Guard ftell(fp) < 0 before unsigned cast / allocation if ftell is used.
            if "ftell(" in patched_body and "gclientTell" not in patched_body:
                patched_body = re.sub(
                    r"\*" + re.escape(size_var) + r"\s*=\s*ftell\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*;",
                    f"long gclientTell = ftell(\\1); if (gclientTell < 0) {{ fclose(\\1); break; }} *{size_var} = (unsigned long)gclientTell;",
                    patched_body,
                    count=1,
                )

            # 2c. Inject or upgrade pre-return decryption + null-termination hook.
            if MARKER not in patched_body:
                masked_for_ret = _mask_cpp_comments_and_strings(patched_body)
                edits: list[tuple[int, int, str]] = []
                for m in ret_re.finditer(masked_for_ret):
                    indent_len = len(m.group(1))
                    stmt_start = m.start(2)
                    stmt_end = m.end(2)
                    var_name = patched_body[m.start(3):m.end(3)]
                    if var_name in null_tokens:
                        continue
                    indent = patched_body[m.start(1):m.start(1) + indent_len]
                    orig_ret = patched_body[stmt_start:stmt_end]
                    if has_alloc:
                        hook_stmt = (
                            f"if ({var_name} && {size_var}) {{ "
                            f"if (*{size_var} > 0 && m_btDecryptFn) {{ m_btDecryptFn({var_name}, {size_var}); }} "
                            f"{var_name}[*{size_var}] = '\\0'; }} // {MARKER}\n{indent}{orig_ret}"
                        )
                    else:
                        hook_stmt = (
                            f"if ({var_name} && {size_var} && *{size_var} > 0 && m_btDecryptFn) "
                            f"{{ unsigned long _gclientPrevSz = *{size_var}; m_btDecryptFn({var_name}, {size_var}); "
                            f"if (*{size_var} < _gclientPrevSz) {var_name}[*{size_var}] = '\\0'; }} // {MARKER}\n{indent}{orig_ret}"
                        )
                    edits.append((stmt_start, stmt_end, hook_stmt))

                for s_idx, e_idx, repl in reversed(edits):
                    patched_body = patched_body[:s_idx] + repl + patched_body[e_idx:]
            elif has_alloc and "[*" + size_var + "] = '\\0'" not in patched_body:
                # Upgrade v1 hook in-place so pBuffer[*pSize] = '\0' is guaranteed after decryption.
                patched_body = re.sub(
                    r"if \(([A-Za-z_][A-Za-z0-9_]*) && " + re.escape(size_var)
                    + r" && \*" + re.escape(size_var)
                    + r" > 0 && m_btDecryptFn\) \{ m_btDecryptFn\(\1, "
                    + re.escape(size_var) + r"\); \} // " + re.escape(MARKER),
                    f"if (\\1 && {size_var}) {{ if (*{size_var} > 0 && m_btDecryptFn) "
                    f"{{ m_btDecryptFn(\\1, {size_var}); }} \\1[*{size_var}] = '\\0'; }} // {MARKER}",
                    patched_body,
                )

            # 2d. Guard against pszFileName == NULL or pSize == NULL in Release (NDEBUG).
            if FILEDATA_GUARD_MARKER not in patched_body:
                null_guard = (
                    f"if (!{file_var} || !{size_var}) {{ if ({size_var}) *{size_var} = 0; return NULL; }} "
                    f"// {FILEDATA_GUARD_MARKER}"
                )
                lock_pos = patched_body.find(THREADSAFE_MARKER)
                if lock_pos != -1:
                    nl_pos = patched_body.find("\n", lock_pos)
                    if nl_pos != -1:
                        patched_body = patched_body[:nl_pos + 1] + "    " + null_guard + "\n" + patched_body[nl_pos + 1:]
                else:
                    patched_body = _inject_after_open_brace(patched_body, null_guard)

            if patched_body != body:
                txt = txt[:b_start] + patched_body + txt[b_end:]

    if needs_binary_fopen_helper and "gclientFopenBinaryRead" not in txt.split("NS_CC_BEGIN")[0]:
        fopen_helper = (
            "// " + FILEDATA_GUARD_MARKER + "\n"
            "#include <stdio.h>\n"
            "#ifdef _WIN32\n"
            "#ifndef WIN32_LEAN_AND_MEAN\n"
            "#define WIN32_LEAN_AND_MEAN\n"
            "#endif\n"
            "#include <windows.h>\n"
            "#include <wchar.h>\n"
            "#endif\n"
            "namespace {\n"
            "static inline FILE* gclientFopenBinaryRead(const char* fullPath) {\n"
            "    if (!fullPath || !fullPath[0]) return NULL;\n"
            "#ifdef _WIN32\n"
            "    int wlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, fullPath, -1, NULL, 0);\n"
            "    if (wlen > 0) {\n"
            "        wchar_t* wbuf = new wchar_t[(size_t)wlen];\n"
            "        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, fullPath, -1, wbuf, wlen);\n"
            "        FILE* fp = _wfopen(wbuf, L\"rb\");\n"
            "        delete[] wbuf;\n"
            "        if (fp) return fp;\n"
            "    }\n"
            "    int alen = MultiByteToWideChar(CP_ACP, 0, fullPath, -1, NULL, 0);\n"
            "    if (alen > 0) {\n"
            "        wchar_t* abuf = new wchar_t[(size_t)alen];\n"
            "        MultiByteToWideChar(CP_ACP, 0, fullPath, -1, abuf, alen);\n"
            "        FILE* fp = _wfopen(abuf, L\"rb\");\n"
            "        delete[] abuf;\n"
            "        if (fp) return fp;\n"
            "    }\n"
            "#endif\n"
            "    return fopen(fullPath, \"rb\");\n"
            "}\n"
            "}\n"
        )
        txt = _insert_before_ns_cc_begin(txt, fopen_helper)

    # Also guard fullPathForFilename against NULL in Release (NDEBUG).
    for fp_method in ("CCFileUtils::fullPathForFilename", "CCFileUtilsWin32::fullPathForFilename"):
        for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, fp_method)):
            body = txt[b_start:b_end]
            if FILEDATA_GUARD_MARKER in body:
                continue
            params = _split_top_level_params(txt[p_open + 1:p_close - 1])
            p_var = _extract_param_ident(params[0], "pszFileName") if params else "pszFileName"
            guard = f"if (!{p_var} || !{p_var}[0]) return std::string(); // {FILEDATA_GUARD_MARKER}"
            patched_body = _inject_after_open_brace(body, guard)
            txt = txt[:b_start] + patched_body + txt[b_end:]

    return txt


def patch_cpp(path: str) -> None:
    txt = open(path, "r", encoding="utf-8", errors="replace").read()
    orig_txt = txt
    is_base_fileutils = os.path.basename(path) == "CCFileUtils.cpp"

    txt = patch_fileutils_decrypt(txt)

    # 3. Guard m_fullPathCache, search-path, and popup-notify accesses with recursive mutex.
    if THREADSAFE_MARKER not in txt:
        if is_base_fileutils:
            mutex_helper = (
                "// " + THREADSAFE_MARKER + "\n"
                "#include <mutex>\n"
                "namespace {\n"
                "static std::recursive_mutex& gclientGetFileUtilsMutex() {\n"
                "    static std::recursive_mutex* s_mutex = new std::recursive_mutex();\n"
                "    return *s_mutex;\n"
                "}\n"
                "struct GClientFileUtilsLockGuard {\n"
                "    GClientFileUtilsLockGuard() { cocos2d::CCFileUtils::lockFileUtilsMutex(); }\n"
                "    ~GClientFileUtilsLockGuard() { cocos2d::CCFileUtils::unlockFileUtilsMutex(); }\n"
                "private:\n"
                "    GClientFileUtilsLockGuard(const GClientFileUtilsLockGuard&);\n"
                "    GClientFileUtilsLockGuard& operator=(const GClientFileUtilsLockGuard&);\n"
                "};\n"
                "}\n"
            )
            txt = _insert_before_ns_cc_begin(txt, mutex_helper)
            ns_begin_match = re.search(r"^[ \t]*NS_CC_BEGIN\b", txt, re.MULTILINE)
            mutex_defs = (
                "\nvoid CCFileUtils::lockFileUtilsMutex() { gclientGetFileUtilsMutex().lock(); } // "
                + THREADSAFE_MARKER
                + "\nvoid CCFileUtils::unlockFileUtilsMutex() { gclientGetFileUtilsMutex().unlock(); }\n"
            )
            if ns_begin_match:
                insert_at = ns_begin_match.end()
                txt = txt[:insert_at] + mutex_defs + txt[insert_at:]
            else:
                txt = txt + "\nnamespace cocos2d {" + mutex_defs + "}\n"
        else:
            guard_only = (
                "// " + THREADSAFE_MARKER + "\n"
                "namespace {\n"
                "struct GClientFileUtilsLockGuard {\n"
                "    GClientFileUtilsLockGuard() { cocos2d::CCFileUtils::lockFileUtilsMutex(); }\n"
                "    ~GClientFileUtilsLockGuard() { cocos2d::CCFileUtils::unlockFileUtilsMutex(); }\n"
                "private:\n"
                "    GClientFileUtilsLockGuard(const GClientFileUtilsLockGuard&);\n"
                "    GClientFileUtilsLockGuard& operator=(const GClientFileUtilsLockGuard&);\n"
                "};\n"
                "}\n"
            )
            txt = _insert_before_ns_cc_begin(txt, guard_only)

    guarded_methods = (
        "CCFileUtils::fullPathForFilename",
        "CCFileUtils::getNewFilename",
        "CCFileUtils::fullPathFromRelativeFile",
        "CCFileUtils::getFileData",
        "CCFileUtils::purgeCachedEntries",
        "CCFileUtils::addSearchPath",
        "CCFileUtils::removeSearchPath",
        "CCFileUtils::removeAllPaths",
        "CCFileUtils::setSearchPaths",
        "CCFileUtils::getSearchPaths",
        "CCFileUtils::setSearchResolutionsOrder",
        "CCFileUtils::addSearchResolutionsOrder",
        "CCFileUtils::getSearchResolutionsOrder",
        "CCFileUtils::setFilenameLookupDictionary",
        "CCFileUtils::loadFilenameLookupDictionaryFromFile",
        "CCFileUtils::setPopupNotify",
        "CCFileUtils::isPopupNotify",
        "CCFileUtilsWin32::fullPathForFilename",
        "CCFileUtilsWin32::getPathForFilename",
        "CCFileUtilsWin32::getFileData",
        "CCFileUtilsWin32::isFileExist",
        "CCFileUtilsWin32::isAbsolutePath",
        "CCFileUtilsWin32::addSearchPath",
        "CCFileUtilsWin32::removeSearchPath",
        "CCFileUtilsWin32::setPopupNotify",
        "CCFileUtilsWin32::isPopupNotify",
    )
    for m_name in guarded_methods:
        for b_start, b_end in reversed(_find_method_body_spans(txt, m_name)):
            body = txt[b_start:b_end]
            if "GClientFileUtilsLockGuard" in body:
                continue
            patched_body = _inject_after_open_brace(body, "GClientFileUtilsLockGuard _gclientLock; (void)_gclientLock; // " + THREADSAFE_MARKER)
            txt = txt[:b_start] + patched_body + txt[b_end:]

    if txt == orig_txt:
        print(f"[skip] Already patched: {path}")
        return

    open(path, "w", encoding="utf-8", newline="\n").write(txt)
    print(f"[ok] Patched cpp: {path}")


ETC1_TEXTURE_ETC_CPP = r"""// GCLIENT_ETC1_PKM_DECODER: Pure-C++ Software ETC1 (.pkm) + Companion _alpha Decoder
#include "CCTextureETC.h"
#include "CCGL.h"
#include "shaders/ccGLStateCache.h"
#include "platform/CCFileUtils.h"
#include "platform/CCImage.h"
#include "zlib.h"

#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>

NS_CC_BEGIN

namespace {

static const int kEtc1ModifierTables[8][4] = {
    {  2,   8,  -2,   -8 },
    {  5,  17,  -5,  -17 },
    {  9,  29,  -9,  -29 },
    { 13,  42, -13,  -42 },
    { 18,  60, -18,  -60 },
    { 24,  80, -24,  -80 },
    { 33, 106, -33, -106 },
    { 47, 183, -47, -183 }
};

static inline unsigned char gclientClampByte(int v) {
    return (unsigned char)(v < 0 ? 0 : (v > 255 ? 255 : v));
}

static inline unsigned int gclientReadBE16(const unsigned char* p) {
    return ((unsigned int)p[0] << 8) | (unsigned int)p[1];
}

static inline unsigned int gclientReadBE32(const unsigned char* p) {
    return ((unsigned int)p[0] << 24) | ((unsigned int)p[1] << 16) |
           ((unsigned int)p[2] << 8) | (unsigned int)p[3];
}

static inline unsigned int gclientReadLE32(const unsigned char* p) {
    return (unsigned int)p[0] | ((unsigned int)p[1] << 8) |
           ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}

static bool gclientMaybeDecompressPayload(
    const unsigned char* src,
    unsigned long srcLen,
    std::vector<unsigned char>& outBuf,
    const unsigned char*& viewPtr,
    unsigned long& viewLen)
{
    viewPtr = src;
    viewLen = srcLen;
    if (!src || srcLen < 4) {
        return false;
    }

    // 1. CCZ! container ("CCZ!", big-endian compression_type == 0 for zlib, uint32_be uncompressed len at +12)
    if (srcLen >= 16 && src[0] == 'C' && src[1] == 'C' && src[2] == 'Z' && src[3] == '!') {
        unsigned int compType = gclientReadBE16(src + 4);
        if (compType != 0) {
            return false;
        }
        unsigned int expectedLen = gclientReadBE32(src + 12);
        if (expectedLen == 0 || expectedLen > 134217728u) {
            return false;
        }
        outBuf.resize(expectedLen);
        uLongf destLen = (uLongf)expectedLen;
        int zret = uncompress(&outBuf[0], &destLen, src + 16, (uLong)(srcLen - 16));
        if (zret != Z_OK) {
            return false;
        }
        outBuf.resize((size_t)destLen);
        viewPtr = outBuf.empty() ? NULL : &outBuf[0];
        viewLen = (unsigned long)destLen;
        return viewPtr != NULL;
    }

    // 2. Raw zlib stream (CMF 0x78, valid FLG check (cmf*256 + flg) % 31 == 0)
    if (src[0] == 0x78 && (((unsigned int)src[0] << 8) | (unsigned int)src[1]) % 31 == 0) {
        z_stream zs;
        memset(&zs, 0, sizeof(zs));
        zs.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(src));
        zs.avail_in = (uInt)srcLen;
        if (inflateInit(&zs) == Z_OK) {
            size_t cap = srcLen * 4;
            if (cap < 4096) cap = 4096;
            outBuf.resize(cap);
            int status = Z_OK;
            while (status == Z_OK) {
                if (zs.total_out >= outBuf.size()) {
                    if (outBuf.size() >= 134217728u) {
                        inflateEnd(&zs);
                        return false;
                    }
                    outBuf.resize(outBuf.size() * 2);
                }
                zs.next_out = reinterpret_cast<Bytef*>(&outBuf[0] + zs.total_out);
                zs.avail_out = (uInt)(outBuf.size() - zs.total_out);
                status = inflate(&zs, Z_SYNC_FLUSH);
            }
            size_t produced = (size_t)zs.total_out;
            inflateEnd(&zs);
            if (status == Z_STREAM_END && produced > 0) {
                outBuf.resize(produced);
                viewPtr = &outBuf[0];
                viewLen = (unsigned long)produced;
                return true;
            }
            outBuf.clear();
        }
    }

    return true;
}

static void gclientDecodeEtc1Block4x4(
    const unsigned char* b,
    unsigned char* dstRgba,
    unsigned int dstWidth,
    unsigned int dstHeight,
    unsigned int blockOriginX,
    unsigned int blockOriginY)
{
    int r1 = 0, g1 = 0, b1 = 0;
    int r2 = 0, g2 = 0, b2 = 0;
    const int diffBit = (b[3] >> 1) & 1;
    const int flipBit = b[3] & 1;
    const int table1 = (b[3] >> 5) & 7;
    const int table2 = (b[3] >> 2) & 7;

    if (diffBit == 0) {
        int cr1 = (b[0] >> 4) & 0x0F;
        int cr2 = b[0] & 0x0F;
        int cg1 = (b[1] >> 4) & 0x0F;
        int cg2 = b[1] & 0x0F;
        int cb1 = (b[2] >> 4) & 0x0F;
        int cb2 = b[2] & 0x0F;
        r1 = (cr1 << 4) | cr1;
        r2 = (cr2 << 4) | cr2;
        g1 = (cg1 << 4) | cg1;
        g2 = (cg2 << 4) | cg2;
        b1 = (cb1 << 4) | cb1;
        b2 = (cb2 << 4) | cb2;
    } else {
        int br1 = (b[0] >> 3) & 0x1F;
        int dr = b[0] & 0x07;
        if (dr >= 4) dr -= 8;
        int br2 = br1 + dr;
        if (br2 < 0) br2 = 0; else if (br2 > 31) br2 = 31;

        int bg1 = (b[1] >> 3) & 0x1F;
        int dg = b[1] & 0x07;
        if (dg >= 4) dg -= 8;
        int bg2 = bg1 + dg;
        if (bg2 < 0) bg2 = 0; else if (bg2 > 31) bg2 = 31;

        int bb1 = (b[2] >> 3) & 0x1F;
        int db = b[2] & 0x07;
        if (db >= 4) db -= 8;
        int bb2 = bb1 + db;
        if (bb2 < 0) bb2 = 0; else if (bb2 > 31) bb2 = 31;

        r1 = (br1 << 3) | (br1 >> 2);
        r2 = (br2 << 3) | (br2 >> 2);
        g1 = (bg1 << 3) | (bg1 >> 2);
        g2 = (bg2 << 3) | (bg2 >> 2);
        b1 = (bb1 << 3) | (bb1 >> 2);
        b2 = (bb2 << 3) | (bb2 >> 2);
    }

    const unsigned int low = gclientReadBE32(b + 4);
    for (unsigned int x = 0; x < 4; ++x) {
        const unsigned int px = blockOriginX + x;
        if (px >= dstWidth) continue;
        for (unsigned int y = 0; y < 4; ++y) {
            const unsigned int py = blockOriginY + y;
            if (py >= dstHeight) continue;

            const unsigned int bitIdx = x * 4u + y;
            const unsigned int lsb = (low >> bitIdx) & 1u;
            const unsigned int msb = (low >> (16u + bitIdx)) & 1u;
            const unsigned int modIdx = (msb << 1) | lsb;

            const bool useSubblock2 = (flipBit == 0) ? (x >= 2u) : (y >= 2u);
            const int delta = useSubblock2
                ? kEtc1ModifierTables[table2][modIdx]
                : kEtc1ModifierTables[table1][modIdx];
            const int baseR = useSubblock2 ? r2 : r1;
            const int baseG = useSubblock2 ? g2 : g1;
            const int baseB = useSubblock2 ? b2 : b1;

            unsigned char* outPx = dstRgba + (((size_t)py * (size_t)dstWidth + (size_t)px) * 4u);
            outPx[0] = gclientClampByte(baseR + delta);
            outPx[1] = gclientClampByte(baseG + delta);
            outPx[2] = gclientClampByte(baseB + delta);
            outPx[3] = 255;
        }
    }
}

static bool gclientDecodeEtc1BlocksToRgba(
    const unsigned char* blocks,
    unsigned long blocksLen,
    unsigned int encodedWidth,
    unsigned int encodedHeight,
    unsigned int outWidth,
    unsigned int outHeight,
    std::vector<unsigned char>& outRgba)
{
    if (outWidth == 0 || outHeight == 0 || outWidth > 16384u || outHeight > 16384u) {
        return false;
    }
    unsigned int blocksX = (encodedWidth + 3u) / 4u;
    unsigned int blocksY = (encodedHeight + 3u) / 4u;
    if (blocksX == 0 || blocksY == 0) {
        return false;
    }
    size_t neededBytes = (size_t)blocksX * (size_t)blocksY * 8u;
    if ((size_t)blocksLen < neededBytes) {
        return false;
    }

    outRgba.assign((size_t)outWidth * (size_t)outHeight * 4u, 255u);
    const unsigned char* cur = blocks;
    for (unsigned int by = 0; by < blocksY; ++by) {
        for (unsigned int bx = 0; bx < blocksX; ++bx) {
            gclientDecodeEtc1Block4x4(cur, &outRgba[0], outWidth, outHeight, bx * 4u, by * 4u);
            cur += 8;
        }
    }
    return true;
}

static bool gclientDecodePKMBuffer(
    const unsigned char* rawBuf,
    unsigned long rawLen,
    std::vector<unsigned char>& outRgba,
    unsigned int& outWidth,
    unsigned int& outHeight)
{
    std::vector<unsigned char> inflated;
    const unsigned char* data = NULL;
    unsigned long dataLen = 0;
    if (!gclientMaybeDecompressPayload(rawBuf, rawLen, inflated, data, dataLen)) {
        return false;
    }
    if (!data || dataLen < 16) {
        return false;
    }
    if (!(data[0] == 'P' && data[1] == 'K' && data[2] == 'M' && data[3] == ' ')) {
        return false;
    }
    unsigned int extW = gclientReadBE16(data + 8);
    unsigned int extH = gclientReadBE16(data + 10);
    unsigned int origW = gclientReadBE16(data + 12);
    unsigned int origH = gclientReadBE16(data + 14);
    if (origW == 0) origW = extW;
    if (origH == 0) origH = extH;
    if (extW < origW) extW = (origW + 3u) & ~3u;
    if (extH < origH) extH = (origH + 3u) & ~3u;

    if (!gclientDecodeEtc1BlocksToRgba(data + 16, dataLen - 16, extW, extH, origW, origH, outRgba)) {
        return false;
    }
    outWidth = origW;
    outHeight = origH;
    return true;
}

static bool gclientExtractAlphaChannelBuffer(
    const unsigned char* rawAlpha,
    unsigned long rawAlphaLen,
    std::vector<unsigned char>& outAlphaPlane,
    unsigned int& outAlphaW,
    unsigned int& outAlphaH)
{
    std::vector<unsigned char> inflated;
    const unsigned char* data = NULL;
    unsigned long dataLen = 0;
    if (!gclientMaybeDecompressPayload(rawAlpha, rawAlphaLen, inflated, data, dataLen) || !data || dataLen < 8) {
        return false;
    }

    // 1. Companion PKM alpha (Green channel holds alpha in etcpack / Mali Texture Compression Tool)
    if (dataLen >= 16 && data[0] == 'P' && data[1] == 'K' && data[2] == 'M' && data[3] == ' ') {
        std::vector<unsigned char> alphaRgba;
        unsigned int aw = 0, ah = 0;
        if (!gclientDecodePKMBuffer(data, dataLen, alphaRgba, aw, ah)) {
            return false;
        }
        size_t totalPx = (size_t)aw * (size_t)ah;
        outAlphaPlane.resize(totalPx);
        for (size_t i = 0; i < totalPx; ++i) {
            outAlphaPlane[i] = alphaRgba[i * 4u + 1u];
        }
        outAlphaW = aw;
        outAlphaH = ah;
        return true;
    }

    // 2. Companion PVR v3 (0x03525650) or PVR v2 ("PVR!" at +44), e.g. inflated _alpha.pvr.ccz
    if (dataLen >= 52 && gclientReadLE32(data) == 0x03525650u) {
        unsigned int pfLo = gclientReadLE32(data + 8);
        unsigned int pfHi = gclientReadLE32(data + 12);
        unsigned int ah = gclientReadLE32(data + 24);
        unsigned int aw = gclientReadLE32(data + 28);
        unsigned int metaLen = gclientReadLE32(data + 48);
        if (aw > 0 && ah > 0 && aw <= 16384u && ah <= 16384u && dataLen >= 52u + metaLen) {
            const unsigned char* payload = data + 52u + metaLen;
            unsigned long payloadLen = dataLen - (52u + metaLen);
            size_t totalPx = (size_t)aw * (size_t)ah;
            if (pfHi == 0 && pfLo == 6u) {
                std::vector<unsigned char> alphaRgba;
                unsigned int extW = (aw + 3u) & ~3u;
                unsigned int extH = (ah + 3u) & ~3u;
                if (gclientDecodeEtc1BlocksToRgba(payload, payloadLen, extW, extH, aw, ah, alphaRgba)) {
                    outAlphaPlane.resize(totalPx);
                    for (size_t i = 0; i < totalPx; ++i) outAlphaPlane[i] = alphaRgba[i * 4u + 1u];
                    outAlphaW = aw;
                    outAlphaH = ah;
                    return true;
                }
            } else if (pfHi != 0) {
                if (payloadLen >= totalPx * 4u) {
                    outAlphaPlane.resize(totalPx);
                    bool hasVariedA = false;
                    for (size_t i = 0; i < totalPx; ++i) {
                        if (payload[i * 4u + 3u] != 255u) { hasVariedA = true; break; }
                    }
                    for (size_t i = 0; i < totalPx; ++i) {
                        outAlphaPlane[i] = hasVariedA ? payload[i * 4u + 3u] : payload[i * 4u + 1u];
                    }
                    outAlphaW = aw;
                    outAlphaH = ah;
                    return true;
                } else if (payloadLen >= totalPx * 2u) {
                    outAlphaPlane.resize(totalPx);
                    for (size_t i = 0; i < totalPx; ++i) {
                        outAlphaPlane[i] = payload[i * 2u + 1u];
                    }
                    outAlphaW = aw;
                    outAlphaH = ah;
                    return true;
                } else if (payloadLen >= totalPx) {
                    outAlphaPlane.assign(payload, payload + totalPx);
                    outAlphaW = aw;
                    outAlphaH = ah;
                    return true;
                }
            }
        }
    } else if (dataLen >= 52 && data[44] == 'P' && data[45] == 'V' && data[46] == 'R' && data[47] == '!') {
        unsigned int ah = gclientReadLE32(data + 4);
        unsigned int aw = gclientReadLE32(data + 8);
        unsigned int fmt = gclientReadLE32(data + 16) & 0xFFu;
        const unsigned char* payload = data + 52u;
        unsigned long payloadLen = dataLen - 52u;
        size_t totalPx = (size_t)aw * (size_t)ah;
        if (aw > 0 && ah > 0 && aw <= 16384u && ah <= 16384u) {
            if (fmt == 0x16u && payloadLen >= totalPx) {
                outAlphaPlane.assign(payload, payload + totalPx);
                outAlphaW = aw;
                outAlphaH = ah;
                return true;
            } else if (fmt == 0x17u && payloadLen >= totalPx * 2u) {
                outAlphaPlane.resize(totalPx);
                for (size_t i = 0; i < totalPx; ++i) outAlphaPlane[i] = payload[i * 2u + 1u];
                outAlphaW = aw;
                outAlphaH = ah;
                return true;
            } else if (fmt == 0x12u && payloadLen >= totalPx * 4u) {
                outAlphaPlane.resize(totalPx);
                bool hasVariedA = false;
                for (size_t i = 0; i < totalPx; ++i) {
                    if (payload[i * 4u + 3u] != 255u) { hasVariedA = true; break; }
                }
                for (size_t i = 0; i < totalPx; ++i) {
                    outAlphaPlane[i] = hasVariedA ? payload[i * 4u + 3u] : payload[i * 4u + 1u];
                }
                outAlphaW = aw;
                outAlphaH = ah;
                return true;
            }
        }
    }

    // 3. Companion PNG / JPG / WebP via CCImage
    CCImage img;
    if (img.initWithImageData(const_cast<unsigned char*>(data), (int)dataLen, CCImage::kFmtUnKnown)) {
        unsigned int aw = (unsigned int)img.getWidth();
        unsigned int ah = (unsigned int)img.getHeight();
        unsigned char* px = img.getData();
        int pxBytes = img.getDataLen();
        size_t totalPx = (size_t)aw * (size_t)ah;
        if (px && aw > 0 && ah > 0 && totalPx > 0) {
            outAlphaPlane.resize(totalPx);
            if (img.hasAlpha() && (size_t)pxBytes >= totalPx * 4u) {
                bool hasVariedAlpha = false;
                for (size_t i = 0; i < totalPx; ++i) {
                    if (px[i * 4u + 3u] != 255u) {
                        hasVariedAlpha = true;
                        break;
                    }
                }
                for (size_t i = 0; i < totalPx; ++i) {
                    outAlphaPlane[i] = hasVariedAlpha ? px[i * 4u + 3u] : px[i * 4u + 1u];
                }
                outAlphaW = aw;
                outAlphaH = ah;
                return true;
            } else if ((size_t)pxBytes >= totalPx * 3u) {
                size_t bpp = (size_t)pxBytes / totalPx;
                for (size_t i = 0; i < totalPx; ++i) {
                    outAlphaPlane[i] = px[i * bpp + 1u];
                }
                outAlphaW = aw;
                outAlphaH = ah;
                return true;
            } else if ((size_t)pxBytes >= totalPx) {
                memcpy(&outAlphaPlane[0], px, totalPx);
                outAlphaW = aw;
                outAlphaH = ah;
                return true;
            }
        }
    }

    return false;
}

static std::string gclientStripKnownTexExt(const std::string& p) {
    if (p.size() > 8 && p.compare(p.size() - 8, 8, ".pvr.ccz") == 0) {
        return p.substr(0, p.size() - 8);
    }
    size_t slash = p.find_last_of("/\\");
    size_t dot = p.find_last_of('.');
    if (dot != std::string::npos && (slash == std::string::npos || dot > slash)) {
        return p.substr(0, dot);
    }
    return p;
}

static void gclientAppendUnique(std::vector<std::string>& list, const std::string& item) {
    if (item.empty()) return;
    for (size_t i = 0; i < list.size(); ++i) {
        if (list[i] == item) return;
    }
    list.push_back(item);
}

} // anonymous namespace

bool ccDecodePKMWithAlpha(
    const char* file,
    unsigned char** outRgbaPremul,
    unsigned int* outWidth,
    unsigned int* outHeight,
    bool* outHasAlpha)
{
    if (!file || !file[0] || !outRgbaPremul || !outWidth || !outHeight) {
        return false;
    }
    *outRgbaPremul = NULL;
    *outWidth = 0;
    *outHeight = 0;
    if (outHasAlpha) *outHasAlpha = false;

    CCFileUtils* fileUtils = CCFileUtils::sharedFileUtils();
    if (!fileUtils) {
        return false;
    }

    bool oldPopup = fileUtils->isPopupNotify();
    fileUtils->setPopupNotify(false);

    std::string fullPath = fileUtils->fullPathForFilename(file);
    if (fullPath.empty()) {
        fullPath = file;
    }
    if (!fileUtils->isFileExist(fullPath)) {
        fileUtils->setPopupNotify(oldPopup);
        return false;
    }

    unsigned long pkmSize = 0;
    unsigned char* pkmBytes = fileUtils->getFileData(fullPath.c_str(), "rb", &pkmSize);
    if (!pkmBytes || pkmSize == 0) {
        delete[] pkmBytes;
        fileUtils->setPopupNotify(oldPopup);
        return false;
    }

    std::vector<unsigned char> rgbaVec;
    unsigned int width = 0, height = 0;
    bool decodedOk = gclientDecodePKMBuffer(pkmBytes, pkmSize, rgbaVec, width, height);
    delete[] pkmBytes;
    if (!decodedOk || width == 0 || height == 0) {
        fileUtils->setPopupNotify(oldPopup);
        return false;
    }

    // Probe companion _alpha candidates across both requested path and resolved fullPath
    std::vector<std::string> alphaCandidates;
    const std::string origStr(file);
    const std::string origStem = gclientStripKnownTexExt(origStr);
    const std::string fullStem = gclientStripKnownTexExt(fullPath);

    gclientAppendUnique(alphaCandidates, origStr + "_alpha");
    gclientAppendUnique(alphaCandidates, fullPath + "_alpha");
    gclientAppendUnique(alphaCandidates, origStem + ".pkm_alpha");
    gclientAppendUnique(alphaCandidates, fullStem + ".pkm_alpha");
    gclientAppendUnique(alphaCandidates, origStem + "_alpha.pkm");
    gclientAppendUnique(alphaCandidates, fullStem + "_alpha.pkm");
    gclientAppendUnique(alphaCandidates, origStem + "_alpha");
    gclientAppendUnique(alphaCandidates, fullStem + "_alpha");
    gclientAppendUnique(alphaCandidates, origStem + "_alpha.png");
    gclientAppendUnique(alphaCandidates, fullStem + "_alpha.png");
    gclientAppendUnique(alphaCandidates, origStem + "_alpha.pvr.ccz");
    gclientAppendUnique(alphaCandidates, fullStem + "_alpha.pvr.ccz");
    gclientAppendUnique(alphaCandidates, origStem + "_alpha.webp");
    gclientAppendUnique(alphaCandidates, fullStem + "_alpha.webp");
    gclientAppendUnique(alphaCandidates, origStem + "_alpha.jpg");
    gclientAppendUnique(alphaCandidates, fullStem + "_alpha.jpg");

    bool foundAlpha = false;
    std::vector<unsigned char> alphaPlane;
    unsigned int alphaW = 0, alphaH = 0;

    for (size_t i = 0; i < alphaCandidates.size(); ++i) {
        std::string resolvedAlpha = fileUtils->fullPathForFilename(alphaCandidates[i].c_str());
        if (resolvedAlpha.empty() || !fileUtils->isFileExist(resolvedAlpha)) {
            continue;
        }
        unsigned long alphaBytesLen = 0;
        unsigned char* alphaBytes = fileUtils->getFileData(resolvedAlpha.c_str(), "rb", &alphaBytesLen);
        if (!alphaBytes || alphaBytesLen == 0) {
            delete[] alphaBytes;
            continue;
        }
        bool okAlpha = gclientExtractAlphaChannelBuffer(alphaBytes, alphaBytesLen, alphaPlane, alphaW, alphaH);
        delete[] alphaBytes;
        if (okAlpha && alphaW > 0 && alphaH > 0) {
            foundAlpha = true;
            break;
        }
    }

    fileUtils->setPopupNotify(oldPopup);

    const size_t totalPixels = (size_t)width * (size_t)height;
    if (foundAlpha) {
        if (alphaW == width && alphaH == height) {
            for (size_t px = 0; px < totalPixels; ++px) {
                const unsigned int a = alphaPlane[px];
                unsigned char* p = &rgbaVec[px * 4u];
                p[0] = (unsigned char)(((unsigned int)p[0] * a + 127u) / 255u);
                p[1] = (unsigned char)(((unsigned int)p[1] * a + 127u) / 255u);
                p[2] = (unsigned char)(((unsigned int)p[2] * a + 127u) / 255u);
                p[3] = (unsigned char)a;
            }
        } else {
            for (unsigned int y = 0; y < height; ++y) {
                unsigned int sy = (y * alphaH) / height;
                if (sy >= alphaH) sy = alphaH - 1u;
                for (unsigned int x = 0; x < width; ++x) {
                    unsigned int sx = (x * alphaW) / width;
                    if (sx >= alphaW) sx = alphaW - 1u;
                    const unsigned int a = alphaPlane[(size_t)sy * (size_t)alphaW + (size_t)sx];
                    unsigned char* p = &rgbaVec[((size_t)y * (size_t)width + (size_t)x) * 4u];
                    p[0] = (unsigned char)(((unsigned int)p[0] * a + 127u) / 255u);
                    p[1] = (unsigned char)(((unsigned int)p[1] * a + 127u) / 255u);
                    p[2] = (unsigned char)(((unsigned int)p[2] * a + 127u) / 255u);
                    p[3] = (unsigned char)a;
                }
            }
        }
    }

    unsigned char* outBuf = (unsigned char*)malloc(totalPixels * 4u);
    if (!outBuf) {
        return false;
    }
    memcpy(outBuf, &rgbaVec[0], totalPixels * 4u);
    *outRgbaPremul = outBuf;
    *outWidth = width;
    *outHeight = height;
    if (outHasAlpha) *outHasAlpha = foundAlpha;
    return true;
}

CCTextureETC::CCTextureETC()
: _name(0)
, _width(0)
, _height(0)
{}

CCTextureETC::~CCTextureETC()
{
    if (_name != 0) {
        ccGLDeleteTexture(_name);
        _name = 0;
    }
}

bool CCTextureETC::initWithFile(const char *file)
{
    return loadTexture(file);
}

unsigned int CCTextureETC::getName() const
{
    return _name;
}

unsigned int CCTextureETC::getWidth() const
{
    return _width;
}

unsigned int CCTextureETC::getHeight() const
{
    return _height;
}

bool CCTextureETC::loadTexture(const char* file)
{
    unsigned char* rgba = NULL;
    unsigned int w = 0, h = 0;
    if (!ccDecodePKMWithAlpha(file, &rgba, &w, &h, NULL)) {
        return false;
    }

    if (_name != 0) {
        ccGLDeleteTexture(_name);
        _name = 0;
    }

    _width = w;
    _height = h;

    glPixelStorei(GL_UNPACK_ALIGNMENT, 4);
    glGenTextures(1, &_name);
    ccGLBindTexture2D(_name);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, (GLsizei)_width, (GLsizei)_height, 0, GL_RGBA, GL_UNSIGNED_BYTE, rgba);

    free(rgba);
    return _name != 0;
}

NS_CC_END
"""


def patch_texture_cache_multi_ext(cocos_root: str) -> None:
    tex_dir = os.path.join(cocos_root, "cocos2dx", "textures")
    cache_cpp = os.path.join(tex_dir, "CCTextureCache.cpp")
    if not os.path.exists(cache_cpp):
        return

    txt = open(cache_cpp, "r", encoding="utf-8", errors="replace").read()
    orig_txt = txt

    if TEXCACHE_MARKER not in txt:
        if '"CCTextureETC.h"' not in txt and "<CCTextureETC.h>" not in txt:
            txt = _insert_before_ns_cc_begin(txt, '#include "CCTextureETC.h"')
        txt = re.sub(
            r"#if\s*\(\s*CC_TARGET_PLATFORM\s*==\s*CC_PLATFORM_ANDROID\s*\)\s*(\n[^\n]*CCTextureCache::addETCImage\b)",
            r"#if 1 // GCLIENT_ENABLE_ETC_WIN32\1",
            txt,
        )

        etc_spans = _find_method_body_spans(txt, "CCTextureCache::addETCImage")
        if etc_spans:
            b_start, b_end = etc_spans[-1]
            sig_slice = txt[max(0, b_start - 180):b_start]
            p_match = re.search(r"\(\s*const\s+char\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", sig_slice)
            p_name = p_match.group(1) if p_match else "path"
            new_etc_body = (
                "{\n"
                f"    // {TEXCACHE_MARKER}\n"
                f"    if (!{p_name} || !{p_name}[0]) return NULL;\n"
                f"    std::string key = CCFileUtils::sharedFileUtils()->fullPathForFilename({p_name});\n"
                f"    if (key.empty()) key = {p_name};\n"
                "    if (CCTexture2D* cached = (CCTexture2D*)m_pTextures->objectForKey(key.c_str())) {\n"
                "        return cached;\n"
                "    }\n"
                "    CCTexture2D* texture = new CCTexture2D();\n"
                "    if (texture && texture->initWithETCFile(key.c_str())) {\n"
                "        m_pTextures->setObject(texture, key.c_str());\n"
                "        texture->autorelease();\n"
                "        return texture;\n"
                "    }\n"
                "    CC_SAFE_RELEASE(texture);\n"
                "    return NULL;\n"
                "}"
            )
            txt = txt[:b_start] + new_etc_body + txt[b_end:]

        add_spans = _find_method_body_spans(txt, "CCTextureCache::addImage")
        if add_spans:
            b_start, b_end = add_spans[-1]
            sig_slice = txt[max(0, b_start - 200):b_start]
            p_match = re.search(r"\(\s*const\s+char\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", sig_slice)
            p_name = p_match.group(1) if p_match else "path"
            body = txt[b_start:b_end]

            prologue = (
                "{\n"
                f"    // {TEXCACHE_MARKER}\n"
                f"    if (!{p_name} || !{p_name}[0]) return NULL;\n"
                f"    std::string gclientOrigKey = CCFileUtils::sharedFileUtils()->fullPathForFilename({p_name});\n"
                f"    if (gclientOrigKey.empty()) gclientOrigKey = {p_name};\n"
                "    if (CCTexture2D* gclientCached = (CCTexture2D*)m_pTextures->objectForKey(gclientOrigKey.c_str())) {\n"
                "        return gclientCached;\n"
                "    }\n"
                "    std::string gclientResolved = gclientOrigKey;\n"
                "    {\n"
                "        CCFileUtils* gclientFU = CCFileUtils::sharedFileUtils();\n"
                "        bool gclientOldPopup = gclientFU->isPopupNotify();\n"
                "        gclientFU->setPopupNotify(false);\n"
                "        if (!gclientFU->isFileExist(gclientResolved)) {\n"
                f"            std::string gclientStem({p_name});\n"
                "            if (gclientStem.size() > 8 && gclientStem.compare(gclientStem.size() - 8, 8, \".pvr.ccz\") == 0) {\n"
                "                gclientStem.erase(gclientStem.size() - 8);\n"
                "            } else {\n"
                "                size_t gclientSlash = gclientStem.find_last_of(\"/\\\\\");\n"
                "                size_t gclientDot = gclientStem.find_last_of('.');\n"
                "                if (gclientDot != std::string::npos && (gclientSlash == std::string::npos || gclientDot > gclientSlash)) {\n"
                "                    gclientStem.erase(gclientDot);\n"
                "                }\n"
                "            }\n"
                "            static const char* const kGClientExts[] = { \".pvr.ccz\", \".pkm\", \".png\", \".webp\" };\n"
                "            for (int gclientIdx = 0; gclientIdx < 4; ++gclientIdx) {\n"
                "                std::string gclientCand = gclientStem + kGClientExts[gclientIdx];\n"
                "                std::string gclientCandFull = gclientFU->fullPathForFilename(gclientCand.c_str());\n"
                "                if (!gclientCandFull.empty() && gclientFU->isFileExist(gclientCandFull)) {\n"
                "                    gclientResolved = gclientCandFull;\n"
                "                    break;\n"
                "                }\n"
                "            }\n"
                "        }\n"
                "        gclientFU->setPopupNotify(gclientOldPopup);\n"
                "    }\n"
                "    if (CCTexture2D* gclientCached2 = (CCTexture2D*)m_pTextures->objectForKey(gclientResolved.c_str())) {\n"
                "        if (gclientOrigKey != gclientResolved) {\n"
                "            m_pTextures->setObject(gclientCached2, gclientOrigKey.c_str());\n"
                "        }\n"
                "        return gclientCached2;\n"
                "    }\n"
                "    {\n"
                "        std::string gclientLower = gclientResolved;\n"
                "        for (size_t gclientI = 0; gclientI < gclientLower.size(); ++gclientI) {\n"
                "            if (gclientLower[gclientI] >= 'A' && gclientLower[gclientI] <= 'Z') {\n"
                "                gclientLower[gclientI] = (char)(gclientLower[gclientI] - 'A' + 'a');\n"
                "            }\n"
                "        }\n"
                "        if (gclientLower.size() >= 4 && gclientLower.compare(gclientLower.size() - 4, 4, \".pkm\") == 0) {\n"
                "            CCTexture2D* gclientTex = new CCTexture2D();\n"
                "            if (gclientTex && gclientTex->initWithETCFile(gclientResolved.c_str())) {\n"
                "                m_pTextures->setObject(gclientTex, gclientResolved.c_str());\n"
                "                if (gclientOrigKey != gclientResolved) {\n"
                "                    m_pTextures->setObject(gclientTex, gclientOrigKey.c_str());\n"
                "                }\n"
                "                gclientTex->autorelease();\n"
                "                return gclientTex;\n"
                "            }\n"
                "            CC_SAFE_RELEASE(gclientTex);\n"
                "            return NULL;\n"
                "        }\n"
                "        if (gclientOrigKey != gclientResolved) {\n"
                "            CCTexture2D* gclientTex = this->addImage(gclientResolved.c_str());\n"
                "            if (gclientTex) {\n"
                "                m_pTextures->setObject(gclientTex, gclientOrigKey.c_str());\n"
                "            }\n"
                "            return gclientTex;\n"
                "        }\n"
                "    }\n"
            )

            epilogue_re = re.compile(r"([ \t]*return\s+texture\s*;\s*\}$)")
            patched_body = prologue + body[1:]
            m_end = epilogue_re.search(patched_body)
            if m_end:
                disguised_rescue = (
                    "    if (!texture) {\n"
                    "        CCTexture2D* gclientDisguised = new CCTexture2D();\n"
                    "        if (gclientDisguised && gclientDisguised->initWithETCFile(gclientResolved.c_str())) {\n"
                    "            m_pTextures->setObject(gclientDisguised, gclientOrigKey.c_str());\n"
                    "            gclientDisguised->autorelease();\n"
                    "            texture = gclientDisguised;\n"
                    "        } else {\n"
                    "            CC_SAFE_RELEASE(gclientDisguised);\n"
                    "        }\n"
                    "    }\n"
                )
                patched_body = patched_body[:m_end.start()] + disguised_rescue + patched_body[m_end.start():]
            txt = txt[:b_start] + patched_body + txt[b_end:]

    if TEXCACHE_V2_MARKER not in txt:
        # Null guard in CCTextureCache::addImageAsync
        for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "CCTextureCache::addImageAsync")):
            body = txt[b_start:b_end]
            if TEXCACHE_V2_MARKER not in body:
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                p_var = _extract_param_ident(params[0], "path") if params else "path"
                patched_body = _inject_after_open_brace(body, f"if (!{p_var} || !{p_var}[0]) return; // {TEXCACHE_V2_MARKER}")
                txt = txt[:b_start] + patched_body + txt[b_end:]

        q_match = re.search(
            r"(?:std::)?queue\s*<\s*ImageInfo\s*\*\s*>\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)",
            txt,
        )
        queue_var = q_match.group(1) if q_match else (
            "s_pImageInfoQueue" if "s_pImageInfoQueue" in txt else "s_pImageQueue"
        )
        m_match = re.search(
            r"pthread_mutex_lock\s*\(\s*&\s*([A-Za-z_][A-Za-z0-9_]*[Ii]mageInfoMutex)\s*\)",
            txt,
        )
        mutex_var = m_match.group(1) if m_match else (
            "s_imageInfoMutex" if "s_imageInfoMutex" in txt else "s_ImageInfoMutex"
        )

        # Patch worker-thread loadImageData (and loadImage if inlined) so BOTH kFmtUnKnown AND failed
        # initWithImageFileThreadSafe (!bRet) push pInfo (image = NULL) onto s_pImageQueue under mutex!
        for worker_fn in ("CCTextureCache::loadImageData", "loadImageData", "loadImage"):
            w_spans = _find_method_body_spans(txt, worker_fn)
            if not w_spans:
                continue
            b_start, b_end = w_spans[-1]
            load_body = txt[b_start:b_end]
            orig_load = load_body

            del_re = re.compile(r"delete\s+pAsyncStruct\s*;\s*(continue\s*;|return(?:\s+[^;]*)?\s*;)")
            fallback_push = (
                "{ // " + TEXCACHE_V2_MARKER + "\n"
                "                ImageInfo* pFallbackInfo = new ImageInfo();\n"
                "                pFallbackInfo->asyncStruct = pAsyncStruct;\n"
                "                pFallbackInfo->image = NULL;\n"
                "                pFallbackInfo->imageType = CCImage::kFmtUnKnown;\n"
                f"                pthread_mutex_lock(&{mutex_var});\n"
                f"                {queue_var}->push(pFallbackInfo);\n"
                f"                pthread_mutex_unlock(&{mutex_var});\n"
                "                \\1\n"
                "            }"
            )
            load_body = del_re.sub(fallback_push, load_body)

            fail_re = re.compile(
                r"(CC_SAFE_RELEASE\s*\(\s*pImage\s*\)\s*;(?:(?!pFallbackInfo)[^{}])*?)"
                r"(continue\s*;|return(?:\s+[^;]*)?\s*;)",
                re.DOTALL,
            )
            fail_push = (
                "\\1"
                "{ // " + TEXCACHE_V2_MARKER + "\n"
                "            ImageInfo* pFallbackInfo = new ImageInfo();\n"
                "            pFallbackInfo->asyncStruct = pAsyncStruct;\n"
                "            pFallbackInfo->image = NULL;\n"
                "            pFallbackInfo->imageType = CCImage::kFmtUnKnown;\n"
                f"            pthread_mutex_lock(&{mutex_var});\n"
                f"            {queue_var}->push(pFallbackInfo);\n"
                f"            pthread_mutex_unlock(&{mutex_var});\n"
                "        }\n"
                "        \\2"
            )
            load_body = fail_re.sub(fail_push, load_body)

            if load_body != orig_load:
                txt = txt[:b_start] + load_body + txt[b_end:]
                break

        # Patch CCTextureCache::addImageAsyncCallBack:
        # 1) When pImage == NULL, gclientTex = this->addImage(...); only call selector when gclientTex != NULL.
        # 2) When pImage != NULL, check if (texture && texture->initWithImage(pImage)) before caching in m_pTextures!
        cb_spans = _find_method_body_spans(txt, "CCTextureCache::addImageAsyncCallBack")
        if cb_spans:
            b_start, b_end = cb_spans[-1]
            cb_body = txt[b_start:b_end]
            # Upgrade legacy v1 block if present, or replace from `CCImage *pImage = pImageInfo->image;` to end of else block.
            img_pos_m = re.search(r"CCImage\s*\*\s*pImage\s*=\s*pImageInfo->image\s*;", cb_body)
            unref_m = re.search(
                r"--\s*s_nAsyncRefCount\s*;\s*if\s*\(\s*0\s*==\s*s_nAsyncRefCount\s*\)\s*\{[^{}]*\}",
                cb_body,
                re.DOTALL,
            )
            if img_pos_m and unref_m and unref_m.end() > img_pos_m.start():
                has_volatile = "VolatileTexture::addImageTexture" in cb_body
                volatile_block = (
                    "#if CC_ENABLE_CACHE_TEXTURE_DATA\n"
                    "            VolatileTexture::addImageTexture(texture, filename, pImageInfo->imageType);\n"
                    "#endif\n"
                ) if has_volatile else ""
                new_cb_tail = (
                    "CCImage *pImage = pImageInfo->image;\n"
                    f"        // {TEXCACHE_V2_MARKER}\n"
                    "        if (pImage == NULL)\n"
                    "        {\n"
                    "            CCObject* gclientTarget = pAsyncStruct->target;\n"
                    "            SEL_CallFuncO gclientSelector = pAsyncStruct->selector;\n"
                    "            CCTexture2D* gclientTex = this->addImage(pAsyncStruct->filename.c_str());\n"
                    "            if (gclientTex && gclientTarget && gclientSelector)\n"
                    "            {\n"
                    "                (gclientTarget->*gclientSelector)(gclientTex);\n"
                    "            }\n"
                    "            if (gclientTarget)\n"
                    "            {\n"
                    "                gclientTarget->release();\n"
                    "            }\n"
                    "            delete pAsyncStruct;\n"
                    "            delete pImageInfo;\n"
                    "            --s_nAsyncRefCount;\n"
                    "            if (0 == s_nAsyncRefCount)\n"
                    "            {\n"
                    "                CCDirector::sharedDirector()->getScheduler()->unscheduleSelector(\n"
                    "                    schedule_selector(CCTextureCache::addImageAsyncCallBack), this);\n"
                    "            }\n"
                    "            return;\n"
                    "        }\n\n"
                    "        CCObject *target = pAsyncStruct->target;\n"
                    "        SEL_CallFuncO selector = pAsyncStruct->selector;\n"
                    "        const char* filename = pAsyncStruct->filename.c_str();\n\n"
                    "        CCTexture2D *texture = new CCTexture2D();\n"
                    "        if (texture && texture->initWithImage(pImage))\n"
                    "        {\n"
                    + volatile_block +
                    "            m_pTextures->setObject(texture, filename);\n"
                    "            texture->autorelease();\n"
                    "            if (target && selector)\n"
                    "            {\n"
                    "                (target->*selector)(texture);\n"
                    "            }\n"
                    "        }\n"
                    "        else\n"
                    "        {\n"
                    "            CC_SAFE_RELEASE_NULL(texture);\n"
                    "            CCTexture2D* gclientFallbackTex = this->addImage(filename);\n"
                    "            if (gclientFallbackTex && target && selector)\n"
                    "            {\n"
                    "                (target->*selector)(gclientFallbackTex);\n"
                    "            }\n"
                    "        }\n"
                    "        if (target)\n"
                    "        {\n"
                    "            target->release();\n"
                    "        }\n\n"
                    "        pImage->release();\n"
                    "        delete pAsyncStruct;\n"
                    "        delete pImageInfo;\n\n"
                    "        --s_nAsyncRefCount;\n"
                    "        if (0 == s_nAsyncRefCount)\n"
                    "        {\n"
                    "            CCDirector::sharedDirector()->getScheduler()->unscheduleSelector(\n"
                    "                schedule_selector(CCTextureCache::addImageAsyncCallBack), this);\n"
                    "        }"
                )
                cb_body = cb_body[:img_pos_m.start()] + new_cb_tail + cb_body[unref_m.end():]
                txt = txt[:b_start] + cb_body + txt[b_end:]

    if txt != orig_txt:
        open(cache_cpp, "w", encoding="utf-8", newline="\n").write(txt)
        print(f"[ok] Patched CCTextureCache.cpp: {cache_cpp}")
    else:
        print(f"[skip] Already patched CCTextureCache.cpp: {cache_cpp}")


def patch_etc1_and_textures(cocos_root: str) -> None:
    tex_dir = os.path.join(cocos_root, "cocos2dx", "textures")

    # 1. CCTextureETC.h: declare ccDecodePKMWithAlpha inside NS_CC_BEGIN
    etc_h = os.path.join(tex_dir, "CCTextureETC.h")
    if os.path.exists(etc_h):
        txt = open(etc_h, "r", encoding="utf-8", errors="replace").read()
        if ETC1_MARKER not in txt:
            decl = (
                "\n// " + ETC1_MARKER + "\n"
                "CC_DLL bool ccDecodePKMWithAlpha(\n"
                "    const char* file,\n"
                "    unsigned char** outRgbaPremul,\n"
                "    unsigned int* outWidth,\n"
                "    unsigned int* outHeight,\n"
                "    bool* outHasAlpha = 0);\n\n"
            )
            if "class CC_DLL CCTextureETC" in txt:
                txt = txt.replace("class CC_DLL CCTextureETC", decl + "class CC_DLL CCTextureETC", 1)
            elif "class CCTextureETC" in txt:
                txt = txt.replace("class CCTextureETC", decl + "class CCTextureETC", 1)
            else:
                raise RuntimeError(f"CCTextureETC class anchor not found in {etc_h}")
            open(etc_h, "w", encoding="utf-8", newline="\n").write(txt)
            print(f"[ok] Patched CCTextureETC.h: {etc_h}")
        else:
            print(f"[skip] Already patched CCTextureETC.h: {etc_h}")

    # 2. CCTextureETC.cpp: replace Android-only stub with cross-platform software ETC1 + _alpha decoder
    etc_cpp = os.path.join(tex_dir, "CCTextureETC.cpp")
    if os.path.exists(etc_cpp):
        txt = open(etc_cpp, "r", encoding="utf-8", errors="replace").read()
        if ETC1_MARKER not in txt:
            open(etc_cpp, "w", encoding="utf-8", newline="\n").write(ETC1_TEXTURE_ETC_CPP)
            print(f"[ok] Patched CCTextureETC.cpp: {etc_cpp}")
        else:
            print(f"[skip] Already patched CCTextureETC.cpp: {etc_cpp}")

    # 3. CCTexture2D.cpp: decode .pkm + _alpha in CCTexture2D::initWithETCFile with premultiplied RGBA8888
    tex2d_cpp = os.path.join(tex_dir, "CCTexture2D.cpp")
    if os.path.exists(tex2d_cpp):
        txt = open(tex2d_cpp, "r", encoding="utf-8", errors="replace").read()
        orig_txt = txt
        if TEX2D_ETC_MARKER not in txt:
            if "CCTextureETC.h" not in txt:
                txt = _insert_before_ns_cc_begin(txt, '#include "CCTextureETC.h"\n#include <stdlib.h>')
            elif "<stdlib.h>" not in txt and "<cstdlib>" not in txt:
                txt = _insert_before_ns_cc_begin(txt, "#include <stdlib.h>")

            spans = _find_method_body_spans(txt, "CCTexture2D::initWithETCFile")
            if spans:
                b_start, b_end = spans[-1]
                sig_slice = txt[max(0, b_start - 180):b_start]
                p_match = re.search(r"\(\s*const\s+char\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", sig_slice)
                p_name = p_match.group(1) if p_match else "file"
                new_body = (
                    "{\n"
                    f"    // {TEX2D_ETC_MARKER}\n"
                    "    unsigned char* rgbaData = NULL;\n"
                    "    unsigned int width = 0, height = 0;\n"
                    "    bool hasAlpha = false;\n"
                    f"    if (ccDecodePKMWithAlpha({p_name}, &rgbaData, &width, &height, &hasAlpha)) {{\n"
                    "        bool ok = initWithData(\n"
                    "            rgbaData,\n"
                    "            kCCTexture2DPixelFormat_RGBA8888,\n"
                    "            width,\n"
                    "            height,\n"
                    "            CCSizeMake((float)width, (float)height));\n"
                    "        free(rgbaData);\n"
                    "        if (ok) {\n"
                    "            m_bHasPremultipliedAlpha = true;\n"
                    "            return true;\n"
                    "        }\n"
                    "    }\n"
                    "    return false;\n"
                    "}"
                )
                txt = txt[:b_start] + new_body + txt[b_end:]

        if txt != orig_txt:
            open(tex2d_cpp, "w", encoding="utf-8", newline="\n").write(txt)
            print(f"[ok] Patched CCTexture2D.cpp: {tex2d_cpp}")
        else:
            print(f"[skip] Already patched CCTexture2D.cpp: {tex2d_cpp}")

    # 4. CCTextureCache.h: ensure addETCImage declaration is enabled on Win32 if platform-guarded
    cache_h = os.path.join(tex_dir, "CCTextureCache.h")
    if os.path.exists(cache_h):
        txt = open(cache_h, "r", encoding="utf-8", errors="replace").read()
        orig_txt = txt
        txt = re.sub(
            r"#if\s*\(\s*CC_TARGET_PLATFORM\s*==\s*CC_PLATFORM_ANDROID\s*\)\s*(\n[^\n]*\baddETCImage\b)",
            r"#if 1 // GCLIENT_ENABLE_ETC_WIN32\1",
            txt,
        )
        if txt != orig_txt:
            open(cache_h, "w", encoding="utf-8", newline="\n").write(txt)
            print(f"[ok] Patched CCTextureCache.h: {cache_h}")

    # 5. CCTextureCache.cpp: .pkm + multi-extension fallback in addImage/addETCImage + addImageAsync rescue
    patch_texture_cache_multi_ext(cocos_root)


def patch_pthread_header(path: str) -> None:
    if not os.path.exists(path):
        return
    txt = open(path, "r", encoding="utf-8", errors="replace").read()
    if "GCLIENT_TIMESPEC_FIX" in txt:
        print(f"[skip] Already patched pthread.h: {path}")
        return
    anchor = "#ifndef HAVE_STRUCT_TIMESPEC"
    if anchor not in txt:
        return
    fix = (
        "// GCLIENT_TIMESPEC_FIX: VS 2015+ UCRT <time.h> already defines struct timespec\n"
        "#if defined(_MSC_VER) && _MSC_VER >= 1900 && !defined(HAVE_STRUCT_TIMESPEC)\n"
        "#define HAVE_STRUCT_TIMESPEC 1\n"
        "#endif\n"
    )
    txt = txt.replace(anchor, fix + anchor, 1)
    open(path, "w", encoding="utf-8", newline="\n").write(txt)
    print(f"[ok] Patched pthread.h: {path}")


def patch_stdc_iob(path: str) -> None:
    if not os.path.exists(path):
        return
    txt = open(path, "r", encoding="utf-8", errors="replace").read()
    if "GCLIENT_LEGACY_STDIO_FIX" in txt:
        print(f"[skip] Already patched CCStdC.cpp: {path}")
        return
    if "GCLIENT_IOB_FUNC_FIX" in txt:
        txt = txt + "\n// GCLIENT_LEGACY_STDIO_FIX\n#if defined(_MSC_VER) && _MSC_VER >= 1900\n#pragma comment(lib, \"legacy_stdio_definitions.lib\")\n#endif\n"
        open(path, "w", encoding="utf-8", newline="\n").write(txt)
        print(f"[ok] Added legacy_stdio_definitions.lib to CCStdC.cpp: {path}")
        return
    shim = (
        "\n// GCLIENT_IOB_FUNC_FIX: VS 2015+ UCRT shim for 2012 prebuilt libpng/libjpeg\n"
        "// GCLIENT_LEGACY_STDIO_FIX\n"
        "#if defined(_MSC_VER) && _MSC_VER >= 1900\n"
        "#include <stdio.h>\n"
        "#pragma comment(lib, \"legacy_stdio_definitions.lib\")\n"
        "extern \"C\" FILE* __cdecl __iob_func(void) {\n"
        "    static FILE iob[3];\n"
        "    iob[0] = *stdin;\n"
        "    iob[1] = *stdout;\n"
        "    iob[2] = *stderr;\n"
        "    return iob;\n"
        "}\n"
        "#endif\n"
    )
    txt = txt + shim
    open(path, "w", encoding="utf-8", newline="\n").write(txt)
    print(f"[ok] Patched CCStdC.cpp: {path}")


def patch_stdc_h(path: str) -> None:
    if not os.path.exists(path):
        return
    txt = open(path, "r", encoding="utf-8", errors="replace").read()
    orig_txt = txt
    if "GCLIENT_SNPRINTF_FIX" in txt:
        print(f"[skip] Already patched CCStdC.h: {path}")
        return
    txt = txt.replace(
        "#ifndef snprintf\n#define snprintf _snprintf\n#endif",
        "// GCLIENT_SNPRINTF_FIX\n#if !defined(snprintf) && (!defined(_MSC_VER) || _MSC_VER < 1900)\n#define snprintf _snprintf\n#endif",
        1,
    )
    txt = txt.replace(
        "#if !defined(isnan)\n    #define isnan   _isnan\n#endif",
        "#if !defined(isnan) && (!defined(_MSC_VER) || _MSC_VER < 1900)\n    #define isnan   _isnan\n#endif",
        1,
    )
    if txt == orig_txt:
        print(f"[skip] Already patched CCStdC.h: {path}")
        return
    open(path, "w", encoding="utf-8", newline="\n").write(txt)
    print(f"[ok] Patched CCStdC.h: {path}")


def patch_chipmunk(path: str) -> None:
    if not os.path.exists(path):
        return
    txt = open(path, "r", encoding="utf-8", errors="replace").read()
    old = 'XSTR(CP_VERSION_MAJOR)"."XSTR(CP_VERSION_MINOR)"."XSTR(CP_VERSION_RELEASE)'
    new = 'XSTR(CP_VERSION_MAJOR) "." XSTR(CP_VERSION_MINOR) "." XSTR(CP_VERSION_RELEASE)'
    if old in txt:
        txt = txt.replace(old, new, 1)
        open(path, "w", encoding="utf-8", newline="\n").write(txt)
        print(f"[ok] Patched chipmunk.c: {path}")
    else:
        print(f"[skip] Already patched chipmunk.c: {path}")


def patch_image_common_and_legacy_dlls(cocos_root: str) -> None:
    img_h = os.path.join(cocos_root, "cocos2dx", "platform", "CCImageCommon_cpp.h")
    if os.path.exists(img_h):
        txt = open(img_h, "r", encoding="utf-8", errors="replace").read()
        orig_txt = txt

        if "GCLIENT_NO_TIFF" not in txt:
            txt = txt.replace('#include "tiffio.h"', '// GCLIENT_NO_TIFF\n// #include "tiffio.h"', 1)
            start = txt.find("static tmsize_t _tiffReadProc")
            end = txt.find("bool CCImage::_initWithRawData")
            if start != -1 and end != -1:
                stub = (
                    "bool CCImage::_initWithTiffData(void* pData, int nDataLen)\n{\n"
                    "    CC_UNUSED_PARAM(pData);\n"
                    "    CC_UNUSED_PARAM(nDataLen);\n"
                    "    return false;\n}\n\n"
                )
                txt = txt[:start] + stub + txt[end:]

        if IMAGE_GUARD_MARKER not in txt:
            # 1. Fix _initWithJpgData JCS_RGB `else { break; }` bug so direct RGB JPEGs decode cleanly,
            #    while unsupported color spaces (e.g. CMYK) destroy decompress state and break safely.
            jpg_bug_re = re.compile(
                r"if\s*\(\s*cinfo\.jpeg_color_space\s*!=\s*JCS_RGB\s*\)\s*\{\s*"
                r"if\s*\(\s*cinfo\.jpeg_color_space\s*==\s*JCS_GRAYSCALE\s*\|\|\s*"
                r"cinfo\.jpeg_color_space\s*==\s*JCS_YCbCr\s*\)\s*\{\s*"
                r"cinfo\.out_color_space\s*=\s*JCS_RGB\s*;\s*\}\s*\}\s*else\s*\{\s*break\s*;\s*\}",
                re.DOTALL,
            )
            jpg_fix = (
                f"// {IMAGE_GUARD_MARKER}\n"
                "        if (cinfo.jpeg_color_space == JCS_RGB || "
                "cinfo.jpeg_color_space == JCS_GRAYSCALE || "
                "cinfo.jpeg_color_space == JCS_YCbCr)\n"
                "        {\n"
                "            cinfo.out_color_space = JCS_RGB;\n"
                "        }\n"
                "        else\n"
                "        {\n"
                "            jpeg_destroy_decompress(&cinfo);\n"
                "            break;\n"
                "        }"
            )
            txt = jpg_bug_re.sub(jpg_fix, txt, count=1)

            # 2. Pad all `m_pData = new unsigned char[size + 4]` allocations by +4 zeroed tail bytes so
            #    Win32 OpenGL ICD 32-bit GL_RGB uploads never fault across a 4KB page boundary.
            alloc_re = re.compile(
                r"([ \t]*)m_pData\s*=\s*new\s+unsigned\s+char\s*\[\s*([^\]]+?)\s*\]\s*;"
            )

            def _pad_img_alloc(m_a: re.Match) -> str:
                indent = m_a.group(1)
                expr = m_a.group(2).strip()
                if "+ 4" in expr or "+4" in expr:
                    return m_a.group(0)
                return (
                    f"{indent}{{ // {IMAGE_GUARD_MARKER}\n"
                    f"{indent}    size_t _gclientImgBytes = (size_t)({expr});\n"
                    f"{indent}    m_pData = new unsigned char[_gclientImgBytes + 4];\n"
                    f"{indent}    if (m_pData) {{ memset(m_pData + _gclientImgBytes, 0, 4); }}\n"
                    f"{indent}}}"
                )

            txt = alloc_re.sub(_pad_img_alloc, txt)

        if txt != orig_txt:
            open(img_h, "w", encoding="utf-8", newline="\n").write(txt)
            print(f"[ok] Patched CCImageCommon_cpp.h: {img_h}")
        else:
            print(f"[skip] Already patched CCImageCommon_cpp.h: {img_h}")

    webp_cpp = os.path.join(cocos_root, "cocos2dx", "platform", "CCImageCommonWebp.cpp")
    if os.path.exists(webp_cpp):
        txt = open(webp_cpp, "r", encoding="utf-8", errors="replace").read()
        if IMAGE_GUARD_MARKER not in txt and "m_pData = new unsigned char[" in txt:
            txt = re.sub(
                r"([ \t]*)m_pData\s*=\s*new\s+unsigned\s+char\s*\[\s*([^\]]+?)\s*\]\s*;",
                r"\1{ // " + IMAGE_GUARD_MARKER + r"\n"
                r"\1    size_t _gclientImgBytes = (size_t)(\2);\n"
                r"\1    m_pData = new unsigned char[_gclientImgBytes + 4];\n"
                r"\1    if (m_pData) { memset(m_pData + _gclientImgBytes, 0, 4); }\n"
                r"\1}",
                txt,
            )
            open(webp_cpp, "w", encoding="utf-8", newline="\n").write(txt)
            print(f"[ok] Patched CCImageCommonWebp.cpp: {webp_cpp}")

    c2d_proj = os.path.join(cocos_root, "cocos2dx", "proj.win32", "cocos2d.vcxproj")
    if os.path.exists(c2d_proj):
        txt = open(c2d_proj, "r", encoding="utf-8", errors="replace").read()
        if "libtiff.lib;" in txt:
            txt = txt.replace("libtiff.lib;", "")
            open(c2d_proj, "w", encoding="utf-8", newline="\n").write(txt)
            print(f"[ok] Removed libtiff.lib from {c2d_proj}")

    ws_cpp = os.path.join(cocos_root, "extensions", "network", "Websocket.cpp")
    if os.path.exists(ws_cpp):
        txt = open(ws_cpp, "r", encoding="utf-8", errors="replace").read()
        if "GCLIENT_NO_WEBSOCKET_V3" not in txt:
            stub = (
                '// GCLIENT_NO_WEBSOCKET_V3: stubbed to avoid MSVCR100.dll-bound websockets.dll\n'
                '#include "Websocket.h"\n'
                'NS_CC_EXT_BEGIN\n'
                'WebSocket::WebSocket() : _readyState(kStateClosed), _port(80), _delegate(NULL) {}\n'
                'WebSocket::~WebSocket() {}\n'
                'bool WebSocket::init(const Delegate&, const std::string&, const std::vector<std::string>*) { return false; }\n'
                'void WebSocket::send(const std::string&) {}\n'
                'void WebSocket::send(const unsigned char*, unsigned int) {}\n'
                'void WebSocket::close() { _readyState = kStateClosed; }\n'
                'WebSocket::State WebSocket::getReadyState() { return _readyState; }\n'
                'void WebSocket::onSubThreadStarted() {}\n'
                'int WebSocket::onSubThreadLoop() { return 0; }\n'
                'void WebSocket::onSubThreadEnded() {}\n'
                'void WebSocket::onUIThreadReceiveMessage(WsMessage*) {}\n'
                'NS_CC_EXT_END\n'
            )
            open(ws_cpp, "w", encoding="utf-8", newline="\n").write(stub)
            print(f"[ok] Stubbed WebSocket in {ws_cpp}")

    ext_proj = os.path.join(cocos_root, "extensions", "proj.win32", "libExtensions.vcxproj")
    if os.path.exists(ext_proj):
        txt = open(ext_proj, "r", encoding="utf-8", errors="replace").read()
        if "websockets.lib;" in txt:
            txt = txt.replace("websockets.lib;", "")
            open(ext_proj, "w", encoding="utf-8", newline="\n").write(txt)
            print(f"[ok] Removed websockets.lib from {ext_proj}")


def patch_lua_loader(cocos_root: str) -> None:
    loader_cpp = os.path.join(cocos_root, "scripting", "lua", "cocos2dx_support", "Cocos2dxLuaLoader.cpp")
    if not os.path.exists(loader_cpp):
        return
    txt = open(loader_cpp, "r", encoding="utf-8", errors="replace").read()
    orig_txt = txt
    if "GCLIENT_LUA_LOADER_FIX_V2" in txt:
        print(f"[skip] Already patched Cocos2dxLuaLoader.cpp: {loader_cpp}")
        return
    txt = txt.replace(
        "std::string prefix = searchpath.substr(begin, next);",
        "// GCLIENT_LUA_LOADER_FIX\n            std::string prefix = searchpath.substr(begin, next - begin);",
        1,
    )
    txt = txt.replace(
        "if (prefix[0] == '.' && prefix[1] == '/')",
        "if (prefix.size() >= 2 && prefix[0] == '.' && (prefix[1] == '/' || prefix[1] == '\\\\'))",
        1,
    )
    direct_lookup = (
        "        // GCLIENT_LUA_LOADER_FIX_V2: resolve via CCFileUtils search paths first\n"
        "        unsigned char* chunk = NULL;\n"
        "        unsigned long chunkSize = 0;\n"
        "        std::string chunkName = \"\";\n"
        "        CCFileUtils* utils = CCFileUtils::sharedFileUtils();\n"
        "        {\n"
        "            std::string relLua = filename + NOT_BYTECODE_FILE_EXT;\n"
        "            std::string fullLua = utils->fullPathForFilename(relLua.c_str());\n"
        "            if (utils->isFileExist(fullLua)) {\n"
        "                chunk = utils->getFileData(fullLua.c_str(), \"rb\", &chunkSize);\n"
        "                chunkName = fullLua;\n"
        "            }\n"
        "        }\n"
        "        if (NULL == chunk) {\n"
    )
    old_block = (
        "        //search file in package.path\n"
        "        unsigned char* chunk = NULL;\n"
        "        unsigned long chunkSize = 0;\n"
        "        std::string chunkName = \"\";\n"
        "        CCFileUtils* utils = CCFileUtils::sharedFileUtils();"
    )
    if old_block in txt:
        txt = txt.replace(old_block, direct_lookup, 1)
        txt = txt.replace(
            "        if (NULL != chunk)",
            "        }\n        if (NULL != chunk)",
            1,
        )
    if txt == orig_txt:
        print(f"[skip] Already patched Cocos2dxLuaLoader.cpp: {loader_cpp}")
        return
    open(loader_cpp, "w", encoding="utf-8", newline="\n").write(txt)
    print(f"[ok] Patched Cocos2dxLuaLoader.cpp: {loader_cpp}")


def _replace_once_if_needed(path: str, replacements: list[tuple[str, str]]) -> None:
    if not os.path.exists(path):
        return
    txt = open(path, "r", encoding="utf-8", errors="replace").read()
    changed = False
    for old, new in replacements:
        if new in txt:
            continue
        if old in txt:
            txt = txt.replace(old, new, 1)
            changed = True
    if changed:
        open(path, "w", encoding="utf-8", newline="\n").write(txt)
        print(f"[ok] Patched: {path}")
    else:
        print(f"[skip] Already patched: {path}")


def patch_clipping_node(cocos_root: str) -> None:
    clip_cpp = os.path.join(cocos_root, "cocos2dx", "misc_nodes", "CCClippingNode.cpp")
    if not os.path.exists(clip_cpp):
        return
    txt = open(clip_cpp, "r", encoding="utf-8", errors="replace").read()
    if CLIPPING_MARKER in txt:
        print(f"[skip] Already patched CCClippingNode.cpp: {clip_cpp}")
        return
    orig_txt = txt

    for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "setProgram")):
        params = _split_top_level_params(txt[p_open + 1:p_close - 1])
        n_var = _extract_param_ident(params[0], "n") if params else "n"
        body = txt[b_start:b_end]
        patched_body = _inject_after_open_brace(body, f"if (!{n_var}) return; // {CLIPPING_MARKER}")
        txt = txt[:b_start] + patched_body + txt[b_end:]

    stencil_methods = (
        ("CCClippingNode::onEnter", "onEnter"),
        ("CCClippingNode::onEnterTransitionDidFinish", "onEnterTransitionDidFinish"),
        ("CCClippingNode::onExitTransitionDidStart", "onExitTransitionDidStart"),
        ("CCClippingNode::onExit", "onExit"),
    )
    for q_name, call_name in stencil_methods:
        for b_start, b_end in reversed(_find_method_body_spans(txt, q_name)):
            body = txt[b_start:b_end]
            body = re.sub(
                r"(?<![A-Za-z0-9_])m_pStencil\s*->\s*" + re.escape(call_name) + r"\s*\(\s*\)\s*;",
                f"if (m_pStencil) {{ m_pStencil->{call_name}(); }} /* {CLIPPING_MARKER} */",
                body,
            )
            txt = txt[:b_start] + body + txt[b_end:]

    if txt != orig_txt:
        open(clip_cpp, "w", encoding="utf-8", newline="\n").write(txt)
        print(f"[ok] Patched CCClippingNode.cpp: {clip_cpp}")
    else:
        print(f"[skip] Already patched CCClippingNode.cpp: {clip_cpp}")


def patch_gui_widget_and_touchgroup(cocos_root: str) -> None:
    # 1. UIWidget.cpp: route non-Widget CCNode* children in Widget::addChild to this->addNode(...)
    widget_cpp = os.path.join(cocos_root, "extensions", "CocoStudio", "GUI", "BaseClasses", "UIWidget.cpp")
    if os.path.exists(widget_cpp):
        txt = open(widget_cpp, "r", encoding="utf-8", errors="replace").read()
        orig_txt = txt
        if UIWIDGET_ADDCHILD_MARKER not in txt:
            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "Widget::addChild")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                c_var = _extract_param_ident(params[0], "child") if len(params) >= 1 else "child"
                if len(params) == 1:
                    new_body = (
                        "{\n"
                        f"    // {UIWIDGET_ADDCHILD_MARKER}\n"
                        f"    if (!{c_var}) return;\n"
                        f"    if (dynamic_cast<Widget*>({c_var}) == NULL)\n"
                        "    {\n"
                        f"        this->addNode({c_var}, {c_var}->getZOrder(), {c_var}->getTag());\n"
                        "        return;\n"
                        "    }\n"
                        f"    CCNode::addChild({c_var});\n"
                        "}"
                    )
                elif len(params) == 2:
                    z_var = _extract_param_ident(params[1], "zOrder")
                    new_body = (
                        "{\n"
                        f"    // {UIWIDGET_ADDCHILD_MARKER}\n"
                        f"    if (!{c_var}) return;\n"
                        f"    if (dynamic_cast<Widget*>({c_var}) == NULL)\n"
                        "    {\n"
                        f"        this->addNode({c_var}, {z_var}, {c_var}->getTag());\n"
                        "        return;\n"
                        "    }\n"
                        f"    CCNode::addChild({c_var}, {z_var});\n"
                        "}"
                    )
                else:
                    z_var = _extract_param_ident(params[1], "zOrder") if len(params) >= 2 else "zOrder"
                    t_var = _extract_param_ident(params[2], "tag") if len(params) >= 3 else "tag"
                    new_body = (
                        "{\n"
                        f"    // {UIWIDGET_ADDCHILD_MARKER}\n"
                        f"    if (!{c_var}) return;\n"
                        f"    if (dynamic_cast<Widget*>({c_var}) == NULL)\n"
                        "    {\n"
                        f"        this->addNode({c_var}, {z_var}, {t_var});\n"
                        "        return;\n"
                        "    }\n"
                        f"    CCNode::addChild({c_var}, {z_var}, {t_var});\n"
                        f"    if (_widgetChildren) {{ _widgetChildren->addObject({c_var}); }}\n"
                        "}"
                    )
                txt = txt[:b_start] + new_body + txt[b_end:]

            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "Widget::addNode")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                n_var = _extract_param_ident(params[0], "node") if len(params) >= 1 else "node"
                body = txt[b_start:b_end]
                if len(params) == 3:
                    z_var = _extract_param_ident(params[1], "zOrder")
                    t_var = _extract_param_ident(params[2], "tag")
                    new_body = (
                        "{\n"
                        f"    // {UIWIDGET_ADDCHILD_MARKER}\n"
                        f"    if (!{n_var}) return;\n"
                        f"    if (dynamic_cast<Widget*>({n_var}) != NULL)\n"
                        "    {\n"
                        f"        this->addChild({n_var}, {z_var}, {t_var});\n"
                        "        return;\n"
                        "    }\n"
                        f"    CCNode::addChild({n_var}, {z_var}, {t_var});\n"
                        f"    if (_nodes) {{ _nodes->addObject({n_var}); }}\n"
                        "}"
                    )
                    txt = txt[:b_start] + new_body + txt[b_end:]
                else:
                    patched = _inject_after_open_brace(body, f"if (!{n_var}) return; // {UIWIDGET_ADDCHILD_MARKER}")
                    txt = txt[:b_start] + patched + txt[b_end:]

            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "Widget::removeChild")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                if len(params) == 2:
                    c_var = _extract_param_ident(params[0], "child")
                    cl_var = _extract_param_ident(params[1], "cleanup")
                    new_rm = (
                        "{\n"
                        f"    // {UIWIDGET_ADDCHILD_MARKER}\n"
                        f"    if (!{c_var}) return;\n"
                        f"    CCNode::removeChild({c_var}, {cl_var});\n"
                        f"    if (_widgetChildren) {{ _widgetChildren->removeObject({c_var}); }}\n"
                        f"    if (_nodes) {{ _nodes->removeObject({c_var}); }}\n"
                        "}"
                    )
                    txt = txt[:b_start] + new_rm + txt[b_end:]

            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "Widget::getChildByTag")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                t_var = _extract_param_ident(params[0], "aTag") if params else "aTag"
                body = txt[b_start:b_end]
                body = re.sub(
                    r"return\s+NULL\s*;\s*\}$",
                    f"return this->getNodeByTag({t_var}); /* {UIWIDGET_ADDCHILD_MARKER} */\n}}",
                    body,
                )
                txt = txt[:b_start] + body + txt[b_end:]

        if txt != orig_txt:
            open(widget_cpp, "w", encoding="utf-8", newline="\n").write(txt)
            print(f"[ok] Patched UIWidget.cpp addChild/addNode guards: {widget_cpp}")
        else:
            print(f"[skip] Already patched UIWidget.cpp addChild/addNode guards: {widget_cpp}")

    # 2. UITouchGroup.cpp: invisible check + null/data check + dynamic_cast<Widget*> + std::vector retain snapshot UAF fix
    tg_cpp = os.path.join(cocos_root, "extensions", "CocoStudio", "GUI", "System", "UITouchGroup.cpp")
    if os.path.exists(tg_cpp):
        txt = open(tg_cpp, "r", encoding="utf-8", errors="replace").read()
        orig_txt = txt
        if UITOUCHGROUP_MARKER not in txt:
            if "#include <vector>" not in txt:
                txt = txt.replace('#include "UITouchGroup.h"', f'#include <vector> // {UITOUCHGROUP_MARKER}\n#include "UITouchGroup.h"', 1)
                if "#include <vector>" not in txt:
                    txt = f"#include <vector> // {UITOUCHGROUP_MARKER}\n" + txt

            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "TouchGroup::checkTouchEvent")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                r_var = _extract_param_ident(params[0], "root") if len(params) >= 1 else "root"
                t_var = _extract_param_ident(params[1], "touch") if len(params) >= 2 else "touch"
                e_var = _extract_param_ident(params[2], "pEvent") if len(params) >= 3 else "pEvent"
                new_cte = (
                    "{\n"
                    f"    // {UITOUCHGROUP_MARKER}\n"
                    f"    if (!{r_var} || !{r_var}->isVisible()) return false;\n"
                    f"    if ({r_var}->getChildren() && {r_var}->getChildren()->data)\n"
                    "    {\n"
                    f"        ccArray* arrayRootChildren = {r_var}->getChildren()->data;\n"
                    "        int length = arrayRootChildren->num;\n"
                    "        for (int i = length - 1; i >= 0; i--)\n"
                    "        {\n"
                    "            Widget* widget = dynamic_cast<Widget*>(static_cast<CCObject*>(arrayRootChildren->arr[i]));\n"
                    f"            if (widget && checkTouchEvent(widget, {t_var}, {e_var}))\n"
                    "            {\n"
                    "                return true;\n"
                    "            }\n"
                    "        }\n"
                    "    }\n"
                    f"    bool pass = {r_var}->onTouchBegan({t_var}, {e_var});\n"
                    f"    if ({r_var}->_hitted)\n"
                    "    {\n"
                    f"        if (m_pSelectedWidgets) {{ m_pSelectedWidgets->addObject({r_var}); }}\n"
                    "        return true;\n"
                    "    }\n"
                    "    return pass;\n"
                    "}"
                )
                txt = txt[:b_start] + new_cte + txt[b_end:]

            for b_start, b_end in reversed(_find_method_body_spans(txt, "TouchGroup::~TouchGroup")):
                new_dtor = (
                    "{\n"
                    f"    // {UITOUCHGROUP_MARKER}\n"
                    "    if (m_pSelectedWidgets) { m_pSelectedWidgets->removeAllObjects(); m_pSelectedWidgets->release(); m_pSelectedWidgets = NULL; }\n"
                    "    if (m_pRootWidget) { m_pRootWidget->release(); m_pRootWidget = NULL; }\n"
                    "}"
                )
                txt = txt[:b_start] + new_dtor + txt[b_end:]

            txt = _prepend_to_method_body(txt, "TouchGroup::addWidget", "if (!widget || !m_pRootWidget) return;", UITOUCHGROUP_MARKER)
            txt = _prepend_to_method_body(txt, "TouchGroup::removeWidget", "if (!widget || !m_pRootWidget) return;", UITOUCHGROUP_MARKER)
            txt = _prepend_to_method_body(txt, "TouchGroup::clear", "if (!m_pRootWidget) return;", UITOUCHGROUP_MARKER)
            txt = _prepend_to_method_body(txt, "TouchGroup::checkEventWidget", "if (!m_pSelectedWidgets || !m_pRootWidget) return false;", UITOUCHGROUP_MARKER)

            for touch_fn, cb_name, clear_sel in (
                ("TouchGroup::ccTouchMoved", "onTouchMoved", False),
                ("TouchGroup::ccTouchEnded", "onTouchEnded", True),
                ("TouchGroup::ccTouchCancelled", "onTouchCancelled", True),
            ):
                for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, touch_fn)):
                    params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                    pt_var = _extract_param_ident(params[0], "pTouch") if len(params) >= 1 else "pTouch"
                    pe_var = _extract_param_ident(params[1], "pEvent") if len(params) >= 2 else "pEvent"
                    clear_line = "    m_pSelectedWidgets->removeAllObjects();\n" if clear_sel else ""
                    new_th = (
                        "{\n"
                        f"    // {UITOUCHGROUP_MARKER}\n"
                        "    if (!m_pSelectedWidgets || !m_pSelectedWidgets->data || m_pSelectedWidgets->data->num <= 0) return;\n"
                        "    this->retain();\n"
                        "    ccArray* selectedWidgetArray = m_pSelectedWidgets->data;\n"
                        "    int length = selectedWidgetArray->num;\n"
                        "    std::vector<Widget*> snapshot;\n"
                        "    snapshot.reserve(length);\n"
                        "    for (int i = 0; i < length; ++i)\n"
                        "    {\n"
                        "        Widget* w = dynamic_cast<Widget*>(static_cast<CCObject*>(selectedWidgetArray->arr[i]));\n"
                        "        if (w) { w->retain(); snapshot.push_back(w); }\n"
                        "    }\n"
                        f"{clear_line}"
                        f"    for (size_t i = 0; i < snapshot.size(); ++i) snapshot[i]->{cb_name}({pt_var}, {pe_var});\n"
                        "    for (size_t i = 0; i < snapshot.size(); ++i) snapshot[i]->release();\n"
                        "    this->release();\n"
                        "}"
                    )
                    txt = txt[:b_start] + new_th + txt[b_end:]

        if txt != orig_txt:
            open(tg_cpp, "w", encoding="utf-8", newline="\n").write(txt)
            print(f"[ok] Patched UITouchGroup.cpp: {tg_cpp}")
        else:
            print(f"[skip] Already patched UITouchGroup.cpp: {tg_cpp}")

    # 3. UIHelper.cpp: null/children->data checks & dynamic_cast<Widget*> across seekWidget* helpers
    helper_cpp = os.path.join(cocos_root, "extensions", "CocoStudio", "GUI", "System", "UIHelper.cpp")
    if os.path.exists(helper_cpp):
        txt = open(helper_cpp, "r", encoding="utf-8", errors="replace").read()
        orig_txt = txt
        if UIHELPER_MARKER not in txt:
            txt = txt.replace(
                "ccArray* arrayRootChildren = root->getChildren()->data;",
                f"if (!root->getChildren() || !root->getChildren()->data) return NULL; /* {UIHELPER_MARKER} */\n"
                "    ccArray* arrayRootChildren = root->getChildren()->data;",
            )
            txt = txt.replace(
                "Widget* child = static_cast<Widget*>(arrayRootChildren->arr[i]);",
                "Widget* child = dynamic_cast<Widget*>(static_cast<CCObject*>(arrayRootChildren->arr[i]));\n"
                "        if (!child) continue;",
            )
            txt = txt.replace(
                "if (strcmp(root->getName(), name) == 0)",
                "if (!name) return NULL;\n    if (root->getName() && strcmp(root->getName(), name) == 0)",
            )
            txt = txt.replace(
                "if (layoutParameter && strcmp(layoutParameter->getRelativeName(), name) == 0)",
                "if (name && layoutParameter && layoutParameter->getRelativeName() && strcmp(layoutParameter->getRelativeName(), name) == 0)",
            )
        if txt != orig_txt:
            open(helper_cpp, "w", encoding="utf-8", newline="\n").write(txt)
            print(f"[ok] Patched UIHelper.cpp: {helper_cpp}")
        else:
            print(f"[skip] Already patched UIHelper.cpp: {helper_cpp}")


def patch_spine_atlas_and_cocos2dx(cocos_root: str) -> None:
    spine_dir = os.path.join(cocos_root, "extensions", "spine")

    # 1. Atlas.cpp: parse Spine 3.2 `size: W, H` tuple into page->width / page->height so UVs never NaN/Inf
    atlas_cpp = os.path.join(spine_dir, "Atlas.cpp")
    if os.path.exists(atlas_cpp):
        txt = open(atlas_cpp, "r", encoding="utf-8", errors="replace").read()
        orig_txt = txt
        if ATLAS_SIZE_MARKER not in txt:
            legacy_size_block = (
                "if (readTuple(end, tuple) == 2) {\n"
                "\t\t\t\tif (!readValue(end, &str)) return abortAtlas(self);\n"
                "\t\t\t} else {\n"
                "\t\t\t\tstr = tuple[0];\n"
                "\t\t\t}"
            )
            size_parse_block = (
                "/* " + ATLAS_SIZE_MARKER + " */\n"
                "\t\t\tint gclientSizeW = 0, gclientSizeH = 0;\n"
                "\t\t\t{\n"
                "\t\t\t\tconst char* gclientSavedBegin = begin;\n"
                "\t\t\t\tif (readTuple(end, tuple) == 2) {\n"
                "\t\t\t\t\tgclientSizeW = atoi(tuple[0].begin);\n"
                "\t\t\t\t\tgclientSizeH = atoi(tuple[1].begin);\n"
                "\t\t\t\t\tif (page->width == 0) {\n"
                "\t\t\t\t\t\tpage->width = gclientSizeW;\n"
                "\t\t\t\t\t\tpage->height = gclientSizeH;\n"
                "\t\t\t\t\t}\n"
                "\t\t\t\t} else {\n"
                "\t\t\t\t\tbegin = gclientSavedBegin;\n"
                "\t\t\t\t}\n"
                "\t\t\t}\n"
                "\t\t\tif (!readValue(end, &str)) return abortAtlas(self);"
            )
            if legacy_size_block in txt:
                txt = txt.replace(legacy_size_block, size_parse_block, 1)
            elif "if (!readValue(end, &str)) return abortAtlas(self);" in txt:
                txt = txt.replace(
                    "if (!readValue(end, &str)) return abortAtlas(self);",
                    size_parse_block,
                    1,
                )

            if "_AtlasPage_createTexture(page, path);" in txt:
                txt = txt.replace(
                    "_AtlasPage_createTexture(page, path);",
                    "_AtlasPage_createTexture(page, path);\n"
                    "\t\t\tif (page->width <= 0 && gclientSizeW > 0) page->width = gclientSizeW;\n"
                    "\t\t\tif (page->height <= 0 && gclientSizeH > 0) page->height = gclientSizeH;\n"
                    "\t\t\tif (page->width <= 0) page->width = 1;\n"
                    "\t\t\tif (page->height <= 0) page->height = 1;",
                    1,
                )

        if txt != orig_txt:
            open(atlas_cpp, "w", encoding="utf-8", newline="\n").write(txt)
            print(f"[ok] Patched Atlas.cpp: {atlas_cpp}")
        else:
            print(f"[skip] Already patched Atlas.cpp: {atlas_cpp}")

    # 2. spine-cocos2dx.cpp: multi-extension probing (.pvr.ccz, .pkm, .webp, .png), size population & binary null-term read
    sc_cpp = os.path.join(spine_dir, "spine-cocos2dx.cpp")
    if os.path.exists(sc_cpp):
        txt = open(sc_cpp, "r", encoding="utf-8", errors="replace").read()
        orig_txt = txt
        if SPINE_MULTIEXT_MARKER not in txt:
            if "<string>" not in txt:
                txt = _insert_before_ns_cc_begin(txt, "#include <string>\n#include <string.h>")

            ct_spans = _find_method_body_spans(txt, "_AtlasPage_createTexture")
            if ct_spans:
                b_start, b_end = ct_spans[-1]
                new_ct = (
                    "{\n"
                    f"\t// {SPINE_MULTIEXT_MARKER}\n"
                    "\tCCTexture2D* texture = path ? CCTextureCache::sharedTextureCache()->addImage(path) : 0;\n"
                    "\tif (!texture && path && path[0]) {\n"
                    "\t\tstd::string stem(path);\n"
                    "\t\tif (stem.size() > 8 && stem.compare(stem.size() - 8, 8, \".pvr.ccz\") == 0) {\n"
                    "\t\t\tstem.erase(stem.size() - 8);\n"
                    "\t\t} else {\n"
                    "\t\t\tsize_t slash = stem.find_last_of(\"/\\\\\");\n"
                    "\t\t\tsize_t dot = stem.find_last_of('.');\n"
                    "\t\t\tif (dot != std::string::npos && (slash == std::string::npos || dot > slash)) {\n"
                    "\t\t\t\tstem.erase(dot);\n"
                    "\t\t\t}\n"
                    "\t\t}\n"
                    "\t\tstatic const char* const kAtlasExts[] = { \".pvr.ccz\", \".pkm\", \".webp\", \".png\" };\n"
                    "\t\tfor (int i = 0; i < 4 && !texture; ++i) {\n"
                    "\t\t\tstd::string cand = stem + kAtlasExts[i];\n"
                    "\t\t\ttexture = CCTextureCache::sharedTextureCache()->addImage(cand.c_str());\n"
                    "\t\t}\n"
                    "\t}\n"
                    "\tif (!texture) {\n"
                    "\t\tself->rendererObject = 0;\n"
                    "\t\treturn;\n"
                    "\t}\n"
                    "\tCCTextureAtlas* textureAtlas = CCTextureAtlas::createWithTexture(texture, 4);\n"
                    "\ttextureAtlas->retain();\n"
                    "\tself->rendererObject = textureAtlas;\n"
                    "\tself->width = texture->getPixelsWide();\n"
                    "\tself->height = texture->getPixelsHigh();\n"
                    "}"
                )
                txt = txt[:b_start] + new_ct + txt[b_end:]

            dt_spans = _find_method_body_spans(txt, "_AtlasPage_disposeTexture")
            if dt_spans:
                b_start, b_end = dt_spans[-1]
                new_dt = (
                    "{\n"
                    "\tif (self->rendererObject) {\n"
                    "\t\t((CCTextureAtlas*)self->rendererObject)->release();\n"
                    "\t\tself->rendererObject = 0;\n"
                    "\t}\n"
                    "}"
                )
                txt = txt[:b_start] + new_dt + txt[b_end:]

            rf_spans = _find_method_body_spans(txt, "_Util_readFile")
            if rf_spans:
                b_start, b_end = rf_spans[-1]
                new_rf = (
                    "{\n"
                    "\tunsigned long size = 0;\n"
                    "\tstd::string fullPath = CCFileUtils::sharedFileUtils()->fullPathForFilename(path);\n"
                    "\tunsigned char* raw = CCFileUtils::sharedFileUtils()->getFileData(fullPath.c_str(), \"rb\", &size);\n"
                    "\tif (!raw) {\n"
                    "\t\tif (length) *length = 0;\n"
                    "\t\treturn 0;\n"
                    "\t}\n"
                    "\tchar* data = MALLOC(char, size + 1);\n"
                    "\tif (size > 0) memcpy(data, raw, size);\n"
                    "\tdata[size] = '\\0';\n"
                    "\tdelete[] raw;\n"
                    "\tif (length) *length = (int)size;\n"
                    "\treturn data;\n"
                    "}"
                )
                txt = txt[:b_start] + new_rf + txt[b_end:]

        if txt != orig_txt:
            open(sc_cpp, "w", encoding="utf-8", newline="\n").write(txt)
            print(f"[ok] Patched spine-cocos2dx.cpp: {sc_cpp}")
        else:
            print(f"[skip] Already patched spine-cocos2dx.cpp: {sc_cpp}")


def patch_spine_and_gui(cocos_root: str) -> None:
    _replace_once_if_needed(
        os.path.join(cocos_root, "extensions", "CocoStudio", "Armature", "display", "CCDisplayManager.cpp"),
        [(
            "    CCDecorativeDisplay *decoDisplay = (CCDecorativeDisplay *)m_pDecoDisplayList->objectAtIndex(m_iDisplayIndex);",
            "    if (!m_pDecoDisplayList || m_iDisplayIndex < 0 || m_iDisplayIndex >= (int)m_pDecoDisplayList->count())\n"
            "    {\n"
            "        setCurrentDecorativeDisplay(NULL);\n"
            "        return;\n"
            "    }\n\n"
            "    CCDecorativeDisplay *decoDisplay = (CCDecorativeDisplay *)m_pDecoDisplayList->objectAtIndex(m_iDisplayIndex);",
        )],
    )
    _replace_once_if_needed(
        os.path.join(cocos_root, "extensions", "CocoStudio", "GUI", "BaseClasses", "UIWidget.cpp"),
        [
            (
                "    Widget* clonedWidget = createCloneInstance();\n    clonedWidget->copyProperties(this);",
                "    Widget* clonedWidget = createCloneInstance();\n"
                "    if (!clonedWidget)\n    {\n        return NULL;\n    }\n"
                "    clonedWidget->copyProperties(this);",
            ),
            (
                "void Widget::copyClonedWidgetChildren(Widget* model)\n{\n"
                "    ccArray* arrayChildren = model->getChildren()->data;\n"
                "    int length = arrayChildren->num;\n"
                "    for (int i=0; i<length; i++)\n    {\n"
                "        Widget* child = static_cast<Widget*>(arrayChildren->arr[i]);\n"
                "        addChild(child->clone());\n    }\n}",
                "void Widget::copyClonedWidgetChildren(Widget* model)\n{\n"
                "    if (!model || !model->getChildren() || !model->getChildren()->data)\n    {\n        return;\n    }\n"
                "    ccArray* arrayChildren = model->getChildren()->data;\n"
                "    int length = arrayChildren->num;\n"
                "    for (int i=0; i<length; i++)\n    {\n"
                "        Widget* child = dynamic_cast<Widget*>(static_cast<CCObject*>(arrayChildren->arr[i]));\n"
                "        if (child)\n        {\n"
                "            Widget* clonedChild = child->clone();\n"
                "            if (clonedChild)\n            {\n                addChild(clonedChild);\n            }\n"
                "        }\n    }\n}",
            ),
        ],
    )
    patch_gui_widget_and_touchgroup(cocos_root)
    patch_spine_atlas_and_cocos2dx(cocos_root)
    # Use distinct comments so 4-tab `continue;` is never skipped as a substring of 5-tab `continue;`!
    _replace_once_if_needed(
        os.path.join(cocos_root, "extensions", "spine", "SkeletonJson.cpp"),
        [
            (
                "\t\t\t\t\tAnimation_dispose(animation);\n"
                "\t\t\t\t\t_SkeletonJson_setError(self, 0, \"Invalid timeline type for a bone: \", timelineType);\n"
                "\t\t\t\t\treturn 0;",
                "\t\t\t\t\tcontinue; /* skip_unknown_bone_timeline */",
            ),
            (
                "\t\t\t\tAnimation_dispose(animation);\n"
                "\t\t\t\t_SkeletonJson_setError(self, 0, \"Invalid timeline type for a slot: \", timelineType);\n"
                "\t\t\t\treturn 0;",
                "\t\t\t\tcontinue; /* skip_unknown_slot_timeline */",
            ),
            (
                "\t\t\t\t\t\tSkeletonData_dispose(skeletonData);\n"
                "\t\t\t\t\t\t_SkeletonJson_setError(self, root, \"Unknown attachment type: \", typeString);\n"
                "\t\t\t\t\t\treturn 0;",
                "\t\t\t\t\t\tcontinue; /* skip_unknown_attachment_type */",
            ),
        ],
    )


def patch_spine_2x_mesh_and_ffd(cocos_root: str) -> None:
    spine_dir = os.path.join(cocos_root, "extensions", "spine")
    _replace_once_if_needed(
        os.path.join(spine_dir, "Slot.h"),
        [(
            "\tAttachment* const attachment;\n} Slot;",
            "\tAttachment* const attachment;\n"
            "\tfloat* attachmentVertices;\n"
            "\tint attachmentVerticesCount;\n"
            "\tint attachmentVerticesCapacity;\n} Slot;",
        )],
    )
    _replace_once_if_needed(
        os.path.join(spine_dir, "Slot.cpp"),
        [
            (
                "void Slot_dispose (Slot* self) {\n\tFREE(self);\n}",
                "void Slot_dispose (Slot* self) {\n\tFREE(self->attachmentVertices);\n\tFREE(self);\n}",
            ),
            (
                "void Slot_setAttachment (Slot* self, Attachment* attachment) {\n"
                "\tCONST_CAST(Attachment*, self->attachment) = attachment;\n"
                "\tSUB_CAST(_Internal, self) ->attachmentTime = self->skeleton->time;\n}",
                "void Slot_setAttachment (Slot* self, Attachment* attachment) {\n"
                "\tCONST_CAST(Attachment*, self->attachment) = attachment;\n"
                "\tSUB_CAST(_Internal, self) ->attachmentTime = self->skeleton->time;\n"
                "\tself->attachmentVerticesCount = 0;\n}",
            ),
        ],
    )
    _replace_once_if_needed(
        os.path.join(spine_dir, "Attachment.h"),
        [(
            "typedef enum {\n\tATTACHMENT_REGION, ATTACHMENT_REGION_SEQUENCE\n} AttachmentType;",
            "typedef enum {\n\tATTACHMENT_REGION, ATTACHMENT_REGION_SEQUENCE, ATTACHMENT_MESH, ATTACHMENT_SKINNED_MESH\n} AttachmentType;",
        ),
        (
            "CC_EX_DLL void Attachment_dispose (Attachment* self);",
            "CC_EX_DLL void Attachment_dispose (Attachment* self);\n\n"
            "typedef struct MeshAttachment {\n"
            "\tAttachment super;\n"
            "\tvoid* rendererObject;\n"
            "\tfloat regionU, regionV, regionU2, regionV2;\n"
            "\tint /*bool*/ regionRotate;\n"
            "\tfloat regionOffsetX, regionOffsetY;\n"
            "\tfloat regionWidth, regionHeight;\n"
            "\tfloat regionOriginalWidth, regionOriginalHeight;\n"
            "\tfloat r, g, b, a;\n"
            "\tfloat* vertices;\n"
            "\tint verticesCount;\n"
            "\tfloat* regionUVs;\n"
            "\tfloat* uvs;\n"
            "\tint* triangles;\n"
            "\tint trianglesCount;\n"
            "\tint hullLength;\n"
            "\tfloat width, height;\n"
            "} MeshAttachment;\n\n"
            "CC_EX_DLL MeshAttachment* MeshAttachment_create (const char* name);\n"
            "CC_EX_DLL void MeshAttachment_updateUVs (MeshAttachment* self);\n"
            "CC_EX_DLL void MeshAttachment_computeWorldVertices (MeshAttachment* self, Slot* slot, float* worldVertices);\n\n"
            "typedef struct SkinnedMeshAttachment {\n"
            "\tAttachment super;\n"
            "\tvoid* rendererObject;\n"
            "\tfloat regionU, regionV, regionU2, regionV2;\n"
            "\tint /*bool*/ regionRotate;\n"
            "\tfloat regionOffsetX, regionOffsetY;\n"
            "\tfloat regionWidth, regionHeight;\n"
            "\tfloat regionOriginalWidth, regionOriginalHeight;\n"
            "\tfloat r, g, b, a;\n"
            "\tint* bones;\n"
            "\tint bonesCount;\n"
            "\tfloat* weights;\n"
            "\tint weightsCount;\n"
            "\tfloat* regionUVs;\n"
            "\tfloat* uvs;\n"
            "\tint uvsCount;\n"
            "\tint* triangles;\n"
            "\tint trianglesCount;\n"
            "\tint hullLength;\n"
            "\tfloat width, height;\n"
            "} SkinnedMeshAttachment;\n\n"
            "CC_EX_DLL SkinnedMeshAttachment* SkinnedMeshAttachment_create (const char* name);\n"
            "CC_EX_DLL void SkinnedMeshAttachment_updateUVs (SkinnedMeshAttachment* self);\n"
            "CC_EX_DLL void SkinnedMeshAttachment_computeWorldVertices (SkinnedMeshAttachment* self, Slot* slot, float* worldVertices);",
        )],
    )
    _replace_once_if_needed(
        os.path.join(spine_dir, "Attachment.cpp"),
        [
            (
                "#include <spine/Slot.h>",
                "#include <spine/Slot.h>\n#include <spine/Skeleton.h>\n#include <spine/Bone.h>",
            ),
            (
                "void Attachment_dispose (Attachment* self) {\n\tVTABLE(Attachment, self) ->dispose(self);\n\tFREE(self);\n}",
                "void Attachment_dispose (Attachment* self) {\n\tVTABLE(Attachment, self) ->dispose(self);\n\tFREE(self);\n}\n\n"
                "void _MeshAttachment_dispose (Attachment* attachment) {\n"
                "\tMeshAttachment* self = SUB_CAST(MeshAttachment, attachment);\n"
                "\t_Attachment_deinit(attachment);\n"
                "\tFREE(self->vertices);\n\tFREE(self->regionUVs);\n\tFREE(self->uvs);\n\tFREE(self->triangles);\n}\n\n"
                "MeshAttachment* MeshAttachment_create (const char* name) {\n"
                "\tMeshAttachment* self = NEW(MeshAttachment);\n"
                "\t_Attachment_init(SUPER(self), name, ATTACHMENT_MESH, _MeshAttachment_dispose);\n"
                "\tself->r = 1;\n\tself->g = 1;\n\tself->b = 1;\n\tself->a = 1;\n\treturn self;\n}\n\n"
                "void MeshAttachment_updateUVs (MeshAttachment* self) {\n"
                "\tint i;\n\tfloat width = self->regionU2 - self->regionU;\n\tfloat height = self->regionV2 - self->regionV;\n"
                "\tFREE(self->uvs);\n\tself->uvs = MALLOC(float, self->verticesCount);\n"
                "\tif (self->regionRotate) {\n"
                "\t\tfor (i = 0; i < self->verticesCount; i += 2) {\n"
                "\t\t\tself->uvs[i] = self->regionU + self->regionUVs[i + 1] * width;\n"
                "\t\t\tself->uvs[i + 1] = self->regionV + height - self->regionUVs[i] * height;\n\t\t}\n"
                "\t} else {\n"
                "\t\tfor (i = 0; i < self->verticesCount; i += 2) {\n"
                "\t\t\tself->uvs[i] = self->regionU + self->regionUVs[i] * width;\n"
                "\t\t\tself->uvs[i + 1] = self->regionV + self->regionUVs[i + 1] * height;\n\t\t}\n\t}\n}\n\n"
                "void MeshAttachment_computeWorldVertices (MeshAttachment* self, Slot* slot, float* worldVertices) {\n"
                "\tSkeleton* skeleton = slot->skeleton;\n\tBone* bone = slot->bone;\n"
                "\tfloat x = skeleton->x + bone->worldX;\n\tfloat y = skeleton->y + bone->worldY;\n"
                "\tfloat m00 = bone->m00, m01 = bone->m01, m10 = bone->m10, m11 = bone->m11;\n"
                "\tfloat* vertices = self->vertices;\n\tint verticesCount = self->verticesCount;\n\tint i;\n"
                "\tif (slot->attachmentVerticesCount == verticesCount) vertices = slot->attachmentVertices;\n"
                "\tfor (i = 0; i < verticesCount; i += 2) {\n"
                "\t\tfloat vx = vertices[i];\n\t\tfloat vy = vertices[i + 1];\n"
                "\t\tworldVertices[i] = vx * m00 + vy * m01 + x;\n"
                "\t\tworldVertices[i + 1] = vx * m10 + vy * m11 + y;\n\t}\n}\n\n"
                "void _SkinnedMeshAttachment_dispose (Attachment* attachment) {\n"
                "\tSkinnedMeshAttachment* self = SUB_CAST(SkinnedMeshAttachment, attachment);\n"
                "\t_Attachment_deinit(attachment);\n"
                "\tFREE(self->bones);\n\tFREE(self->weights);\n\tFREE(self->regionUVs);\n\tFREE(self->uvs);\n\tFREE(self->triangles);\n}\n\n"
                "SkinnedMeshAttachment* SkinnedMeshAttachment_create (const char* name) {\n"
                "\tSkinnedMeshAttachment* self = NEW(SkinnedMeshAttachment);\n"
                "\t_Attachment_init(SUPER(self), name, ATTACHMENT_SKINNED_MESH, _SkinnedMeshAttachment_dispose);\n"
                "\tself->r = 1;\n\tself->g = 1;\n\tself->b = 1;\n\tself->a = 1;\n\treturn self;\n}\n\n"
                "void SkinnedMeshAttachment_updateUVs (SkinnedMeshAttachment* self) {\n"
                "\tint i;\n\tfloat width = self->regionU2 - self->regionU;\n\tfloat height = self->regionV2 - self->regionV;\n"
                "\tFREE(self->uvs);\n\tself->uvs = MALLOC(float, self->uvsCount);\n"
                "\tif (self->regionRotate) {\n"
                "\t\tfor (i = 0; i < self->uvsCount; i += 2) {\n"
                "\t\t\tself->uvs[i] = self->regionU + self->regionUVs[i + 1] * width;\n"
                "\t\t\tself->uvs[i + 1] = self->regionV + height - self->regionUVs[i] * height;\n\t\t}\n"
                "\t} else {\n"
                "\t\tfor (i = 0; i < self->uvsCount; i += 2) {\n"
                "\t\t\tself->uvs[i] = self->regionU + self->regionUVs[i] * width;\n"
                "\t\t\tself->uvs[i + 1] = self->regionV + self->regionUVs[i + 1] * height;\n\t\t}\n\t}\n}\n\n"
                "void SkinnedMeshAttachment_computeWorldVertices (SkinnedMeshAttachment* self, Slot* slot, float* worldVertices) {\n"
                "\tSkeleton* skeleton = slot->skeleton;\n\tBone** skeletonBones = skeleton->bones;\n"
                "\tfloat x = skeleton->x, y = skeleton->y;\n\tint w = 0, v = 0, b = 0, f = 0;\n"
                "\tif (slot->attachmentVerticesCount == 0) {\n"
                "\t\tfor (; v < self->bonesCount; w += 2) {\n"
                "\t\t\tfloat wx = 0, wy = 0;\n\t\t\tconst int bc = self->bones[v++];\n\t\t\tconst int nn = bc + v;\n"
                "\t\t\tfor (; v < nn; v++, b += 3) {\n"
                "\t\t\t\tBone* bone = skeletonBones[self->bones[v]];\n"
                "\t\t\t\tfloat vx = self->weights[b], vy = self->weights[b + 1], weight = self->weights[b + 2];\n"
                "\t\t\t\twx += (vx * bone->m00 + vy * bone->m01 + bone->worldX) * weight;\n"
                "\t\t\t\twy += (vx * bone->m10 + vy * bone->m11 + bone->worldY) * weight;\n\t\t\t}\n"
                "\t\t\tworldVertices[w] = wx + x;\n\t\t\tworldVertices[w + 1] = wy + y;\n\t\t}\n"
                "\t} else {\n"
                "\t\tconst float* ffd = slot->attachmentVertices;\n"
                "\t\tfor (; v < self->bonesCount; w += 2) {\n"
                "\t\t\tfloat wx = 0, wy = 0;\n\t\t\tconst int bc = self->bones[v++];\n\t\t\tconst int nn = bc + v;\n"
                "\t\t\tfor (; v < nn; v++, b += 3, f += 2) {\n"
                "\t\t\t\tBone* bone = skeletonBones[self->bones[v]];\n"
                "\t\t\t\tfloat vx = self->weights[b] + (f < slot->attachmentVerticesCount ? ffd[f] : 0.0f);\n"
                "\t\t\t\tfloat vy = self->weights[b + 1] + (f + 1 < slot->attachmentVerticesCount ? ffd[f + 1] : 0.0f);\n"
                "\t\t\t\tfloat weight = self->weights[b + 2];\n"
                "\t\t\t\twx += (vx * bone->m00 + vy * bone->m01 + bone->worldX) * weight;\n"
                "\t\t\t\twy += (vx * bone->m10 + vy * bone->m11 + bone->worldY) * weight;\n\t\t\t}\n"
                "\t\t\tworldVertices[w] = wx + x;\n\t\t\tworldVertices[w + 1] = wy + y;\n\t\t}\n\t}\n}",
            ),
        ],
    )
    _replace_once_if_needed(
        os.path.join(spine_dir, "AtlasAttachmentLoader.cpp"),
        [(
            "\t\tattachment->regionOriginalHeight = region->originalHeight;\n\t\treturn SUPER(attachment);\n\t}\n\tdefault:",
            "\t\tattachment->regionOriginalHeight = region->originalHeight;\n\t\treturn SUPER(attachment);\n\t}\n"
            "\tcase ATTACHMENT_MESH: {\n"
            "\t\tMeshAttachment* attachment;\n"
            "\t\tAtlasRegion* region = Atlas_findRegion(self->atlas, name);\n"
            "\t\tif (!region) {\n\t\t\t_AttachmentLoader_setError(loader, \"Region not found: \", name);\n\t\t\treturn 0;\n\t\t}\n"
            "\t\tattachment = MeshAttachment_create(name);\n"
            "\t\tattachment->rendererObject = region;\n"
            "\t\tattachment->regionU = region->u;\n\t\tattachment->regionV = region->v;\n"
            "\t\tattachment->regionU2 = region->u2;\n\t\tattachment->regionV2 = region->v2;\n"
            "\t\tattachment->regionRotate = region->rotate;\n"
            "\t\tattachment->regionOffsetX = region->offsetX;\n\t\tattachment->regionOffsetY = region->offsetY;\n"
            "\t\tattachment->regionWidth = region->width;\n\t\tattachment->regionHeight = region->height;\n"
            "\t\tattachment->regionOriginalWidth = region->originalWidth;\n\t\tattachment->regionOriginalHeight = region->originalHeight;\n"
            "\t\treturn SUPER(attachment);\n\t}\n"
            "\tcase ATTACHMENT_SKINNED_MESH: {\n"
            "\t\tSkinnedMeshAttachment* attachment;\n"
            "\t\tAtlasRegion* region = Atlas_findRegion(self->atlas, name);\n"
            "\t\tif (!region) {\n\t\t\t_AttachmentLoader_setError(loader, \"Region not found: \", name);\n\t\t\treturn 0;\n\t\t}\n"
            "\t\tattachment = SkinnedMeshAttachment_create(name);\n"
            "\t\tattachment->rendererObject = region;\n"
            "\t\tattachment->regionU = region->u;\n\t\tattachment->regionV = region->v;\n"
            "\t\tattachment->regionU2 = region->u2;\n\t\tattachment->regionV2 = region->v2;\n"
            "\t\tattachment->regionRotate = region->rotate;\n"
            "\t\tattachment->regionOffsetX = region->offsetX;\n\t\tattachment->regionOffsetY = region->offsetY;\n"
            "\t\tattachment->regionWidth = region->width;\n\t\tattachment->regionHeight = region->height;\n"
            "\t\tattachment->regionOriginalWidth = region->originalWidth;\n\t\tattachment->regionOriginalHeight = region->originalHeight;\n"
            "\t\treturn SUPER(attachment);\n\t}\n\tdefault:",
        )],
    )
    _replace_once_if_needed(
        os.path.join(spine_dir, "Animation.h"),
        [(
            "CC_EX_DLL void AttachmentTimeline_setFrame (AttachmentTimeline* self, int frameIndex, float time, const char* attachmentName);",
            "CC_EX_DLL void AttachmentTimeline_setFrame (AttachmentTimeline* self, int frameIndex, float time, const char* attachmentName);\n\n"
            "struct Attachment;\n\n"
            "typedef struct {\n\tCurveTimeline super;\n\tint const framesLength;\n\tfloat* const frames;\n"
            "\tint slotIndex;\n\tconst struct Attachment* attachment;\n\tfloat** const frameVertices;\n"
            "\tint frameVerticesCount;\n} FFDTimeline;\n\n"
            "CC_EX_DLL FFDTimeline* FFDTimeline_create (int frameCount, int frameVerticesCount);\n"
            "CC_EX_DLL void FFDTimeline_setFrame (FFDTimeline* self, int frameIndex, float time, float* vertices);",
        )],
    )
    _replace_once_if_needed(
        os.path.join(spine_dir, "Animation.cpp"),
        [(
            "\t\tself->attachmentNames[frameIndex] = 0;\n}",
            "\t\tself->attachmentNames[frameIndex] = 0;\n}\n\n"
            "void _FFDTimeline_apply (const Timeline* timeline, Skeleton* skeleton, float time, float alpha) {\n"
            "\tFFDTimeline* self = (FFDTimeline*)timeline;\n\tSlot* slot = skeleton->slots[self->slotIndex];\n"
            "\tint i, frameIndex;\n\tfloat frameTime, percent;\n"
            "\tfloat* frameVertices;\n\tfloat* prevVertices;\n\tfloat* nextVertices;\n\tfloat* vertices;\n"
            "\tif (slot->attachment != self->attachment) return;\n\tif (time < self->frames[0]) return;\n"
            "\tif (slot->attachmentVerticesCapacity < self->frameVerticesCount) {\n"
            "\t\tFREE(slot->attachmentVertices);\n\t\tslot->attachmentVertices = MALLOC(float, self->frameVerticesCount);\n"
            "\t\tslot->attachmentVerticesCapacity = self->frameVerticesCount;\n\t}\n"
            "\tslot->attachmentVerticesCount = self->frameVerticesCount;\n\tvertices = slot->attachmentVertices;\n"
            "\tif (time >= self->frames[self->framesLength - 1]) {\n"
            "\t\tframeVertices = self->frameVertices[self->framesLength - 1];\n"
            "\t\tif (alpha < 1) {\n\t\t\tfor (i = 0; i < self->frameVerticesCount; ++i)\n\t\t\t\tvertices[i] += (frameVertices[i] - vertices[i]) * alpha;\n"
            "\t\t} else {\n\t\t\tmemcpy(vertices, frameVertices, self->frameVerticesCount * sizeof(float));\n\t\t}\n\t\treturn;\n\t}\n"
            "\tframeIndex = binarySearch(self->frames, self->framesLength, time, 1);\n\tframeTime = self->frames[frameIndex];\n"
            "\tpercent = 1 - (time - frameTime) / (self->frames[frameIndex - 1] - frameTime);\n"
            "\tpercent = CurveTimeline_getCurvePercent(SUPER(self), frameIndex - 1, percent < 0 ? 0 : (percent > 1 ? 1 : percent));\n"
            "\tprevVertices = self->frameVertices[frameIndex - 1];\n\tnextVertices = self->frameVertices[frameIndex];\n"
            "\tif (alpha < 1) {\n\t\tfor (i = 0; i < self->frameVerticesCount; ++i) {\n\t\t\tfloat prev = prevVertices[i];\n"
            "\t\t\tvertices[i] += (prev + (nextVertices[i] - prev) * percent - vertices[i]) * alpha;\n\t\t}\n"
            "\t} else {\n\t\tfor (i = 0; i < self->frameVerticesCount; ++i) {\n\t\t\tfloat prev = prevVertices[i];\n"
            "\t\t\tvertices[i] = prev + (nextVertices[i] - prev) * percent;\n\t\t}\n\t}\n}\n\n"
            "void _FFDTimeline_dispose (Timeline* timeline) {\n\tFFDTimeline* self = (FFDTimeline*)timeline;\n\tint i;\n"
            "\t_CurveTimeline_deinit(SUB_CAST(CurveTimeline, timeline));\n\tfor (i = 0; i < self->framesLength; ++i)\n\t\tFREE(self->frameVertices[i]);\n"
            "\tFREE(self->frameVertices);\n\tFREE(self->frames);\n\tFREE(self);\n}\n\n"
            "FFDTimeline* FFDTimeline_create (int frameCount, int frameVerticesCount) {\n"
            "\tFFDTimeline* self = NEW(FFDTimeline);\n\t_CurveTimeline_init(SUPER(self), frameCount, _FFDTimeline_dispose, _FFDTimeline_apply);\n"
            "\tCONST_CAST(int, self->framesLength) = frameCount;\n\tCONST_CAST(float*, self->frames) = CALLOC(float, frameCount);\n"
            "\tCONST_CAST(float**, self->frameVertices) = CALLOC(float*, frameCount);\n\tself->frameVerticesCount = frameVerticesCount;\n\treturn self;\n}\n\n"
            "void FFDTimeline_setFrame (FFDTimeline* self, int frameIndex, float time, float* vertices) {\n"
            "\tself->frames[frameIndex] = time;\n\tFREE(self->frameVertices[frameIndex]);\n\tself->frameVertices[frameIndex] = vertices;\n}",
        )],
    )

    # BoneData.h, BoneData.cpp, Bone.cpp: add and honor inheritRotation & inheritScale (default 1)
    _replace_once_if_needed(
        os.path.join(spine_dir, "BoneData.h"),
        [(
            "\tfloat scaleX, scaleY;",
            "\tfloat scaleX, scaleY;\n"
            f"\tint /*bool*/ inheritScale, inheritRotation; /* {SPINE_DEFORM_INHERIT_MARKER} */",
        )],
    )
    _replace_once_if_needed(
        os.path.join(spine_dir, "BoneData.cpp"),
        [(
            "\tself->scaleX = 1;\n\tself->scaleY = 1;",
            "\tself->scaleX = 1;\n\tself->scaleY = 1;\n"
            f"\tself->inheritScale = 1; /* {SPINE_DEFORM_INHERIT_MARKER} */\n"
            "\tself->inheritRotation = 1;",
        )],
    )
    _replace_once_if_needed(
        os.path.join(spine_dir, "Bone.cpp"),
        [(
            "\t\tCONST_CAST(float, self->worldScaleX) = self->parent->worldScaleX * self->scaleX;\n"
            "\t\tCONST_CAST(float, self->worldScaleY) = self->parent->worldScaleY * self->scaleY;\n"
            "\t\tCONST_CAST(float, self->worldRotation) = self->parent->worldRotation + self->rotation;",
            f"\t\t/* {SPINE_DEFORM_INHERIT_MARKER} */\n"
            "\t\tif (self->data->inheritScale) {\n"
            "\t\t\tCONST_CAST(float, self->worldScaleX) = self->parent->worldScaleX * self->scaleX;\n"
            "\t\t\tCONST_CAST(float, self->worldScaleY) = self->parent->worldScaleY * self->scaleY;\n"
            "\t\t} else {\n"
            "\t\t\tCONST_CAST(float, self->worldScaleX) = self->scaleX;\n"
            "\t\t\tCONST_CAST(float, self->worldScaleY) = self->scaleY;\n"
            "\t\t}\n"
            "\t\tCONST_CAST(float, self->worldRotation) = self->data->inheritRotation ? (self->parent->worldRotation + self->rotation) : self->rotation;",
        )],
    )

    # CCSkeleton.cpp: draw() for mesh/skinnedmesh AND boundingBox() for region/mesh/skinnedmesh
    ccskel_cpp = os.path.join(spine_dir, "CCSkeleton.cpp")
    _replace_once_if_needed(
        ccskel_cpp,
        [
            (
                "#include <spine/spine-cocos2dx.h>",
                "#include <spine/spine-cocos2dx.h>\n#include <vector>",
            ),
            (
                "\tfor (int i = 0, n = skeleton->slotCount; i < n; i++) {\n"
                "\t\tSlot* slot = skeleton->slots[i];\n"
                "\t\tif (!slot->attachment || slot->attachment->type != ATTACHMENT_REGION) continue;\n"
                "\t\tRegionAttachment* attachment = (RegionAttachment*)slot->attachment;\n"
                "\t\tCCTextureAtlas* regionTextureAtlas = getTextureAtlas(attachment);\n"
                "\t\tif (regionTextureAtlas != textureAtlas) {\n"
                "\t\t\tif (textureAtlas) {\n"
                "\t\t\t\ttextureAtlas->drawQuads();\n"
                "\t\t\t\ttextureAtlas->removeAllQuads();\n"
                "\t\t\t}\n"
                "\t\t}\n"
                "\t\ttextureAtlas = regionTextureAtlas;\n"
                "\t\tif (textureAtlas->getCapacity() == textureAtlas->getTotalQuads() &&\n"
                "\t\t\t!textureAtlas->resizeCapacity(textureAtlas->getCapacity() * 2)) return;\n"
                "\t\tRegionAttachment_updateQuad(attachment, slot, &quad, premultipliedAlpha);\n"
                "\t\ttextureAtlas->updateQuad(&quad, textureAtlas->getTotalQuads());\n"
                "\t}",
                "\tfor (int i = 0, n = skeleton->slotCount; i < n; i++) {\n"
                "\t\tSlot* slot = skeleton->drawOrder ? skeleton->drawOrder[i] : skeleton->slots[i];\n"
                "\t\tif (!slot->attachment) continue;\n"
                "\t\tif (slot->attachment->type == ATTACHMENT_REGION) {\n"
                "\t\t\tRegionAttachment* attachment = (RegionAttachment*)slot->attachment;\n"
                "\t\t\tCCTextureAtlas* regionTextureAtlas = getTextureAtlas(attachment);\n"
                "\t\t\tif (!regionTextureAtlas) continue;\n"
                "\t\t\tif (regionTextureAtlas != textureAtlas) {\n"
                "\t\t\t\tif (textureAtlas) {\n"
                "\t\t\t\t\ttextureAtlas->drawQuads();\n"
                "\t\t\t\t\ttextureAtlas->removeAllQuads();\n"
                "\t\t\t\t}\n"
                "\t\t\t}\n"
                "\t\t\ttextureAtlas = regionTextureAtlas;\n"
                "\t\t\tif (textureAtlas->getCapacity() == textureAtlas->getTotalQuads() &&\n"
                "\t\t\t\t!textureAtlas->resizeCapacity(textureAtlas->getCapacity() * 2)) return;\n"
                "\t\t\tRegionAttachment_updateQuad(attachment, slot, &quad, premultipliedAlpha);\n"
                "\t\t\ttextureAtlas->updateQuad(&quad, textureAtlas->getTotalQuads());\n"
                "\t\t} else if (slot->attachment->type == ATTACHMENT_MESH || slot->attachment->type == ATTACHMENT_SKINNED_MESH) {\n"
                "\t\t\tif (textureAtlas) {\n"
                "\t\t\t\ttextureAtlas->drawQuads();\n"
                "\t\t\t\ttextureAtlas->removeAllQuads();\n"
                "\t\t\t\ttextureAtlas = 0;\n"
                "\t\t\t}\n"
                "\t\t\tvoid* rendererObject = 0;\n"
                "\t\t\tfloat* uvs = 0;\n"
                "\t\t\tint* triangles = 0;\n"
                "\t\t\tint trianglesCount = 0;\n"
                "\t\t\tint verticesCount = 0;\n"
                "\t\t\tint uvsLimit = 0;\n"
                "\t\t\tfloat ar = 1, ag = 1, ab = 1, aa = 1;\n"
                "\t\t\tif (slot->attachment->type == ATTACHMENT_MESH) {\n"
                "\t\t\t\tMeshAttachment* mesh = (MeshAttachment*)slot->attachment;\n"
                "\t\t\t\trendererObject = mesh->rendererObject; uvs = mesh->uvs; triangles = mesh->triangles;\n"
                "\t\t\t\ttrianglesCount = mesh->trianglesCount; verticesCount = mesh->verticesCount; uvsLimit = mesh->verticesCount;\n"
                "\t\t\t\tar = mesh->r; ag = mesh->g; ab = mesh->b; aa = mesh->a;\n"
                "\t\t\t} else {\n"
                "\t\t\t\tSkinnedMeshAttachment* mesh = (SkinnedMeshAttachment*)slot->attachment;\n"
                "\t\t\t\trendererObject = mesh->rendererObject; uvs = mesh->uvs; triangles = mesh->triangles;\n"
                "\t\t\t\ttrianglesCount = mesh->trianglesCount;\n"
                "\t\t\t\tverticesCount = (mesh->weightsCount / 3) * 2;\n"
                "\t\t\t\tif (verticesCount < mesh->uvsCount) verticesCount = mesh->uvsCount;\n"
                "\t\t\t\tuvsLimit = mesh->uvsCount;\n"
                "\t\t\t\tar = mesh->r; ag = mesh->g; ab = mesh->b; aa = mesh->a;\n"
                "\t\t\t}\n"
                "\t\t\tif (!rendererObject || !uvs || !triangles || trianglesCount <= 0 || verticesCount <= 0 || uvsLimit <= 0) continue;\n"
                "\t\t\tAtlasRegion* region = (AtlasRegion*)rendererObject;\n"
                "\t\t\tCCTextureAtlas* meshAtlas = region->page ? (CCTextureAtlas*)region->page->rendererObject : 0;\n"
                "\t\t\tif (!meshAtlas || !meshAtlas->getTexture()) continue;\n"
                "\t\t\tstd::vector<float> worldVertices(verticesCount, 0.0f);\n"
                "\t\t\tif (slot->attachment->type == ATTACHMENT_MESH)\n"
                "\t\t\t\tMeshAttachment_computeWorldVertices((MeshAttachment*)slot->attachment, slot, worldVertices.data());\n"
                "\t\t\telse\n"
                "\t\t\t\tSkinnedMeshAttachment_computeWorldVertices((SkinnedMeshAttachment*)slot->attachment, slot, worldVertices.data());\n"
                "\t\t\tccColor4B c4;\n"
                "\t\t\tfloat a = skeleton->a * slot->a * aa;\n"
                "\t\t\tfloat r = skeleton->r * slot->r * ar * (premultipliedAlpha ? a : 1.0f);\n"
                "\t\t\tfloat g = skeleton->g * slot->g * ag * (premultipliedAlpha ? a : 1.0f);\n"
                "\t\t\tfloat b = skeleton->b * slot->b * ab * (premultipliedAlpha ? a : 1.0f);\n"
                "\t\t\tc4.r = (GLubyte)(r * 255.0f); c4.g = (GLubyte)(g * 255.0f); c4.b = (GLubyte)(b * 255.0f); c4.a = (GLubyte)(a * 255.0f);\n"
                "\t\t\tstd::vector<ccV3F_C4B_T2F> triVerts(trianglesCount);\n"
                "\t\t\tfor (int t = 0; t < trianglesCount; ++t) {\n"
                "\t\t\t\tint vIdx = triangles[t] * 2;\n"
                "\t\t\t\tif (vIdx < 0 || vIdx + 1 >= verticesCount || vIdx + 1 >= uvsLimit) continue;\n"
                "\t\t\t\ttriVerts[t].vertices.x = worldVertices[vIdx];\n"
                "\t\t\t\ttriVerts[t].vertices.y = worldVertices[vIdx + 1];\n"
                "\t\t\t\ttriVerts[t].vertices.z = 0;\n"
                "\t\t\t\ttriVerts[t].colors = c4;\n"
                "\t\t\t\ttriVerts[t].texCoords.u = uvs[vIdx];\n"
                "\t\t\t\ttriVerts[t].texCoords.v = uvs[vIdx + 1];\n"
                "\t\t\t}\n"
                "\t\t\tccGLBindTexture2D(meshAtlas->getTexture()->getName());\n"
                "\t\t\tccGLEnableVertexAttribs(kCCVertexAttribFlag_PosColorTex);\n"
                "\t\t\tglVertexAttribPointer(kCCVertexAttrib_Position, 3, GL_FLOAT, GL_FALSE, sizeof(ccV3F_C4B_T2F), &triVerts[0].vertices);\n"
                "\t\t\tglVertexAttribPointer(kCCVertexAttrib_Color, 4, GL_UNSIGNED_BYTE, GL_TRUE, sizeof(ccV3F_C4B_T2F), &triVerts[0].colors);\n"
                "\t\t\tglVertexAttribPointer(kCCVertexAttrib_TexCoords, 2, GL_FLOAT, GL_FALSE, sizeof(ccV3F_C4B_T2F), &triVerts[0].texCoords);\n"
                "\t\t\tglDrawArrays(GL_TRIANGLES, 0, trianglesCount);\n"
                "\t\t}\n"
                "\t}",
            ),
        ],
    )
    if os.path.exists(ccskel_cpp):
        txt = open(ccskel_cpp, "r", encoding="utf-8", errors="replace").read()
        if SPINE_BBOX_MARKER not in txt:
            reg_hdr_p = os.path.join(spine_dir, "RegionAttachment.h")
            reg_hdr_txt = open(reg_hdr_p, "r", encoding="utf-8", errors="replace").read() if os.path.exists(reg_hdr_p) else ""
            reg_compute_fn = (
                "RegionAttachment_computeWorldVertices"
                if "RegionAttachment_computeWorldVertices" in reg_hdr_txt and "RegionAttachment_computeVertices" not in reg_hdr_txt
                else "RegionAttachment_computeVertices"
            )
            bbox_spans = _find_method_body_spans(txt, "CCSkeleton::boundingBox")
            if bbox_spans:
                b_start, b_end = bbox_spans[-1]
                new_bbox = (
                    "{\n"
                    f"\t// {SPINE_BBOX_MARKER}\n"
                    "\tCCPoint position = getPosition();\n"
                    "\tif (!skeleton) return CCRectMake(position.x, position.y, 0, 0);\n"
                    "\tfloat minX = FLT_MAX, minY = FLT_MAX, maxX = -FLT_MAX, maxY = -FLT_MAX;\n"
                    "\tbool hasVertices = false;\n"
                    "\tfloat scaleX = getScaleX(), scaleY = getScaleY();\n"
                    "\tfloat vertices[8];\n"
                    "\tstd::vector<float> meshVertices;\n"
                    "\tfor (int i = 0; i < skeleton->slotCount; ++i) {\n"
                    "\t\tSlot* slot = skeleton->slots[i];\n"
                    "\t\tif (!slot || !slot->attachment) continue;\n"
                    "\t\tif (slot->attachment->type == ATTACHMENT_REGION) {\n"
                    "\t\t\tRegionAttachment* attachment = (RegionAttachment*)slot->attachment;\n"
                    f"\t\t\t{reg_compute_fn}(attachment, slot->skeleton->x, slot->skeleton->y, slot->bone, vertices);\n"
                    "\t\t\tfor (int ii = 0; ii < 8; ii += 2) {\n"
                    "\t\t\t\tfloat x = vertices[ii] * scaleX, y = vertices[ii + 1] * scaleY;\n"
                    "\t\t\t\tif (x < minX) minX = x;\n"
                    "\t\t\t\tif (y < minY) minY = y;\n"
                    "\t\t\t\tif (x > maxX) maxX = x;\n"
                    "\t\t\t\tif (y > maxY) maxY = y;\n"
                    "\t\t\t\thasVertices = true;\n"
                    "\t\t\t}\n"
                    "\t\t} else if (slot->attachment->type == ATTACHMENT_MESH) {\n"
                    "\t\t\tMeshAttachment* mesh = (MeshAttachment*)slot->attachment;\n"
                    "\t\t\tint count = mesh->verticesCount;\n"
                    "\t\t\tif (count <= 0 || !mesh->vertices) continue;\n"
                    "\t\t\tif ((int)meshVertices.size() < count) meshVertices.resize(count);\n"
                    "\t\t\tMeshAttachment_computeWorldVertices(mesh, slot, &meshVertices[0]);\n"
                    "\t\t\tfor (int ii = 0; ii + 1 < count; ii += 2) {\n"
                    "\t\t\t\tfloat x = meshVertices[ii] * scaleX, y = meshVertices[ii + 1] * scaleY;\n"
                    "\t\t\t\tif (x < minX) minX = x;\n"
                    "\t\t\t\tif (y < minY) minY = y;\n"
                    "\t\t\t\tif (x > maxX) maxX = x;\n"
                    "\t\t\t\tif (y > maxY) maxY = y;\n"
                    "\t\t\t\thasVertices = true;\n"
                    "\t\t\t}\n"
                    "\t\t} else if (slot->attachment->type == ATTACHMENT_SKINNED_MESH) {\n"
                    "\t\t\tSkinnedMeshAttachment* mesh = (SkinnedMeshAttachment*)slot->attachment;\n"
                    "\t\t\tint count = mesh->uvsCount > 0 ? mesh->uvsCount : (mesh->weightsCount / 3) * 2;\n"
                    "\t\t\tint bufCap = (mesh->weightsCount / 3) * 2;\n"
                    "\t\t\tif (bufCap < count) bufCap = count;\n"
                    "\t\t\tif (count <= 0 || !mesh->bones || !mesh->weights) continue;\n"
                    "\t\t\tif ((int)meshVertices.size() < bufCap) meshVertices.resize(bufCap);\n"
                    "\t\t\tSkinnedMeshAttachment_computeWorldVertices(mesh, slot, &meshVertices[0]);\n"
                    "\t\t\tfor (int ii = 0; ii + 1 < count; ii += 2) {\n"
                    "\t\t\t\tfloat x = meshVertices[ii] * scaleX, y = meshVertices[ii + 1] * scaleY;\n"
                    "\t\t\t\tif (x < minX) minX = x;\n"
                    "\t\t\t\tif (y < minY) minY = y;\n"
                    "\t\t\t\tif (x > maxX) maxX = x;\n"
                    "\t\t\t\tif (y > maxY) maxY = y;\n"
                    "\t\t\t\thasVertices = true;\n"
                    "\t\t\t}\n"
                    "\t\t}\n"
                    "\t}\n"
                    "\tif (!hasVertices) return CCRectMake(position.x, position.y, 0, 0);\n"
                    "\treturn CCRectMake(position.x + minX, position.y + minY, maxX - minX, maxY - minY);\n"
                    "}"
                )
                txt = txt[:b_start] + new_bbox + txt[b_end:]
                open(ccskel_cpp, "w", encoding="utf-8", newline="\n").write(txt)
                print(f"[ok] Patched CCSkeleton::boundingBox in: {ccskel_cpp}")

    # SkeletonJson.cpp: mesh/skinnedmesh, ffd + deform alias, and BoneData inheritRotation/inheritScale
    skel_json_cpp = os.path.join(spine_dir, "SkeletonJson.cpp")
    ffd_apply_tail = (
        "\tif (ffd) {\n\t\tfor (i = 0; i < ffdCount; ++i) {\n"
        "\t\t\tJson* skinMap = Json_getItemAt(ffd, i);\n\t\t\tSkin* skin = SkeletonData_findSkin(skeletonData, skinMap->name);\n"
        "\t\t\tint slotMapCount = Json_getSize(skinMap);\n\t\t\tfor (ii = 0; ii < slotMapCount; ++ii) {\n"
        "\t\t\t\tJson* slotMap = Json_getItemAt(skinMap, ii);\n\t\t\t\tint slotIndex = SkeletonData_findSlotIndex(skeletonData, slotMap->name);\n"
        "\t\t\t\tint meshCount = Json_getSize(slotMap);\n\t\t\t\tif (!skin || slotIndex == -1) continue;\n"
        "\t\t\t\tfor (iii = 0; iii < meshCount; ++iii) {\n\t\t\t\t\tJson* meshMap = Json_getItemAt(slotMap, iii);\n"
        "\t\t\t\t\tAttachment* attachment = Skin_getAttachment(skin, slotIndex, meshMap->name);\n"
        "\t\t\t\t\tint frameCount = Json_getSize(meshMap);\n\t\t\t\t\tint verticesCount = 0;\n\t\t\t\t\tFFDTimeline* timeline;\n\t\t\t\t\tfloat duration;\n\t\t\t\t\tint frameIndex;\n"
        "\t\t\t\t\tif (!attachment || frameCount == 0) continue;\n"
        "\t\t\t\t\tif (attachment->type == ATTACHMENT_MESH) verticesCount = ((MeshAttachment*)attachment)->verticesCount;\n"
        "\t\t\t\t\telse if (attachment->type == ATTACHMENT_SKINNED_MESH) verticesCount = (((SkinnedMeshAttachment*)attachment)->weightsCount / 3) * 2;\n"
        "\t\t\t\t\telse continue;\n"
        "\t\t\t\t\ttimeline = FFDTimeline_create(frameCount, verticesCount);\n\t\t\t\t\ttimeline->slotIndex = slotIndex;\n\t\t\t\t\ttimeline->attachment = attachment;\n"
        "\t\t\t\t\tfor (frameIndex = 0; frameIndex < frameCount; ++frameIndex) {\n"
        "\t\t\t\t\t\tJson* frameMap = Json_getItemAt(meshMap, frameIndex);\n\t\t\t\t\t\tJson* verticesJson = Json_getItem(frameMap, \"vertices\");\n"
        "\t\t\t\t\t\tfloat* frameVertices = CALLOC(float, verticesCount);\n"
        "\t\t\t\t\t\tif (verticesJson) {\n\t\t\t\t\t\t\tint offset = Json_getInt(frameMap, \"offset\", 0);\n"
        "\t\t\t\t\t\t\tint vCount = Json_getSize(verticesJson);\n\t\t\t\t\t\t\tint v;\n"
        "\t\t\t\t\t\t\tfor (v = 0; v < vCount && (offset + v) < verticesCount; ++v)\n"
        "\t\t\t\t\t\t\t\tframeVertices[offset + v] = Json_getItemAt(verticesJson, v)->valuefloat * self->scale;\n\t\t\t\t\t\t}\n"
        "\t\t\t\t\t\tif (attachment->type == ATTACHMENT_MESH) {\n"
        "\t\t\t\t\t\t\tMeshAttachment* mesh = (MeshAttachment*)attachment;\n\t\t\t\t\t\t\tint v;\n"
        "\t\t\t\t\t\t\tfor (v = 0; v < verticesCount; ++v) frameVertices[v] += mesh->vertices[v];\n\t\t\t\t\t\t}\n"
        "\t\t\t\t\t\tFFDTimeline_setFrame(timeline, frameIndex, Json_getFloat(frameMap, \"time\", 0), frameVertices);\n"
        "\t\t\t\t\t\treadCurve(SUPER(timeline), frameIndex, frameMap);\n"
        "\t\t\t\t\t}\n"
        "\t\t\t\t\tanimation->timelines[animation->timelineCount++] = (Timeline*)timeline;\n"
        "\t\t\t\t\tduration = timeline->frames[frameCount - 1];\n"
        "\t\t\t\t\tif (duration > animation->duration) animation->duration = duration;\n"
        "\t\t\t\t}\n\t\t\t}\n\t\t}\n\t}\n\n\treturn animation;"
    )
    _replace_once_if_needed(
        skel_json_cpp,
        [
            (
                "\t\tboneData->scaleX = Json_getFloat(boneMap, \"scaleX\", 1);\n\t\tboneData->scaleY = Json_getFloat(boneMap, \"scaleY\", 1);",
                "\t\tboneData->scaleX = Json_getFloat(boneMap, \"scaleX\", 1);\n"
                "\t\tboneData->scaleY = Json_getFloat(boneMap, \"scaleY\", 1);\n"
                f"\t\t/* {SPINE_DEFORM_INHERIT_MARKER} */\n"
                "\t\t{\n"
                "\t\t\tJson* ir = Json_getItem(boneMap, \"inheritRotation\");\n"
                "\t\t\tboneData->inheritRotation = ir ? (ir->type == Json_True ? 1 : (ir->type == Json_False ? 0 : ir->valueint)) : 1;\n"
                "\t\t\tJson* is = Json_getItem(boneMap, \"inheritScale\");\n"
                "\t\t\tboneData->inheritScale = is ? (is->type == Json_True ? 1 : (is->type == Json_False ? 0 : is->valueint)) : 1;\n"
                "\t\t}",
            ),
            (
                "\tJson* slots = Json_getItem(root, \"slots\");\n\tint slotCount = slots ? Json_getSize(slots) : 0;\n\n\tint timelineCount = 0;",
                "\tJson* slots = Json_getItem(root, \"slots\");\n\tint slotCount = slots ? Json_getSize(slots) : 0;\n\n"
                "\tJson* ffd = Json_getItem(root, \"ffd\");\n"
                "\tif (!ffd) ffd = Json_getItem(root, \"deform\");\n"
                "\tint ffdCount = ffd ? Json_getSize(ffd) : 0;\n\n\tint timelineCount = 0;",
            ),
            (
                "\tJson* ffd = Json_getItem(root, \"ffd\");\n\tint ffdCount = ffd ? Json_getSize(ffd) : 0;",
                "\tJson* ffd = Json_getItem(root, \"ffd\");\n"
                "\tif (!ffd) ffd = Json_getItem(root, \"deform\");\n"
                "\tint ffdCount = ffd ? Json_getSize(ffd) : 0;",
            ),
            (
                "\tfor (i = 0; i < slotCount; ++i)\n\t\ttimelineCount += Json_getSize(Json_getItemAt(slots, i));\n\tanimation = Animation_create(root->name, timelineCount);",
                "\tfor (i = 0; i < slotCount; ++i)\n\t\ttimelineCount += Json_getSize(Json_getItemAt(slots, i));\n"
                "\tfor (i = 0; i < ffdCount; ++i) {\n\t\tJson* skinMap = Json_getItemAt(ffd, i);\n"
                "\t\tint slotMapCount = Json_getSize(skinMap);\n\t\tfor (ii = 0; ii < slotMapCount; ++ii)\n"
                "\t\t\ttimelineCount += Json_getSize(Json_getItemAt(skinMap, ii));\n\t}\n"
                "\tanimation = Animation_create(root->name, timelineCount);",
            ),
            (
                "\t\t\t} else {\n\t\t\t\tcontinue; /* skip_unknown_slot_timeline */\n\t\t\t}\n\t\t}\n\t}\n\n\treturn animation;",
                "\t\t\t} else {\n\t\t\t\tcontinue; /* skip_unknown_slot_timeline */\n\t\t\t}\n\t\t}\n\t}\n\n" + ffd_apply_tail,
            ),
            (
                "\t\t\t} else {\n\t\t\t\tcontinue;\n\t\t\t}\n\t\t}\n\t}\n\n\treturn animation;",
                "\t\t\t} else {\n\t\t\t\tcontinue;\n\t\t\t}\n\t\t}\n\t}\n\n" + ffd_apply_tail,
            ),
            (
                "\t\t\t\t\tconst char* attachmentName = Json_getString(attachmentMap, \"name\", skinAttachmentName);\n\n"
                "\t\t\t\t\tconst char* typeString = Json_getString(attachmentMap, \"type\", \"region\");\n"
                "\t\t\t\t\tAttachmentType type;\n"
                "\t\t\t\t\tif (strcmp(typeString, \"region\") == 0)\n\t\t\t\t\t\ttype = ATTACHMENT_REGION;\n"
                "\t\t\t\t\telse if (strcmp(typeString, \"regionSequence\") == 0)\n\t\t\t\t\t\ttype = ATTACHMENT_REGION_SEQUENCE;\n"
                "\t\t\t\t\telse {\n\t\t\t\t\t\tcontinue; /* skip_unknown_attachment_type */\n\t\t\t\t\t}\n\n"
                "\t\t\t\t\tattachment = AttachmentLoader_newAttachment(self->attachmentLoader, skin, type, attachmentName);",
                "\t\t\t\t\tconst char* attachmentName = Json_getString(attachmentMap, \"name\", skinAttachmentName);\n"
                "\t\t\t\t\tconst char* path = Json_getString(attachmentMap, \"path\", attachmentName);\n\n"
                "\t\t\t\t\tconst char* typeString = Json_getString(attachmentMap, \"type\", \"region\");\n"
                "\t\t\t\t\tAttachmentType type;\n"
                "\t\t\t\t\tif (strcmp(typeString, \"region\") == 0)\n\t\t\t\t\t\ttype = ATTACHMENT_REGION;\n"
                "\t\t\t\t\telse if (strcmp(typeString, \"regionSequence\") == 0)\n\t\t\t\t\t\ttype = ATTACHMENT_REGION_SEQUENCE;\n"
                "\t\t\t\t\telse if (strcmp(typeString, \"mesh\") == 0)\n\t\t\t\t\t\ttype = ATTACHMENT_MESH;\n"
                "\t\t\t\t\telse if (strcmp(typeString, \"weightedmesh\") == 0 || strcmp(typeString, \"skinnedmesh\") == 0)\n\t\t\t\t\t\ttype = ATTACHMENT_SKINNED_MESH;\n"
                "\t\t\t\t\telse {\n\t\t\t\t\t\tcontinue; /* skip_unknown_attachment_type */\n\t\t\t\t\t}\n\n"
                "\t\t\t\t\tattachment = AttachmentLoader_newAttachment(self->attachmentLoader, skin, type, path);",
            ),
            (
                "\t\t\t\t\tconst char* attachmentName = Json_getString(attachmentMap, \"name\", skinAttachmentName);\n\n"
                "\t\t\t\t\tconst char* typeString = Json_getString(attachmentMap, \"type\", \"region\");\n"
                "\t\t\t\t\tAttachmentType type;\n"
                "\t\t\t\t\tif (strcmp(typeString, \"region\") == 0)\n\t\t\t\t\t\ttype = ATTACHMENT_REGION;\n"
                "\t\t\t\t\telse if (strcmp(typeString, \"regionSequence\") == 0)\n\t\t\t\t\t\ttype = ATTACHMENT_REGION_SEQUENCE;\n"
                "\t\t\t\t\telse {\n\t\t\t\t\t\tcontinue;\n\t\t\t\t\t}\n\n"
                "\t\t\t\t\tattachment = AttachmentLoader_newAttachment(self->attachmentLoader, skin, type, attachmentName);",
                "\t\t\t\t\tconst char* attachmentName = Json_getString(attachmentMap, \"name\", skinAttachmentName);\n"
                "\t\t\t\t\tconst char* path = Json_getString(attachmentMap, \"path\", attachmentName);\n\n"
                "\t\t\t\t\tconst char* typeString = Json_getString(attachmentMap, \"type\", \"region\");\n"
                "\t\t\t\t\tAttachmentType type;\n"
                "\t\t\t\t\tif (strcmp(typeString, \"region\") == 0)\n\t\t\t\t\t\ttype = ATTACHMENT_REGION;\n"
                "\t\t\t\t\telse if (strcmp(typeString, \"regionSequence\") == 0)\n\t\t\t\t\t\ttype = ATTACHMENT_REGION_SEQUENCE;\n"
                "\t\t\t\t\telse if (strcmp(typeString, \"mesh\") == 0)\n\t\t\t\t\t\ttype = ATTACHMENT_MESH;\n"
                "\t\t\t\t\telse if (strcmp(typeString, \"weightedmesh\") == 0 || strcmp(typeString, \"skinnedmesh\") == 0)\n\t\t\t\t\t\ttype = ATTACHMENT_SKINNED_MESH;\n"
                "\t\t\t\t\telse {\n\t\t\t\t\t\tcontinue;\n\t\t\t\t\t}\n\n"
                "\t\t\t\t\tattachment = AttachmentLoader_newAttachment(self->attachmentLoader, skin, type, path);",
            ),
            (
                "\t\t\t\t\t\tRegionAttachment_updateOffset(regionAttachment);\n\t\t\t\t\t}\n\n\t\t\t\t\tSkin_addAttachment",
                "\t\t\t\t\t\tRegionAttachment_updateOffset(regionAttachment);\n"
                "\t\t\t\t\t} else if (attachment->type == ATTACHMENT_MESH) {\n"
                "\t\t\t\t\t\tMeshAttachment* mesh = (MeshAttachment*)attachment;\n"
                "\t\t\t\t\t\tJson* verticesJson = Json_getItem(attachmentMap, \"vertices\");\n"
                "\t\t\t\t\t\tJson* uvsJson = Json_getItem(attachmentMap, \"uvs\");\n"
                "\t\t\t\t\t\tJson* trianglesJson = Json_getItem(attachmentMap, \"triangles\");\n"
                "\t\t\t\t\t\tint idx;\n"
                "\t\t\t\t\t\tif (verticesJson && uvsJson && trianglesJson) {\n"
                "\t\t\t\t\t\t\tmesh->verticesCount = Json_getSize(verticesJson);\n"
                "\t\t\t\t\t\t\tmesh->vertices = MALLOC(float, mesh->verticesCount);\n"
                "\t\t\t\t\t\t\tfor (idx = 0; idx < mesh->verticesCount; ++idx) mesh->vertices[idx] = Json_getItemAt(verticesJson, idx)->valuefloat * self->scale;\n"
                "\t\t\t\t\t\t\tmesh->regionUVs = MALLOC(float, mesh->verticesCount);\n"
                "\t\t\t\t\t\t\tfor (idx = 0; idx < mesh->verticesCount; ++idx) mesh->regionUVs[idx] = Json_getItemAt(uvsJson, idx)->valuefloat;\n"
                "\t\t\t\t\t\t\tmesh->trianglesCount = Json_getSize(trianglesJson);\n"
                "\t\t\t\t\t\t\tmesh->triangles = MALLOC(int, mesh->trianglesCount);\n"
                "\t\t\t\t\t\t\tfor (idx = 0; idx < mesh->trianglesCount; ++idx) mesh->triangles[idx] = Json_getItemAt(trianglesJson, idx)->valueint;\n"
                "\t\t\t\t\t\t\tMeshAttachment_updateUVs(mesh);\n"
                "\t\t\t\t\t\t}\n"
                "\t\t\t\t\t\tmesh->hullLength = Json_getInt(attachmentMap, \"hull\", 0);\n"
                "\t\t\t\t\t\tmesh->width = Json_getFloat(attachmentMap, \"width\", 0) * self->scale;\n"
                "\t\t\t\t\t\tmesh->height = Json_getFloat(attachmentMap, \"height\", 0) * self->scale;\n"
                "\t\t\t\t\t\t{ const char* color = Json_getString(attachmentMap, \"color\", 0); if (color) { mesh->r = toColor(color, 0); mesh->g = toColor(color, 1); mesh->b = toColor(color, 2); mesh->a = toColor(color, 3); } }\n"
                "\t\t\t\t\t} else if (attachment->type == ATTACHMENT_SKINNED_MESH) {\n"
                "\t\t\t\t\t\tSkinnedMeshAttachment* mesh = (SkinnedMeshAttachment*)attachment;\n"
                "\t\t\t\t\t\tJson* uvsJson = Json_getItem(attachmentMap, \"uvs\");\n"
                "\t\t\t\t\t\tJson* verticesJson = Json_getItem(attachmentMap, \"vertices\");\n"
                "\t\t\t\t\t\tJson* trianglesJson = Json_getItem(attachmentMap, \"triangles\");\n"
                "\t\t\tif (uvsJson && verticesJson && trianglesJson) {\n"
                "\t\t\t\t\t\t\tint uvsSize = Json_getSize(uvsJson), vSize = Json_getSize(verticesJson), idx = 0, bCount = 0, wCount = 0;\n"
                "\t\t\t\t\t\t\tmesh->uvsCount = uvsSize; mesh->regionUVs = MALLOC(float, uvsSize);\n"
                "\t\t\t\t\t\t\tfor (idx = 0; idx < uvsSize; ++idx) mesh->regionUVs[idx] = Json_getItemAt(uvsJson, idx)->valuefloat;\n"
                "\t\t\t\t\t\t\tfor (idx = 0; idx < vSize;) { int bc = Json_getItemAt(verticesJson, idx++)->valueint; bCount += 1 + bc; wCount += bc * 3; idx += bc * 4; }\n"
                "\t\t\t\t\t\t\tmesh->bonesCount = bCount; mesh->bones = MALLOC(int, bCount);\n"
                "\t\t\t\t\t\t\tmesh->weightsCount = wCount; mesh->weights = MALLOC(float, wCount);\n"
                "\t\t\t\t\t\t\t{ int bIdx = 0, wIdx = 0; for (idx = 0; idx < vSize;) { int bc = Json_getItemAt(verticesJson, idx++)->valueint; int n; mesh->bones[bIdx++] = bc; for (n = 0; n < bc; ++n) { mesh->bones[bIdx++] = Json_getItemAt(verticesJson, idx++)->valueint; mesh->weights[wIdx++] = Json_getItemAt(verticesJson, idx++)->valuefloat * self->scale; mesh->weights[wIdx++] = Json_getItemAt(verticesJson, idx++)->valuefloat * self->scale; mesh->weights[wIdx++] = Json_getItemAt(verticesJson, idx++)->valuefloat; } } }\n"
                "\t\t\t\t\t\t\tmesh->trianglesCount = Json_getSize(trianglesJson); mesh->triangles = MALLOC(int, mesh->trianglesCount);\n"
                "\t\t\t\t\t\t\tfor (idx = 0; idx < mesh->trianglesCount; ++idx) mesh->triangles[idx] = Json_getItemAt(trianglesJson, idx)->valueint;\n"
                "\t\t\t\t\t\t\tSkinnedMeshAttachment_updateUVs(mesh);\n"
                "\t\t\t\t\t\t}\n"
                "\t\t\t\t\t\tmesh->hullLength = Json_getInt(attachmentMap, \"hull\", 0);\n"
                "\t\t\t\t\t\tmesh->width = Json_getFloat(attachmentMap, \"width\", 0) * self->scale;\n"
                "\t\t\t\t\t\tmesh->height = Json_getFloat(attachmentMap, \"height\", 0) * self->scale;\n"
                "\t\t\t\t\t\t{ const char* color = Json_getString(attachmentMap, \"color\", 0); if (color) { mesh->r = toColor(color, 0); mesh->g = toColor(color, 1); mesh->b = toColor(color, 2); mesh->a = toColor(color, 3); } }\n"
                "\t\t\t\t\t}\n\n\t\t\t\t\tSkin_addAttachment",
            ),
        ],
    )


def patch_node_sprite_actions_particles(cocos_root: str) -> None:
    # 1. CCNode.cpp: null guards across all 3 addChild overloads, clean reparenting, and runAction null guard
    node_cpp = os.path.join(cocos_root, "cocos2dx", "base_nodes", "CCNode.cpp")
    if os.path.exists(node_cpp):
        txt = open(node_cpp, "r", encoding="utf-8", errors="replace").read()
        orig_txt = txt
        if CCNODE_GUARD_MARKER not in txt:
            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "CCNode::addChild")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                c_var = _extract_param_ident(params[0], "child") if params else "child"
                body = txt[b_start:b_end]
                if len(params) == 3:
                    reparent_prologue = (
                        "{\n"
                        f"    // {CCNODE_GUARD_MARKER}\n"
                        f"    if (!{c_var} || {c_var} == this) return;\n"
                        "    bool _gclientReparented = false;\n"
                        f"    if ({c_var}->m_pParent != NULL)\n"
                        "    {\n"
                        f"        {c_var}->retain();\n"
                        "        _gclientReparented = true;\n"
                        f"        {c_var}->removeFromParentAndCleanup(false);\n"
                        "    }"
                    )
                    patched = _inject_after_open_brace(body[:-1], reparent_prologue[5:]) + f"\n    if (_gclientReparented) {{ {c_var}->release(); }}\n}}"
                else:
                    patched = _inject_after_open_brace(body, f"if (!{c_var}) return; // {CCNODE_GUARD_MARKER}")
                txt = txt[:b_start] + patched + txt[b_end:]

            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "CCNode::runAction")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                a_var = _extract_param_ident(params[0], "action") if params else "action"
                body = txt[b_start:b_end]
                patched = _inject_after_open_brace(body, f"if (!{a_var}) return NULL; // {CCNODE_GUARD_MARKER}")
                txt = txt[:b_start] + patched + txt[b_end:]

        if txt != orig_txt:
            open(node_cpp, "w", encoding="utf-8", newline="\n").write(txt)
            print(f"[ok] Patched CCNode.cpp: {node_cpp}")
        else:
            print(f"[skip] Already patched CCNode.cpp: {node_cpp}")

    # 2. CCSprite.cpp: null guards in initWithSpriteFrame, setDisplayFrame, setDisplayFrameWithAnimationName
    sprite_cpp = os.path.join(cocos_root, "cocos2dx", "sprite_nodes", "CCSprite.cpp")
    if os.path.exists(sprite_cpp):
        txt = open(sprite_cpp, "r", encoding="utf-8", errors="replace").read()
        orig_txt = txt
        if CCSPRITE_GUARD_MARKER not in txt:
            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "CCSprite::initWithSpriteFrame")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                f_var = _extract_param_ident(params[0], "pSpriteFrame") if params else "pSpriteFrame"
                body = txt[b_start:b_end]
                txt = txt[:b_start] + _inject_after_open_brace(body, f"if (!{f_var}) return false; // {CCSPRITE_GUARD_MARKER}") + txt[b_end:]

            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "CCSprite::initWithSpriteFrameName")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                n_var = _extract_param_ident(params[0], "pszSpriteFrameName") if params else "pszSpriteFrameName"
                body = txt[b_start:b_end]
                txt = txt[:b_start] + _inject_after_open_brace(body, f"if (!{n_var}) return false; // {CCSPRITE_GUARD_MARKER}") + txt[b_end:]

            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "CCSprite::setDisplayFrame")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                f_var = _extract_param_ident(params[0], "pNewFrame") if params else "pNewFrame"
                body = txt[b_start:b_end]
                txt = txt[:b_start] + _inject_after_open_brace(body, f"if (!{f_var}) return; // {CCSPRITE_GUARD_MARKER}") + txt[b_end:]

            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "CCSprite::setDisplayFrameWithAnimationName")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                a_name_var = _extract_param_ident(params[0], "animationName") if len(params) >= 1 else "animationName"
                idx_var = _extract_param_ident(params[1], "frameIndex") if len(params) >= 2 else "frameIndex"
                new_body = (
                    "{\n"
                    f"    // {CCSPRITE_GUARD_MARKER}\n"
                    f"    if (!{a_name_var}) return;\n"
                    f"    CCAnimation *a = CCAnimationCache::sharedAnimationCache()->animationByName({a_name_var});\n"
                    "    if (!a || !a->getFrames()) return;\n"
                    f"    if ({idx_var} < 0 || {idx_var} >= (int)a->getFrames()->count()) return;\n"
                    f"    CCAnimationFrame* frame = (CCAnimationFrame*)a->getFrames()->objectAtIndex({idx_var});\n"
                    "    if (!frame) return;\n"
                    "    setDisplayFrame(frame->getSpriteFrame());\n"
                    "}"
                )
                txt = txt[:b_start] + new_body + txt[b_end:]

        if txt != orig_txt:
            open(sprite_cpp, "w", encoding="utf-8", newline="\n").write(txt)
            print(f"[ok] Patched CCSprite.cpp: {sprite_cpp}")
        else:
            print(f"[skip] Already patched CCSprite.cpp: {sprite_cpp}")

    # 3. CCActionInterval.cpp: null/empty guards in CCAnimate, CCRepeatForever, CCRepeat, CCSequence, CCSpawn
    act_cpp = os.path.join(cocos_root, "cocos2dx", "actions", "CCActionInterval.cpp")
    if os.path.exists(act_cpp):
        txt = open(act_cpp, "r", encoding="utf-8", errors="replace").read()
        orig_txt = txt
        if CCACTION_GUARD_MARKER not in txt:
            single_bool_guards = (
                ("CCAnimate::initWithAnimation", "pAnimation"),
                ("CCRepeatForever::initWithAction", "pAction"),
                ("CCRepeat::initWithAction", "pAction"),
            )
            for q_name, def_param in single_bool_guards:
                for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, q_name)):
                    params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                    v = _extract_param_ident(params[0], def_param) if params else def_param
                    body = txt[b_start:b_end]
                    txt = txt[:b_start] + _inject_after_open_brace(body, f"if (!{v}) return false; // {CCACTION_GUARD_MARKER}") + txt[b_end:]

            two_bool_guards = (
                ("CCSequence::initWithTwoActions", "pActionOne", "pActionTwo"),
                ("CCSpawn::initWithTwoActions", "pAction1", "pAction2"),
            )
            for q_name, def_p1, def_p2 in two_bool_guards:
                for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, q_name)):
                    params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                    v1 = _extract_param_ident(params[0], def_p1) if len(params) >= 1 else def_p1
                    v2 = _extract_param_ident(params[1], def_p2) if len(params) >= 2 else def_p2
                    body = txt[b_start:b_end]
                    txt = txt[:b_start] + _inject_after_open_brace(body, f"if (!{v1} || !{v2}) return false; // {CCACTION_GUARD_MARKER}") + txt[b_end:]

            for create_fn in ("CCSequence::create", "CCSpawn::create"):
                for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, create_fn)):
                    sig_inner = txt[p_open + 1:p_close - 1]
                    if "CCArray" not in sig_inner:
                        continue
                    params = _split_top_level_params(sig_inner)
                    arr_var = _extract_param_ident(params[0], "arrayOfActions") if params else "arrayOfActions"
                    body = txt[b_start:b_end]
                    guard = f"if (!{arr_var} || {arr_var}->count() == 0) return NULL; // {CCACTION_GUARD_MARKER}"
                    txt = txt[:b_start] + _inject_after_open_brace(body, guard) + txt[b_end:]

            # Ensure factory methods check init* return value instead of autoreleasing uninitialized actions.
            factory_specs = (
                ("CCSequence::createWithTwoActions", "CCSequence", "initWithTwoActions", 2),
                ("CCSpawn::createWithTwoActions", "CCSpawn", "initWithTwoActions", 2),
                ("CCRepeat::create", "CCRepeat", "initWithAction", 2),
                ("CCAnimate::create", "CCAnimate", "initWithAnimation", 1),
            )
            for q_name, cls_name, init_fn, arity in factory_specs:
                for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, q_name)):
                    params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                    if len(params) != arity:
                        continue
                    arg_names = [_extract_param_ident(p, f"arg{idx}") for idx, p in enumerate(params)]
                    call_args = ", ".join(arg_names)
                    new_factory = (
                        "{\n"
                        f"    // {CCACTION_GUARD_MARKER}\n"
                        f"    {cls_name}* pRet = new {cls_name}();\n"
                        f"    if (pRet && pRet->{init_fn}({call_args}))\n"
                        "    {\n"
                        "        pRet->autorelease();\n"
                        "        return pRet;\n"
                        "    }\n"
                        "    CC_SAFE_DELETE(pRet);\n"
                        "    return NULL;\n"
                        "}"
                    )
                    txt = txt[:b_start] + new_factory + txt[b_end:]

        if txt != orig_txt:
            open(act_cpp, "w", encoding="utf-8", newline="\n").write(txt)
            print(f"[ok] Patched CCActionInterval.cpp: {act_cpp}")
        else:
            print(f"[skip] Already patched CCActionInterval.cpp: {act_cpp}")

    # 4. CCParticleSystem.cpp: check if (!dict) return false; before initWithDictionary and dict->release()
    part_cpp = os.path.join(cocos_root, "cocos2dx", "particle_nodes", "CCParticleSystem.cpp")
    if os.path.exists(part_cpp):
        txt = open(part_cpp, "r", encoding="utf-8", errors="replace").read()
        orig_txt = txt
        if PARTICLE_GUARD_MARKER not in txt:
            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "CCParticleSystem::initWithFile")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                p_var = _extract_param_ident(params[0], "plistFile") if params else "plistFile"
                body = txt[b_start:b_end]
                body = re.sub(
                    r"(CCDictionary\s*\*\s*dict\s*=\s*[^;]+;)",
                    f"\\1\n    if (!dict) return false; /* {PARTICLE_GUARD_MARKER} */",
                    body,
                    count=1,
                )
                body = _inject_after_open_brace(body, f"if (!{p_var} || !{p_var}[0]) return false; // {PARTICLE_GUARD_MARKER}")
                txt = txt[:b_start] + body + txt[b_end:]

            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "CCParticleSystem::initWithDictionary")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                if len(params) == 2:
                    d_var = _extract_param_ident(params[0], "dictionary")
                    body = txt[b_start:b_end]
                    body = _inject_after_open_brace(body, f"if (!{d_var}) return false; // {PARTICLE_GUARD_MARKER}")
                    txt = txt[:b_start] + body + txt[b_end:]

        if txt != orig_txt:
            open(part_cpp, "w", encoding="utf-8", newline="\n").write(txt)
            print(f"[ok] Patched CCParticleSystem.cpp: {part_cpp}")
        else:
            print(f"[skip] Already patched CCParticleSystem.cpp: {part_cpp}")


def patch_armature_and_richtext(cocos_root: str) -> None:
    arm_root = os.path.join(cocos_root, "extensions", "CocoStudio", "Armature")

    # 1. CCArmature.cpp: guard animationData, armatureData, movementNames.at(0), and boneData in createBone
    arm_cpp = os.path.join(arm_root, "CCArmature.cpp")
    if os.path.exists(arm_cpp):
        txt = open(arm_cpp, "r", encoding="utf-8", errors="replace").read()
        orig_txt = txt
        if ARMATURE_GUARD_MARKER not in txt:
            txt = re.sub(
                r"(CCAnimationData\s*\*\s*animationData\s*=\s*armatureDataManager->getAnimationData\([^)]+\)\s*;)",
                f"\\1\n            if (!animationData) {{ CCLOG(\"CCAnimationData not exist: %s\", name ? name : \"\"); break; }} /* {ARMATURE_GUARD_MARKER} */",
                txt,
                count=1,
            )
            txt = re.sub(
                r"(CCArmatureData\s*\*\s*armatureData\s*=\s*armatureDataManager->getArmatureData\([^)]+\)\s*;)",
                f"\\1\n            if (!armatureData) {{ CCLOG(\"CCArmatureData not exist: %s\", name ? name : \"\"); break; }} /* {ARMATURE_GUARD_MARKER} */",
                txt,
                count=1,
            )
            txt = txt.replace(
                "CCMovementData *movData = animationData->getMovement(animationData->movementNames.at(0).c_str());",
                f"CC_BREAK_IF(!bone || !animationData || animationData->movementNames.empty()); // {ARMATURE_GUARD_MARKER}\n"
                "                    CCMovementData *movData = animationData->getMovement(animationData->movementNames.at(0).c_str());",
                1,
            )
            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "CCArmature::createBone")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                b_var = _extract_param_ident(params[0], "boneName") if params else "boneName"
                body = txt[b_start:b_end]
                body = re.sub(
                    r"(CCBoneData\s*\*\s*boneData\s*=\s*[^;]+;)",
                    f"\\1\n    if (!boneData) return NULL; /* {ARMATURE_GUARD_MARKER} */",
                    body,
                    count=1,
                )
                body = _inject_after_open_brace(body, f"if (!{b_var} || !m_pArmatureData) return NULL; // {ARMATURE_GUARD_MARKER}")
                txt = txt[:b_start] + body + txt[b_end:]

        if txt != orig_txt:
            open(arm_cpp, "w", encoding="utf-8", newline="\n").write(txt)
            print(f"[ok] Patched CCArmature.cpp: {arm_cpp}")
        else:
            print(f"[skip] Already patched CCArmature.cpp: {arm_cpp}")

    # 2. CCArmatureAnimation.cpp: guard m_pAnimationData, m_pMovementData, and animationIndex bounds
    armanim_cpp = os.path.join(arm_root, "animation", "CCArmatureAnimation.cpp")
    if os.path.exists(armanim_cpp):
        txt = open(armanim_cpp, "r", encoding="utf-8", errors="replace").read()
        orig_txt = txt
        if ARMATURE_GUARD_MARKER not in txt:
            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "CCArmatureAnimation::play")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                a_var = _extract_param_ident(params[0], "animationName") if params else "animationName"
                body = txt[b_start:b_end]
                body = re.sub(
                    r"(m_pMovementData\s*=\s*m_pAnimationData->getMovement\([^)]+\)\s*;)",
                    f"\\1\n    if (!m_pMovementData) return; /* {ARMATURE_GUARD_MARKER} */",
                    body,
                    count=1,
                )
                body = _inject_after_open_brace(body, f"if (!{a_var} || !m_pAnimationData) return; // {ARMATURE_GUARD_MARKER}")
                txt = txt[:b_start] + body + txt[b_end:]

            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "CCArmatureAnimation::playWithIndex")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                idx_var = _extract_param_ident(params[0], "animationIndex") if params else "animationIndex"
                body = txt[b_start:b_end]
                body = re.sub(
                    r"(std::vector<std::string>\s*&\s*movName\s*=\s*m_pAnimationData->movementNames\s*;)",
                    f"if (!m_pAnimationData) return; /* {ARMATURE_GUARD_MARKER} */\n    \\1\n"
                    f"    if ({idx_var} < 0 || {idx_var} >= (int)movName.size()) return;",
                    body,
                    count=1,
                )
                txt = txt[:b_start] + body + txt[b_end:]

            for b_start, b_end in reversed(_find_method_body_spans(txt, "CCArmatureAnimation::playWithIndexes")):
                body = txt[b_start:b_end]
                body = _inject_after_open_brace(body, f"if (!m_pAnimationData) return; // {ARMATURE_GUARD_MARKER}")
                body = body.replace(
                    "std::string name = movName.at(movementIndexes[i]);",
                    "if (movementIndexes[i] < 0 || movementIndexes[i] >= (int)movName.size()) continue;\n"
                    "        std::string name = movName.at(movementIndexes[i]);",
                    1,
                )
                txt = txt[:b_start] + body + txt[b_end:]

        if txt != orig_txt:
            open(armanim_cpp, "w", encoding="utf-8", newline="\n").write(txt)
            print(f"[ok] Patched CCArmatureAnimation.cpp: {armanim_cpp}")
        else:
            print(f"[skip] Already patched CCArmatureAnimation.cpp: {armanim_cpp}")

    # 3. CCSkin.cpp: guard m_pBone in CCSkin::updateArmatureTransform & null name in initWithSpriteFrameName
    skin_cpp = os.path.join(arm_root, "display", "CCSkin.cpp")
    if os.path.exists(skin_cpp):
        txt = open(skin_cpp, "r", encoding="utf-8", errors="replace").read()
        orig_txt = txt
        if ARMATURE_GUARD_MARKER not in txt:
            txt = _prepend_to_method_body(txt, "CCSkin::updateArmatureTransform", "if (!m_pBone) return;", ARMATURE_GUARD_MARKER)
            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "CCSkin::initWithSpriteFrameName")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                n_var = _extract_param_ident(params[0], "pszSpriteFrameName") if params else "pszSpriteFrameName"
                body = txt[b_start:b_end]
                txt = txt[:b_start] + _inject_after_open_brace(body, f"if (!{n_var} || !{n_var}[0]) return false; // {ARMATURE_GUARD_MARKER}") + txt[b_end:]
        if txt != orig_txt:
            open(skin_cpp, "w", encoding="utf-8", newline="\n").write(txt)
            print(f"[ok] Patched CCSkin.cpp: {skin_cpp}")
        else:
            print(f"[skip] Already patched CCSkin.cpp: {skin_cpp}")

    # 4. CCTween.cpp: guard movementBoneData & getFrameData(0) in CCTween::play and updateFrameData
    tween_cpp = os.path.join(arm_root, "animation", "CCTween.cpp")
    if os.path.exists(tween_cpp):
        txt = open(tween_cpp, "r", encoding="utf-8", errors="replace").read()
        orig_txt = txt
        if ARMATURE_GUARD_MARKER not in txt:
            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "CCTween::play")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                mbd_var = _extract_param_ident(params[0], "movementBoneData") if params else "movementBoneData"
                body = txt[b_start:b_end]
                body = re.sub(
                    r"(CCFrameData\s*\*\s*nextKeyFrame\s*=\s*m_pMovementBoneData->getFrameData\(\s*0\s*\)\s*;)",
                    f"\\1\n    if (!nextKeyFrame || !m_pTweenData) return; /* {ARMATURE_GUARD_MARKER} */",
                    body,
                    count=1,
                )
                body = body.replace(
                    "if (m_pBone->getArmature()->getArmatureData()->dataVersion >= VERSION_COMBINED)",
                    "if (m_pBone && m_pBone->getArmature() && m_pBone->getArmature()->getArmatureData() "
                    "&& m_pBone->getBoneData() && m_pBone->getArmature()->getArmatureData()->dataVersion >= VERSION_COMBINED)",
                    1,
                )
                body = _inject_after_open_brace(body, f"if (!{mbd_var} || {mbd_var}->frameList.count() == 0) return; // {ARMATURE_GUARD_MARKER}")
                txt = txt[:b_start] + body + txt[b_end:]

            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "CCTween::updateFrameData")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                cp_var = _extract_param_ident(params[0], "currentPercent") if params else "currentPercent"
                body = txt[b_start:b_end]
                guard = (
                    "if (!m_pMovementBoneData || m_pMovementBoneData->frameList.count() == 0 "
                    f"|| !m_pMovementBoneData->frameList.data) return {cp_var}; // {ARMATURE_GUARD_MARKER}"
                )
                body = _inject_after_open_brace(body, guard)
                body = body.replace(
                    "m_iFromIndex = m_iToIndex;",
                    "if (m_iToIndex < 0 || m_iToIndex >= length) { m_iToIndex = 0; }\n            m_iFromIndex = m_iToIndex;\n"
                    "            if (!frames[m_iFromIndex]) break;",
                    1,
                )
                body = body.replace(
                    "to = frames[m_iToIndex];",
                    "to = frames[m_iToIndex];\n            if (!to) break;",
                    1,
                )
                body = body.replace(
                    "if (tweenType != TWEEN_EASING_MAX && tweenType != Linear && !m_bPassLastFrame)",
                    "if (tweenType != TWEEN_EASING_MAX && tweenType != Linear && !m_bPassLastFrame && m_pFrom)",
                    1,
                )
                txt = txt[:b_start] + body + txt[b_end:]

        if txt != orig_txt:
            open(tween_cpp, "w", encoding="utf-8", newline="\n").write(txt)
            print(f"[ok] Patched CCTween.cpp: {tween_cpp}")
        else:
            print(f"[skip] Already patched CCTween.cpp: {tween_cpp}")

    # 5. CCDisplayFactory.cpp: guard null CCParticleSystem in createParticleDisplay & updateParticleDisplay
    df_cpp = os.path.join(arm_root, "display", "CCDisplayFactory.cpp")
    if os.path.exists(df_cpp):
        txt = open(df_cpp, "r", encoding="utf-8", errors="replace").read()
        orig_txt = txt
        if ARMATURE_GUARD_MARKER not in txt:
            for b_start, b_end in reversed(_find_method_body_spans(txt, "CCDisplayFactory::createParticleDisplay")):
                new_cpd = (
                    "{\n"
                    f"    // {ARMATURE_GUARD_MARKER}\n"
                    "    if (!bone || !decoDisplay) return;\n"
                    "    CCParticleDisplayData *displayData = (CCParticleDisplayData *)decoDisplay->getDisplayData();\n"
                    "    if (!displayData || displayData->displayName.empty()) { decoDisplay->setDisplay(NULL); return; }\n"
                    "    CCParticleSystem *system = CCParticleSystemQuad::create(displayData->displayName.c_str());\n"
                    "    if (!system)\n"
                    "    {\n"
                    "        decoDisplay->setDisplay(NULL);\n"
                    "        return;\n"
                    "    }\n"
                    "    system->removeFromParent();\n"
                    "    CCArmature *armature = bone->getArmature();\n"
                    "    if (armature)\n"
                    "    {\n"
                    "        system->setParent(armature);\n"
                    "    }\n"
                    "    decoDisplay->setDisplay(system);\n"
                    "}"
                )
                txt = txt[:b_start] + new_cpd + txt[b_end:]

            txt = _prepend_to_method_body(
                txt,
                "CCDisplayFactory::updateParticleDisplay",
                "if (!bone || !display) return;",
                ARMATURE_GUARD_MARKER,
            )

        if txt != orig_txt:
            open(df_cpp, "w", encoding="utf-8", newline="\n").write(txt)
            print(f"[ok] Patched CCDisplayFactory.cpp: {df_cpp}")
        else:
            print(f"[skip] Already patched CCDisplayFactory.cpp: {df_cpp}")

    # 6. UIRichText.cpp: formatText elementRenderer/Widget color fallback, image/custom null guards,
    #    and UTF-8 safe non-infinite recursion in handleTextRenderer when leftLength <= 0.
    rt_cpp = os.path.join(cocos_root, "extensions", "CocoStudio", "GUI", "UIWidgets", "UIRichText.cpp")
    if os.path.exists(rt_cpp):
        txt = open(rt_cpp, "r", encoding="utf-8", errors="replace").read()
        orig_txt = txt
        if RICHTEXT_GUARD_MARKER not in txt:
            txt = re.sub(
                r"(_customNode\s*=\s*customNode\s*;\s*)_customNode\s*->\s*retain\s*\(\s*\)\s*;",
                f"\\1if (_customNode) {{ _customNode->retain(); }} /* {RICHTEXT_GUARD_MARKER} */",
                txt,
                count=1,
            )
            txt = re.sub(
                r"(RichElement\s*\*\s*element\s*=\s*static_cast<RichElement\*>\([^;]+;\s*)",
                f"\\1if (!element) continue; /* {RICHTEXT_GUARD_MARKER} */\n            ",
                txt,
            )
            rgba_re = re.compile(
                r"([ 	]*)CCRGBAProtocol\s*\*\s*colorRenderer\s*=\s*dynamic_cast<CCRGBAProtocol\*>\(\s*elementRenderer\s*\)\s*;\s*"
                r"colorRenderer\s*->\s*setColor\s*\(\s*element->_color\s*\)\s*;\s*"
                r"colorRenderer\s*->\s*setOpacity\s*\(\s*element->_opacity\s*\)\s*;\s*"
                r"pushToContainer\s*\(\s*elementRenderer\s*\)\s*;",
                re.DOTALL,
            )

            def _repl_rgba(m_r: re.Match) -> str:
                ind = m_r.group(1)
                return (
                    f"{ind}/* {RICHTEXT_GUARD_MARKER} */\n"
                    f"{ind}if (!elementRenderer) continue;\n"
                    f"{ind}CCRGBAProtocol* colorRenderer = dynamic_cast<CCRGBAProtocol*>(elementRenderer);\n"
                    f"{ind}if (colorRenderer)\n"
                    f"{ind}{{\n"
                    f"{ind}    colorRenderer->setColor(element->_color);\n"
                    f"{ind}    colorRenderer->setOpacity(element->_opacity);\n"
                    f"{ind}}}\n"
                    f"{ind}else if (Widget* w = dynamic_cast<Widget*>(elementRenderer))\n"
                    f"{ind}{{\n"
                    f"{ind}    w->setColor(element->_color);\n"
                    f"{ind}    w->setOpacity(element->_opacity);\n"
                    f"{ind}}}\n"
                    f"{ind}pushToContainer(elementRenderer);"
                )

            txt = rgba_re.sub(_repl_rgba, txt, count=1)

            for b_start, b_end in reversed(_find_method_body_spans(txt, "RichText::handleImageRenderer")):
                new_hir = (
                    "{\n"
                    f"    // {RICHTEXT_GUARD_MARKER}\n"
                    "    if (!fileParh || !fileParh[0]) return;\n"
                    "    CCSprite* imageRenderer = CCSprite::create(fileParh);\n"
                    "    if (!imageRenderer) return;\n"
                    "    imageRenderer->setColor(color);\n"
                    "    imageRenderer->setOpacity(opacity);\n"
                    "    handleCustomRenderer(imageRenderer);\n"
                    "}"
                )
                txt = txt[:b_start] + new_hir + txt[b_end:]

            txt = _prepend_to_method_body(txt, "RichText::handleCustomRenderer", "if (!renderer) return;", RICHTEXT_GUARD_MARKER)
            txt = _prepend_to_method_body(txt, "RichText::pushToContainer", "if (!renderer) return;", RICHTEXT_GUARD_MARKER)

            for b_start, b_end in reversed(_find_method_body_spans(txt, "RichText::handleTextRenderer")):
                new_htr = (
                    "{\n"
                    f"    // {RICHTEXT_GUARD_MARKER}\n"
                    "    if (!text || !text[0]) return;\n"
                    "    CCLabelTTF* textRenderer = CCLabelTTF::create(text, fontName ? fontName : \"\", fontSize);\n"
                    "    if (!textRenderer) return;\n"
                    "    float textRendererWidth = textRenderer->getContentSize().width;\n"
                    "    if (textRendererWidth <= 0.0f || _customSize.width <= 0.0f)\n"
                    "    {\n"
                    "        textRenderer->setColor(color);\n"
                    "        textRenderer->setOpacity(opacity);\n"
                    "        pushToContainer(textRenderer);\n"
                    "        return;\n"
                    "    }\n"
                    "    bool wasAtLineStart = (_leftSpaceWidth >= _customSize.width - 0.01f);\n"
                    "    _leftSpaceWidth -= textRendererWidth;\n"
                    "    if (_leftSpaceWidth < 0.0f)\n"
                    "    {\n"
                    "        float overstepPercent = (-_leftSpaceWidth) / textRendererWidth;\n"
                    "        std::string curText = text;\n"
                    "        int stringLength = (int)curText.length();\n"
                    "        int leftLength = (int)(stringLength * (1.0f - overstepPercent));\n"
                    "        while (leftLength > 0 && leftLength < stringLength && (((unsigned char)curText[leftLength] & 0xC0) == 0x80))\n"
                    "        {\n"
                    "            --leftLength;\n"
                    "        }\n"
                    "        if (leftLength <= 0)\n"
                    "        {\n"
                    "            if (!wasAtLineStart)\n"
                    "            {\n"
                    "                addNewLine();\n"
                    "                handleTextRenderer(curText.c_str(), fontName, fontSize, color, opacity);\n"
                    "                return;\n"
                    "            }\n"
                    "            // _customSize.width cannot fit even 1 glyph on a fresh line: advance >= 1 UTF-8 codepoint\n"
                    "            // so recursion strictly shrinks curText and NEVER loops infinitely!\n"
                    "            leftLength = 1;\n"
                    "            while (leftLength < stringLength && (((unsigned char)curText[leftLength] & 0xC0) == 0x80))\n"
                    "            {\n"
                    "                ++leftLength;\n"
                    "            }\n"
                    "            if (leftLength >= stringLength)\n"
                    "            {\n"
                    "                textRenderer->setColor(color);\n"
                    "                textRenderer->setOpacity(opacity);\n"
                    "                pushToContainer(textRenderer);\n"
                    "                return;\n"
                    "            }\n"
                    "        }\n"
                    "        std::string leftWords = curText.substr(0, (size_t)leftLength);\n"
                    "        std::string cutWords = curText.substr((size_t)leftLength);\n"
                    "        CCLabelTTF* leftRenderer = CCLabelTTF::create(leftWords.c_str(), fontName ? fontName : \"\", fontSize);\n"
                    "        if (leftRenderer)\n"
                    "        {\n"
                    "            leftRenderer->setColor(color);\n"
                    "            leftRenderer->setOpacity(opacity);\n"
                    "            pushToContainer(leftRenderer);\n"
                    "        }\n"
                    "        addNewLine();\n"
                    "        if (!cutWords.empty())\n"
                    "        {\n"
                    "            handleTextRenderer(cutWords.c_str(), fontName, fontSize, color, opacity);\n"
                    "        }\n"
                    "    }\n"
                    "    else\n"
                    "    {\n"
                    "        textRenderer->setColor(color);\n"
                    "        textRenderer->setOpacity(opacity);\n"
                    "        pushToContainer(textRenderer);\n"
                    "    }\n"
                    "}"
                )
                txt = txt[:b_start] + new_htr + txt[b_end:]

        if txt != orig_txt:
            open(rt_cpp, "w", encoding="utf-8", newline="\n").write(txt)
            print(f"[ok] Patched UIRichText.cpp: {rt_cpp}")
        else:
            print(f"[skip] Already patched UIRichText.cpp: {rt_cpp}")


def patch_spine_skeleton_ndebug(cocos_root: str) -> None:
    spine_dir = os.path.join(cocos_root, "extensions", "spine")

    # 1. CCSkeleton.cpp: guard skeletonData == NULL, skeleton == NULL, and skeleton->boneCount == 0
    skel_cpp = os.path.join(spine_dir, "CCSkeleton.cpp")
    if os.path.exists(skel_cpp):
        txt = open(skel_cpp, "r", encoding="utf-8", errors="replace").read()
        orig_txt = txt
        if SPINE_GUARD_MARKER not in txt:
            for b_start, b_end in reversed(_find_method_body_spans(txt, "CCSkeleton::initialize")):
                body = txt[b_start:b_end]
                txt = txt[:b_start] + _inject_after_open_brace(body, f"// {SPINE_GUARD_MARKER}\n\tskeleton = 0;\n\trootBone = 0;\n\townsSkeletonData = false;", indent="\t") + txt[b_end:]

            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "CCSkeleton::setSkeletonData")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                sd_var = _extract_param_ident(params[0], "skeletonData") if len(params) >= 1 else "skeletonData"
                own_var = _extract_param_ident(params[1], "ownsSkeletonData") if len(params) >= 2 else "ownsSkeletonData"
                new_ssd = (
                    "{\n"
                    f"\t// {SPINE_GUARD_MARKER}\n"
                    f"\tif (!{sd_var}) {{\n"
                    "\t\tskeleton = 0;\n"
                    "\t\trootBone = 0;\n"
                    "\t\tthis->ownsSkeletonData = false;\n"
                    "\t\treturn;\n"
                    "\t}\n"
                    f"\tskeleton = Skeleton_create({sd_var});\n"
                    "\trootBone = (skeleton && skeleton->boneCount > 0 && skeleton->bones) ? skeleton->bones[0] : 0;\n"
                    f"\tthis->ownsSkeletonData = {own_var};\n"
                    "}"
                )
                txt = txt[:b_start] + new_ssd + txt[b_end:]

            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "CCSkeleton::CCSkeleton")):
                sig_inner = txt[p_open + 1:p_close - 1]
                params = _split_top_level_params(sig_inner)
                if len(params) == 0:
                    continue
                if "SkeletonData" in params[0]:
                    sd_var = _extract_param_ident(params[0], "skeletonData")
                    own_var = _extract_param_ident(params[1], "ownsSkeletonData") if len(params) >= 2 else "false"
                    new_ctor = (
                        "{\n"
                        f"\t// {SPINE_GUARD_MARKER}\n"
                        "\tinitialize();\n"
                        f"\tif ({sd_var}) setSkeletonData({sd_var}, {own_var});\n"
                        "}"
                    )
                    txt = txt[:b_start] + new_ctor + txt[b_end:]
                elif len(params) >= 2 and "Atlas" in params[1]:
                    sf_var = _extract_param_ident(params[0], "skeletonDataFile")
                    at_var = _extract_param_ident(params[1], "atlas")
                    sc_var = _extract_param_ident(params[2], "scale") if len(params) >= 3 else "1"
                    new_ctor = (
                        "{\n"
                        f"\t// {SPINE_GUARD_MARKER}\n"
                        "\tinitialize();\n"
                        f"\tif (!{sf_var} || !{at_var}) return;\n"
                        f"\tSkeletonJson* json = SkeletonJson_create({at_var});\n"
                        "\tif (!json) return;\n"
                        f"\tjson->scale = {sc_var};\n"
                        f"\tSkeletonData* skeletonData = SkeletonJson_readSkeletonDataFile(json, {sf_var});\n"
                        "\tSkeletonJson_dispose(json);\n"
                        "\tif (!skeletonData) return;\n"
                        "\tsetSkeletonData(skeletonData, true);\n"
                        "}"
                    )
                    txt = txt[:b_start] + new_ctor + txt[b_end:]
                elif len(params) >= 2 and "char" in params[1]:
                    sf_var = _extract_param_ident(params[0], "skeletonDataFile")
                    af_var = _extract_param_ident(params[1], "atlasFile")
                    sc_var = _extract_param_ident(params[2], "scale") if len(params) >= 3 else "1"
                    new_ctor = (
                        "{\n"
                        f"\t// {SPINE_GUARD_MARKER}\n"
                        "\tinitialize();\n"
                        f"\tif (!{sf_var} || !{af_var}) return;\n"
                        f"\tatlas = Atlas_readAtlasFile({af_var});\n"
                        "\tif (!atlas) return;\n"
                        "\tSkeletonJson* json = SkeletonJson_create(atlas);\n"
                        "\tif (!json) return;\n"
                        f"\tjson->scale = {sc_var};\n"
                        f"\tSkeletonData* skeletonData = SkeletonJson_readSkeletonDataFile(json, {sf_var});\n"
                        "\tSkeletonJson_dispose(json);\n"
                        "\tif (!skeletonData) return;\n"
                        "\tsetSkeletonData(skeletonData, true);\n"
                        "}"
                    )
                    txt = txt[:b_start] + new_ctor + txt[b_end:]

            for b_start, b_end in reversed(_find_method_body_spans(txt, "CCSkeleton::~CCSkeleton")):
                new_dtor = (
                    "{\n"
                    f"\t// {SPINE_GUARD_MARKER}\n"
                    "\tif (ownsSkeletonData && skeleton && skeleton->data) SkeletonData_dispose(skeleton->data);\n"
                    "\tif (atlas) Atlas_dispose(atlas);\n"
                    "\tif (skeleton) Skeleton_dispose(skeleton);\n"
                    "}"
                )
                txt = txt[:b_start] + new_dtor + txt[b_end:]

            txt = _prepend_to_method_body(txt, "CCSkeleton::update", "if (!skeleton) return;", SPINE_GUARD_MARKER)
            txt = _prepend_to_method_body(txt, "CCSkeleton::draw", "if (!skeleton) return;", SPINE_GUARD_MARKER)
            txt = _prepend_to_method_body(
                txt,
                "CCSkeleton::boundingBox",
                "if (!skeleton) return CCRectMake(getPosition().x, getPosition().y, 0, 0);",
                SPINE_GUARD_MARKER,
            )
            txt = _prepend_to_method_body(txt, "CCSkeleton::updateWorldTransform", "if (!skeleton) return;", SPINE_GUARD_MARKER)
            txt = _prepend_to_method_body(txt, "CCSkeleton::setToSetupPose", "if (!skeleton) return;", SPINE_GUARD_MARKER)
            txt = _prepend_to_method_body(txt, "CCSkeleton::setBonesToSetupPose", "if (!skeleton) return;", SPINE_GUARD_MARKER)
            txt = _prepend_to_method_body(txt, "CCSkeleton::setSlotsToSetupPose", "if (!skeleton) return;", SPINE_GUARD_MARKER)
            txt = _prepend_to_method_body(txt, "CCSkeleton::findBone", "if (!skeleton || !boneName) return 0;", SPINE_GUARD_MARKER)
            txt = _prepend_to_method_body(txt, "CCSkeleton::findSlot", "if (!skeleton || !slotName) return 0;", SPINE_GUARD_MARKER)
            txt = _prepend_to_method_body(txt, "CCSkeleton::setSkin", "if (!skeleton) return false;", SPINE_GUARD_MARKER)
            txt = _prepend_to_method_body(txt, "CCSkeleton::getAttachment", "if (!skeleton || !slotName || !attachmentName) return 0;", SPINE_GUARD_MARKER)
            txt = _prepend_to_method_body(txt, "CCSkeleton::setAttachment", "if (!skeleton || !slotName) return false;", SPINE_GUARD_MARKER)
            txt = _prepend_to_method_body(
                txt,
                "CCSkeleton::getTextureAtlas",
                "if (!regionAttachment || !regionAttachment->rendererObject || !((AtlasRegion*)regionAttachment->rendererObject)->page) return 0;",
                SPINE_GUARD_MARKER,
            )

        if txt != orig_txt:
            open(skel_cpp, "w", encoding="utf-8", newline="\n").write(txt)
            print(f"[ok] Patched CCSkeleton.cpp null/boneCount guards: {skel_cpp}")
        else:
            print(f"[skip] Already patched CCSkeleton.cpp null/boneCount guards: {skel_cpp}")

    # 2. CCSkeletonAnimation.cpp: guard skeleton == NULL & state / states across constructors, ~dtor, update, and anim APIs
    skel_anim_cpp = os.path.join(spine_dir, "CCSkeletonAnimation.cpp")
    if os.path.exists(skel_anim_cpp):
        txt = open(skel_anim_cpp, "r", encoding="utf-8", errors="replace").read()
        orig_txt = txt
        if SPINE_GUARD_MARKER not in txt:
            for b_start, b_end in reversed(_find_method_body_spans(txt, "CCSkeletonAnimation::initialize")):
                body = txt[b_start:b_end]
                if "AnimationState_create" in body:
                    new_init = (
                        "{\n"
                        f"\t// {SPINE_GUARD_MARKER}\n"
                        "\tstate = 0;\n"
                        "\townsAnimationStateData = false;\n"
                        "\tif (!skeleton || !skeleton->data) return;\n"
                        "\townsAnimationStateData = true;\n"
                        "\tstate = AnimationState_create(AnimationStateData_create(skeleton->data));\n"
                        "}"
                    )
                    txt = txt[:b_start] + new_init + txt[b_end:]

            for b_start, b_end in reversed(_find_method_body_spans(txt, "CCSkeletonAnimation::~CCSkeletonAnimation")):
                body = txt[b_start:b_end]
                if "ownsAnimationStateData" in body:
                    new_dtor = (
                        "{\n"
                        f"\t// {SPINE_GUARD_MARKER}\n"
                        "\tif (state) {\n"
                        "\t\tif (ownsAnimationStateData && state->data) AnimationStateData_dispose(state->data);\n"
                        "\t\tAnimationState_dispose(state);\n"
                        "\t\tstate = 0;\n"
                        "\t}\n"
                        "}"
                    )
                    txt = txt[:b_start] + new_dtor + txt[b_end:]
                elif "stateDatas" in body:
                    new_dtor = (
                        "{\n"
                        f"\t// {SPINE_GUARD_MARKER}\n"
                        "\tfor (std::vector<AnimationStateData*>::iterator iter = stateDatas.begin(); iter != stateDatas.end(); ++iter)\n"
                        "\t\tif (*iter) AnimationStateData_dispose(*iter);\n"
                        "\tfor (std::vector<AnimationState*>::iterator iter = states.begin(); iter != states.end(); ++iter)\n"
                        "\t\tif (*iter) AnimationState_dispose(*iter);\n"
                        "}"
                    )
                    txt = txt[:b_start] + new_dtor + txt[b_end:]

            for b_start, b_end in reversed(_find_method_body_spans(txt, "CCSkeletonAnimation::addAnimationState")):
                body = txt[b_start:b_end]
                patched = _inject_after_open_brace(body, f"if (!stateData && (!skeleton || !skeleton->data)) return; // {SPINE_GUARD_MARKER}", indent="\t")
                txt = txt[:b_start] + patched + txt[b_end:]

            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "CCSkeletonAnimation::setAnimationStateData")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                body = txt[b_start:b_end]
                if len(params) == 1 and "ownsAnimationStateData" in body:
                    sd_var = _extract_param_ident(params[0], "stateData")
                    new_sasd = (
                        "{\n"
                        f"\t// {SPINE_GUARD_MARKER}\n"
                        f"\tif (!{sd_var}) return;\n"
                        "\tif (state) {\n"
                        "\t\tif (ownsAnimationStateData && state->data) AnimationStateData_dispose(state->data);\n"
                        "\t\tAnimationState_dispose(state);\n"
                        "\t}\n"
                        "\townsAnimationStateData = false;\n"
                        f"\tstate = AnimationState_create({sd_var});\n"
                        "}"
                    )
                    txt = txt[:b_start] + new_sasd + txt[b_end:]
                elif len(params) >= 2 and "states" in body:
                    sd_var = _extract_param_ident(params[0], "stateData")
                    idx_var = _extract_param_ident(params[1], "stateIndex")
                    guard = f"if (!{sd_var} || {idx_var} < 0 || {idx_var} >= (int)states.size()) return; // {SPINE_GUARD_MARKER}"
                    txt = txt[:b_start] + _inject_after_open_brace(body, guard, indent="\t") + txt[b_end:]

            for b_start, b_end in reversed(_find_method_body_spans(txt, "CCSkeletonAnimation::update")):
                body = txt[b_start:b_end]
                if "states" in body:
                    guard = f"if (!skeleton) return; // {SPINE_GUARD_MARKER}"
                else:
                    guard = f"if (!skeleton || !state) return; // {SPINE_GUARD_MARKER}"
                txt = txt[:b_start] + _inject_after_open_brace(body, guard, indent="\t") + txt[b_end:]

            # Guard setMix / setAnimation / addAnimation / clearAnimation / clearTracks / clearTrack
            uses_states_vec = "std::vector<AnimationState*>" in txt or "states[stateIndex]" in txt
            if uses_states_vec:
                for fn_name in ("setMix", "setAnimation", "addAnimation", "clearAnimation"):
                    txt = _prepend_to_method_body(
                        txt,
                        f"CCSkeletonAnimation::{fn_name}",
                        "if (stateIndex < 0 || stateIndex >= (int)states.size() || !states[stateIndex]) return;",
                        SPINE_GUARD_MARKER,
                    )
            else:
                txt = _prepend_to_method_body(txt, "CCSkeletonAnimation::setMix", "if (!state || !state->data) return;", SPINE_GUARD_MARKER)
                txt = _prepend_to_method_body(txt, "CCSkeletonAnimation::setAnimation", "if (!state) return 0;", SPINE_GUARD_MARKER)
                txt = _prepend_to_method_body(txt, "CCSkeletonAnimation::addAnimation", "if (!state) return 0;", SPINE_GUARD_MARKER)
                txt = _prepend_to_method_body(txt, "CCSkeletonAnimation::clearTracks", "if (!state) return;", SPINE_GUARD_MARKER)
                txt = _prepend_to_method_body(txt, "CCSkeletonAnimation::clearTrack", "if (!state) return;", SPINE_GUARD_MARKER)

        if txt != orig_txt:
            open(skel_anim_cpp, "w", encoding="utf-8", newline="\n").write(txt)
            print(f"[ok] Patched CCSkeletonAnimation.cpp: {skel_anim_cpp}")
        else:
            print(f"[skip] Already patched CCSkeletonAnimation.cpp: {skel_anim_cpp}")


def patch_audio_win32(cocos_root: str) -> None:
    audio_dir = os.path.join(cocos_root, "CocosDenshion", "win32")

    # 1. SimpleAudioEngine.cpp: null/empty guards BEFORE _Hash(pszFilePath) & mute/volume tracking
    sae_cpp = os.path.join(audio_dir, "SimpleAudioEngine.cpp")
    if os.path.exists(sae_cpp):
        txt = open(sae_cpp, "r", encoding="utf-8", errors="replace").read()
        orig_txt = txt
        if AUDIO_GUARD_MARKER not in txt:
            vol_state = (
                f"\n// {AUDIO_GUARD_MARKER}\n"
                "static float s_fBackgroundMusicVolume = 1.0f;\n"
                "static float s_fEffectsVolume = 1.0f;\n"
            )
            ns_m = re.search(r"namespace\s+CocosDenshion\s*\{", txt)
            if ns_m:
                txt = txt[:ns_m.end()] + vol_state + txt[ns_m.end():]
            else:
                txt = vol_state + txt

            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "_Hash")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                k_var = _extract_param_ident(params[0], "key") if params else "key"
                body = txt[b_start:b_end]
                txt = txt[:b_start] + _inject_after_open_brace(body, f"if (!{k_var} || !{k_var}[0]) return 0; // {AUDIO_GUARD_MARKER}") + txt[b_end:]

            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "SimpleAudioEngine::playBackgroundMusic")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                f_var = _extract_param_ident(params[0], "pszFilePath") if params else "pszFilePath"
                body = txt[b_start:b_end]
                guard = f"if (!{f_var} || !{f_var}[0] || s_fBackgroundMusicVolume <= 0.0f) return; // {AUDIO_GUARD_MARKER}"
                txt = txt[:b_start] + _inject_after_open_brace(body, guard) + txt[b_end:]

            txt = _prepend_to_method_body(
                txt,
                "SimpleAudioEngine::resumeBackgroundMusic",
                "if (s_fBackgroundMusicVolume <= 0.0f) return;",
                AUDIO_GUARD_MARKER,
            )

            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "SimpleAudioEngine::playEffect")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                f_var = _extract_param_ident(params[0], "pszFilePath") if params else "pszFilePath"
                body = txt[b_start:b_end]
                guard = (
                    f"if (!{f_var} || !{f_var}[0]) return 0; // {AUDIO_GUARD_MARKER}\n"
                    "    if (s_fEffectsVolume <= 0.0f) return 0;"
                )
                txt = txt[:b_start] + _inject_after_open_brace(body, guard) + txt[b_end:]

            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "SimpleAudioEngine::preloadEffect")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                f_var = _extract_param_ident(params[0], "pszFilePath") if params else "pszFilePath"
                body = txt[b_start:b_end]
                guard = f"if (!{f_var} || !{f_var}[0] || s_fEffectsVolume <= 0.0f) return; // {AUDIO_GUARD_MARKER}"
                txt = txt[:b_start] + _inject_after_open_brace(body, guard) + txt[b_end:]

            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "SimpleAudioEngine::unloadEffect")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                f_var = _extract_param_ident(params[0], "pszFilePath") if params else "pszFilePath"
                sig_prefix = txt[max(0, p_open - 80):p_open]
                ret_zero = "return 0;" if "int" in sig_prefix and "void" not in sig_prefix else "return;"
                body = txt[b_start:b_end]
                guard = f"if (!{f_var} || !{f_var}[0]) {ret_zero} // {AUDIO_GUARD_MARKER}"
                txt = txt[:b_start] + _inject_after_open_brace(body, guard) + txt[b_end:]

            txt = _prepend_to_method_body(txt, "SimpleAudioEngine::resumeEffect", "if (s_fEffectsVolume <= 0.0f) return;", AUDIO_GUARD_MARKER)
            txt = _prepend_to_method_body(txt, "SimpleAudioEngine::resumeAllEffects", "if (s_fEffectsVolume <= 0.0f) return;", AUDIO_GUARD_MARKER)

            for b_start, b_end in reversed(_find_method_body_spans(txt, "SimpleAudioEngine::getBackgroundMusicVolume")):
                txt = txt[:b_start] + f"{{\n    return s_fBackgroundMusicVolume; // {AUDIO_GUARD_MARKER}\n}}" + txt[b_end:]

            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "SimpleAudioEngine::setBackgroundMusicVolume")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                v_var = _extract_param_ident(params[0], "volume") if params else "volume"
                new_set_bgm = (
                    "{\n"
                    f"    // {AUDIO_GUARD_MARKER}\n"
                    f"    if ({v_var} < 0.0f) {v_var} = 0.0f;\n"
                    f"    else if ({v_var} > 1.0f) {v_var} = 1.0f;\n"
                    f"    s_fBackgroundMusicVolume = {v_var};\n"
                    "    if (s_fBackgroundMusicVolume <= 0.0f) { sharedMusic().Stop(); }\n"
                    "}"
                )
                txt = txt[:b_start] + new_set_bgm + txt[b_end:]

            for b_start, b_end in reversed(_find_method_body_spans(txt, "SimpleAudioEngine::getEffectsVolume")):
                txt = txt[:b_start] + f"{{\n    return s_fEffectsVolume; // {AUDIO_GUARD_MARKER}\n}}" + txt[b_end:]

            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "SimpleAudioEngine::setEffectsVolume")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                v_var = _extract_param_ident(params[0], "volume") if params else "volume"
                new_set_eff = (
                    "{\n"
                    f"    // {AUDIO_GUARD_MARKER}\n"
                    f"    if ({v_var} < 0.0f) {v_var} = 0.0f;\n"
                    f"    else if ({v_var} > 1.0f) {v_var} = 1.0f;\n"
                    f"    s_fEffectsVolume = {v_var};\n"
                    "    if (s_fEffectsVolume <= 0.0f) { stopAllEffects(); }\n"
                    "}"
                )
                txt = txt[:b_start] + new_set_eff + txt[b_end:]

        if txt != orig_txt:
            open(sae_cpp, "w", encoding="utf-8", newline="\n").write(txt)
            print(f"[ok] Patched SimpleAudioEngine.cpp: {sae_cpp}")
        else:
            print(f"[skip] Already patched SimpleAudioEngine.cpp: {sae_cpp}")

    # 2. MciPlayer.cpp: skip .ogg, decrypt 0xFEFEFEFE into %TEMP%/gclient_audio_cache/, wide mciSendCommandW,
    #    and clear GWLP_USERDATA before Close() in ~MciPlayer().
    mci_cpp = os.path.join(audio_dir, "MciPlayer.cpp")
    if os.path.exists(mci_cpp):
        txt = open(mci_cpp, "r", encoding="utf-8", errors="replace").read()
        orig_txt = txt
        if AUDIO_GUARD_MARKER not in txt:
            mci_helpers = (
                f"// {AUDIO_GUARD_MARKER}\n"
                '#include "cocos2d.h"\n'
                "#include <stdio.h>\n"
                "#include <string.h>\n"
                "#include <wchar.h>\n"
                "#include <string>\n"
                "#ifndef GWLP_USERDATA\n"
                "#define GWLP_USERDATA GWL_USERDATA\n"
                "#endif\n"
                "namespace {\n"
                "static std::wstring gclientAudioToWide(const char* utf8OrAcp) {\n"
                "    if (!utf8OrAcp || !utf8OrAcp[0]) return std::wstring();\n"
                "    int wlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8OrAcp, -1, NULL, 0);\n"
                "    if (wlen > 0) {\n"
                "        std::wstring out((size_t)wlen - 1, L'\\0');\n"
                "        if (wlen > 1) MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8OrAcp, -1, &out[0], wlen);\n"
                "        return out;\n"
                "    }\n"
                "    int alen = MultiByteToWideChar(CP_ACP, 0, utf8OrAcp, -1, NULL, 0);\n"
                "    if (alen > 0) {\n"
                "        std::wstring out((size_t)alen - 1, L'\\0');\n"
                "        if (alen > 1) MultiByteToWideChar(CP_ACP, 0, utf8OrAcp, -1, &out[0], alen);\n"
                "        return out;\n"
                "    }\n"
                "    return std::wstring();\n"
                "}\n"
                "static bool gclientHasOggExtension(const char* p) {\n"
                "    if (!p) return false;\n"
                "    size_t n = strlen(p);\n"
                "    if (n < 4) return false;\n"
                "    const char* ext = p + (n - 4);\n"
                "    return ext[0] == '.' &&\n"
                "           (ext[1] == 'o' || ext[1] == 'O') &&\n"
                "           (ext[2] == 'g' || ext[2] == 'G') &&\n"
                "           (ext[3] == 'g' || ext[3] == 'G');\n"
                "}\n"
                "static unsigned long long gclientFnv1a64(const char* s) {\n"
                "    unsigned long long h = 14695981039346656037ULL;\n"
                "    if (!s) return h;\n"
                "    while (*s) {\n"
                "        unsigned char c = (unsigned char)(*s++);\n"
                "        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c - 'A' + 'a');\n"
                "        if (c == '\\\\') c = '/';\n"
                "        h ^= (unsigned long long)c;\n"
                "        h *= 1099511628211ULL;\n"
                "    }\n"
                "    return h;\n"
                "}\n"
                "static bool gclientPrepareAudioFileWide(const char* pFileName, std::wstring& outWidePath) {\n"
                "    outWidePath = gclientAudioToWide(pFileName);\n"
                "    if (outWidePath.empty()) return false;\n"
                "    FILE* fp = _wfopen(outWidePath.c_str(), L\"rb\");\n"
                "    std::string resolvedUtf8(pFileName);\n"
                "    if (!fp && cocos2d::CCFileUtils::sharedFileUtils()) {\n"
                "        resolvedUtf8 = cocos2d::CCFileUtils::sharedFileUtils()->fullPathForFilename(pFileName);\n"
                "        std::wstring wResolved = gclientAudioToWide(resolvedUtf8.c_str());\n"
                "        if (!wResolved.empty()) {\n"
                "            fp = _wfopen(wResolved.c_str(), L\"rb\");\n"
                "            if (fp) outWidePath = wResolved;\n"
                "        }\n"
                "    }\n"
                "    if (!fp) return false;\n"
                "    unsigned char magic[4] = {0, 0, 0, 0};\n"
                "    size_t nRead = fread(magic, 1, 4, fp);\n"
                "    fclose(fp);\n"
                "    if (!(nRead == 4 && magic[0] == 0xFE && magic[1] == 0xFE && magic[2] == 0xFE && magic[3] == 0xFE)) {\n"
                "        return true;\n"
                "    }\n"
                "    WCHAR tempBuf[MAX_PATH + 1] = {0};\n"
                "    DWORD tLen = GetTempPathW(MAX_PATH, tempBuf);\n"
                "    if (tLen == 0 || tLen > MAX_PATH) return false;\n"
                "    std::wstring cacheDir(tempBuf);\n"
                "    if (!cacheDir.empty() && cacheDir[cacheDir.size() - 1] != L'\\\\' && cacheDir[cacheDir.size() - 1] != L'/') {\n"
                "        cacheDir += L'\\\\';\n"
                "    }\n"
                "    cacheDir += L\"gclient_audio_cache\";\n"
                "    CreateDirectoryW(cacheDir.c_str(), NULL);\n"
                "    std::wstring ext = L\".mp3\";\n"
                "    size_t slash = outWidePath.find_last_of(L\"/\\\\\");\n"
                "    size_t dot = outWidePath.find_last_of(L'.');\n"
                "    if (dot != std::wstring::npos && (slash == std::wstring::npos || dot > slash)) {\n"
                "        ext = outWidePath.substr(dot);\n"
                "    }\n"
                "    wchar_t hexBuf[48] = {0};\n"
                "    swprintf(hexBuf, 48, L\"\\\\snd_%016llx\", gclientFnv1a64(resolvedUtf8.c_str()));\n"
                "    std::wstring cacheFile = cacheDir + hexBuf + ext;\n"
                "    WIN32_FILE_ATTRIBUTE_DATA fad;\n"
                "    if (GetFileAttributesExW(cacheFile.c_str(), GetFileExInfoStandard, &fad) &&\n"
                "        !(fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&\n"
                "        (fad.nFileSizeHigh > 0 || fad.nFileSizeLow > 4)) {\n"
                "        outWidePath = cacheFile;\n"
                "        return true;\n"
                "    }\n"
                "    if (!cocos2d::CCFileUtils::sharedFileUtils()) return false;\n"
                "    unsigned long decSize = 0;\n"
                "    unsigned char* decBytes = cocos2d::CCFileUtils::sharedFileUtils()->getFileData(resolvedUtf8.c_str(), \"rb\", &decSize);\n"
                "    if (!decBytes || decSize == 0) {\n"
                "        delete[] decBytes;\n"
                "        return false;\n"
                "    }\n"
                "    if (decSize >= 4 && decBytes[0] == 0xFE && decBytes[1] == 0xFE && decBytes[2] == 0xFE && decBytes[3] == 0xFE) {\n"
                "        delete[] decBytes;\n"
                "        return false;\n"
                "    }\n"
                "    wchar_t tidBuf[32] = {0};\n"
                "    swprintf(tidBuf, 32, L\".%lu.tmp\", (unsigned long)GetCurrentThreadId());\n"
                "    std::wstring tmpFile = cacheFile + tidBuf;\n"
                "    FILE* outFp = _wfopen(tmpFile.c_str(), L\"wb\");\n"
                "    if (!outFp) {\n"
                "        delete[] decBytes;\n"
                "        return false;\n"
                "    }\n"
                "    size_t written = fwrite(decBytes, 1, (size_t)decSize, outFp);\n"
                "    fclose(outFp);\n"
                "    delete[] decBytes;\n"
                "    if (written != (size_t)decSize) {\n"
                "        DeleteFileW(tmpFile.c_str());\n"
                "        return false;\n"
                "    }\n"
                "    if (!MoveFileExW(tmpFile.c_str(), cacheFile.c_str(), MOVEFILE_REPLACE_EXISTING)) {\n"
                "        DeleteFileW(tmpFile.c_str());\n"
                "        if (GetFileAttributesW(cacheFile.c_str()) == INVALID_FILE_ATTRIBUTES) return false;\n"
                "    }\n"
                "    outWidePath = cacheFile;\n"
                "    return true;\n"
                "}\n"
                "}\n"
            )
            txt = _insert_before_ns_cc_begin(txt, mci_helpers)

            for b_start, b_end in reversed(_find_method_body_spans(txt, "MciPlayer::~MciPlayer")):
                new_dtor = (
                    "{\n"
                    f"    // {AUDIO_GUARD_MARKER}\n"
                    "    if (m_hWnd)\n"
                    "    {\n"
                    "        SetWindowLongPtr(m_hWnd, GWLP_USERDATA, 0);\n"
                    "    }\n"
                    "    Close();\n"
                    "    if (m_hWnd)\n"
                    "    {\n"
                    "        DestroyWindow(m_hWnd);\n"
                    "        m_hWnd = NULL;\n"
                    "    }\n"
                    "}"
                )
                txt = txt[:b_start] + new_dtor + txt[b_end:]

            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "MciPlayer::Open")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                f_var = _extract_param_ident(params[0], "pFileName") if len(params) >= 1 else "pFileName"
                id_var = _extract_param_ident(params[1], "uId") if len(params) >= 2 else "uId"
                new_open = (
                    "{\n"
                    f"    // {AUDIO_GUARD_MARKER}\n"
                    "    do\n"
                    "    {\n"
                    f"        BREAK_IF(!{f_var} || !{f_var}[0] || !m_hWnd);\n"
                    "        Close();\n"
                    "        m_nSoundID = 0;\n"
                    f"        BREAK_IF(gclientHasOggExtension({f_var}));\n"
                    "        std::wstring wElementPath;\n"
                    f"        BREAK_IF(!gclientPrepareAudioFileWide({f_var}, wElementPath));\n"
                    "        MCI_OPEN_PARMSW mciOpen = {0};\n"
                    "        mciOpen.lpstrDeviceType = (LPCWSTR)MCI_ALL_DEVICE_ID;\n"
                    "        mciOpen.lpstrElementName = wElementPath.c_str();\n"
                    "        MCIERROR mciError = mciSendCommandW(0, MCI_OPEN, MCI_OPEN_ELEMENT, reinterpret_cast<DWORD_PTR>(&mciOpen));\n"
                    "        BREAK_IF(mciError);\n"
                    "        m_hDev = mciOpen.wDeviceID;\n"
                    f"        m_nSoundID = {id_var};\n"
                    "        m_bPlaying = false;\n"
                    "    } while (0);\n"
                    "}"
                )
                txt = txt[:b_start] + new_open + txt[b_end:]

        if txt != orig_txt:
            open(mci_cpp, "w", encoding="utf-8", newline="\n").write(txt)
            print(f"[ok] Patched MciPlayer.cpp: {mci_cpp}")
        else:
            print(f"[skip] Already patched MciPlayer.cpp: {mci_cpp}")


def patch_lua_stack_and_tolua(cocos_root: str) -> None:
    # 1. CCLuaStack.cpp: check if (!objectValue) { lua_pushnil(m_state); return; } BEFORE objectValue->m_uID
    luastack_cpp = os.path.join(cocos_root, "scripting", "lua", "cocos2dx_support", "CCLuaStack.cpp")
    if os.path.exists(luastack_cpp):
        txt = open(luastack_cpp, "r", encoding="utf-8", errors="replace").read()
        orig_txt = txt
        if LUA_GUARD_MARKER not in txt:
            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "CCLuaStack::pushCCObject")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                obj_var = _extract_param_ident(params[0], "objectValue") if params else "objectValue"
                body = txt[b_start:b_end]
                guard = f"if (!{obj_var}) {{ lua_pushnil(m_state); return; }} // {LUA_GUARD_MARKER}"
                txt = txt[:b_start] + _inject_after_open_brace(body, guard) + txt[b_end:]

            for p_open, p_close, b_start, b_end in reversed(_find_method_spans_with_sig(txt, "CCLuaStack::removeScriptObjectByCCObject")):
                params = _split_top_level_params(txt[p_open + 1:p_close - 1])
                obj_var = _extract_param_ident(params[0], "pObj") if params else "pObj"
                body = txt[b_start:b_end]
                guard = f"if (!{obj_var}) return; // {LUA_GUARD_MARKER}"
                txt = txt[:b_start] + _inject_after_open_brace(body, guard) + txt[b_end:]

        if txt != orig_txt:
            open(luastack_cpp, "w", encoding="utf-8", newline="\n").write(txt)
            print(f"[ok] Patched CCLuaStack.cpp: {luastack_cpp}")
        else:
            print(f"[skip] Already patched CCLuaStack.cpp: {luastack_cpp}")

    # 2. tolua_push.c: push nil (1 value) when luaL_getmetatable returns non-table, preventing stack underflow!
    tolua_push_c = os.path.join(cocos_root, "scripting", "lua", "tolua", "tolua_push.c")
    if os.path.exists(tolua_push_c):
        txt = open(tolua_push_c, "r", encoding="utf-8", errors="replace").read()
        orig_txt = txt
        if LUA_GUARD_MARKER not in txt:
            txt = re.sub(
                r"if\s*\(\s*value\s*==\s*NULL\s*\)\s*lua_pushnil\s*\(\s*L\s*\)\s*;",
                f"if (value == NULL || type == NULL) /* {LUA_GUARD_MARKER} */\n        lua_pushnil(L);",
                txt,
                count=1,
            )
            mt_re = re.compile(
                r"if\s*\(\s*lua_isnil\s*\(\s*L\s*,\s*-1\s*\)\s*\)\s*\{[^}]*lua_pop\s*\(\s*L\s*,\s*1\s*\)\s*;\s*return\s*;\s*\}",
                re.DOTALL,
            )
            mt_fix = (
                f"if (!lua_istable(L, -1)) {{ /* {LUA_GUARD_MARKER}: NOT FOUND metatable */\n"
                "            lua_pop(L, 1);\n"
                "            lua_pushnil(L);\n"
                "            return;\n"
                "        }"
            )
            txt = mt_re.sub(mt_fix, txt, count=1)

            txt = txt.replace(
                "tolua_register_gc(L,lua_gettop(L));",
                f"if (lua_isuserdata(L, -1)) tolua_register_gc(L, lua_gettop(L)); /* {LUA_GUARD_MARKER} */",
            )

        if txt != orig_txt:
            open(tolua_push_c, "w", encoding="utf-8", newline="\n").write(txt)
            print(f"[ok] Patched tolua_push.c: {tolua_push_c}")
        else:
            print(f"[skip] Already patched tolua_push.c: {tolua_push_c}")

def patch_null_texture_guards(cocos_root: str) -> None:
    """Guard against NULL CCTexture2D/PVR dereferences, Button anchor title offsets, and Win32 cell-height fonts."""
    marker = "GCLIENT_NULL_TEX_GUARD"
    targets = [
        (
            os.path.join(cocos_root, "cocos2dx", "base_nodes", "CCAtlasNode.cpp"),
            [
                (
                    "if (!m_pTextureAtlas->getTexture()->hasPremultipliedAlpha())",
                    f"if (!m_pTextureAtlas || !m_pTextureAtlas->getTexture() || !m_pTextureAtlas->getTexture()->hasPremultipliedAlpha()) // {marker}",
                ),
                (
                    "if (m_pTextureAtlas->getTexture()->hasPremultipliedAlpha())",
                    f"if (m_pTextureAtlas && m_pTextureAtlas->getTexture() && m_pTextureAtlas->getTexture()->hasPremultipliedAlpha()) // {marker}",
                ),
            ],
        ),
        (
            os.path.join(cocos_root, "cocos2dx", "label_nodes", "CCLabelBMFont.cpp"),
            [
                (
                    "bool bOpacityModifyRGB = m_pobTextureAtlas->getTexture()->hasPremultipliedAlpha();",
                    f"bool bOpacityModifyRGB = (m_pobTextureAtlas && m_pobTextureAtlas->getTexture()) ? m_pobTextureAtlas->getTexture()->hasPremultipliedAlpha() : false; // {marker}",
                ),
            ],
        ),
        (
            os.path.join(cocos_root, "cocos2dx", "particle_nodes", "CCParticleBatchNode.cpp"),
            [
                (
                    "if( texture && ! texture->hasPremultipliedAlpha() )",
                    f"if( texture && ! texture->hasPremultipliedAlpha() ) // {marker}",
                ),
                (
                    "if( ! m_pTextureAtlas->getTexture()->hasPremultipliedAlpha() )",
                    f"if( ! m_pTextureAtlas || ! m_pTextureAtlas->getTexture() || ! m_pTextureAtlas->getTexture()->hasPremultipliedAlpha() ) // {marker}",
                ),
            ],
        ),
        (
            os.path.join(cocos_root, "cocos2dx", "sprite_nodes", "CCSpriteBatchNode.cpp"),
            [
                (
                    "if( ! m_pobTextureAtlas->getTexture()->hasPremultipliedAlpha() )",
                    f"if( ! m_pobTextureAtlas || ! m_pobTextureAtlas->getTexture() || ! m_pobTextureAtlas->getTexture()->hasPremultipliedAlpha() ) // {marker}",
                ),
                (
                    '    CCAssert(pSprite->getTexture()->getName() == m_pobTextureAtlas->getTexture()->getName(), "");',
                    f'    if (!pSprite->getTexture() || !m_pobTextureAtlas || !m_pobTextureAtlas->getTexture()) return; // {marker}\n    CCAssert(pSprite->getTexture()->getName() == m_pobTextureAtlas->getTexture()->getName(), "");',
                ),
            ],
        ),
        (
            os.path.join(cocos_root, "extensions", "GUI", "CCControlExtension", "CCScale9Sprite.cpp"),
            [
                (
                    "    CC_SAFE_RELEASE(this->_centre);\n"
                    "    CC_SAFE_RELEASE(this->_top);\n"
                    "    CC_SAFE_RELEASE(this->_topLeft);\n"
                    "    CC_SAFE_RELEASE(this->_topRight);\n"
                    "    CC_SAFE_RELEASE(this->_left);\n"
                    "    CC_SAFE_RELEASE(this->_right);\n"
                    "    CC_SAFE_RELEASE(this->_bottomLeft);\n"
                    "    CC_SAFE_RELEASE(this->_bottom);\n"
                    "    CC_SAFE_RELEASE(this->_bottomRight);\n\n    \n"
                    "    if(this->_scale9Image != batchnode)",
                    f"    CC_SAFE_RELEASE_NULL(this->_centre); // {marker}\n"
                    "    CC_SAFE_RELEASE_NULL(this->_top);\n"
                    "    CC_SAFE_RELEASE_NULL(this->_topLeft);\n"
                    "    CC_SAFE_RELEASE_NULL(this->_topRight);\n"
                    "    CC_SAFE_RELEASE_NULL(this->_left);\n"
                    "    CC_SAFE_RELEASE_NULL(this->_right);\n"
                    "    CC_SAFE_RELEASE_NULL(this->_bottomLeft);\n"
                    "    CC_SAFE_RELEASE_NULL(this->_bottom);\n"
                    "    CC_SAFE_RELEASE_NULL(this->_bottomRight);\n\n"
                    "    if (!batchnode || !batchnode->getTextureAtlas() || !batchnode->getTextureAtlas()->getTexture())\n"
                    "    {\n"
                    "        CC_SAFE_RELEASE_NULL(this->_scale9Image);\n"
                    "        return false;\n"
                    "    }\n\n"
                    "    if(this->_scale9Image != batchnode)",
                ),
                (
                    "void CCScale9Sprite::setSpriteFrame(CCSpriteFrame * spriteFrame)\n{\n    CCSpriteBatchNode * batchnode = CCSpriteBatchNode::createWithTexture(spriteFrame->getTexture(), 9);",
                    f"void CCScale9Sprite::setSpriteFrame(CCSpriteFrame * spriteFrame)\n{{\n    if (!spriteFrame) return; // {marker}\n    CCSpriteBatchNode * batchnode = CCSpriteBatchNode::createWithTexture(spriteFrame->getTexture(), 9);",
                ),
            ],
        ),
        (
            os.path.join(cocos_root, "extensions", "CocoStudio", "GUI", "UIWidgets", "UIButton.cpp"),
            [
                (
                    "void Button::onSizeChanged()\n{\n    Widget::onSizeChanged();\n    normalTextureScaleChangedWithSize();\n    pressedTextureScaleChangedWithSize();\n    disabledTextureScaleChangedWithSize();\n}",
                    f"void Button::onSizeChanged() // {marker}\n{{\n    Widget::onSizeChanged();\n    normalTextureScaleChangedWithSize();\n    pressedTextureScaleChangedWithSize();\n    disabledTextureScaleChangedWithSize();\n    if (_titleRenderer) _titleRenderer->setPosition(CCPoint(_size.width*(0.5f-m_obAnchorPoint.x), _size.height*(0.5f-m_obAnchorPoint.y)));\n}}",
                ),
            ],
        ),
        (
            os.path.join(cocos_root, "cocos2dx", "textures", "CCTexturePVR.cpp"),
            [
                (
                    "    header = (ccPVRv2TexHeader *)data;",
                    f"    if (!data || len < sizeof(ccPVRv2TexHeader)) return false; // {marker}\n    header = (ccPVRv2TexHeader *)data;",
                ),
                (
                    "    if (pvrlen < 0)\n    {\n        this->release();\n        return false;\n    }",
                    f"    if (pvrlen <= 0 || !pvrdata) // {marker}\n    {{\n        this->release();\n        return false;\n    }}",
                ),
            ],
        ),
        (
            os.path.join(cocos_root, "cocos2dx", "platform", "win32", "CCImage.cpp"),
            [
                (
                    "            if (nSize)\n            {\n                tNewFont.lfHeight = -nSize;\n            }",
                    f"            if (nSize) // {marker}\n            {{\n                tNewFont.lfHeight = nSize;\n            }}",
                ),
            ],
        ),
    ]
    for path, reps in targets:
        if not os.path.exists(path):
            continue
        txt = open(path, "r", encoding="utf-8", errors="replace").read()
        if marker in txt:
            print(f"[skip] Null-texture guard already patched: {path}")
            continue
        orig = txt
        for old, new in reps:
            if old in txt:
                txt = txt.replace(old, new)
        if txt != orig:
            open(path, "w", encoding="utf-8", newline="\n").write(txt)
            print(f"[ok] Applied null-texture guard: {path}")


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python patch_cocos2dx.py <path_to_cocos2d-x-2.2.6>")
        return 1
    cocos_root = sys.argv[1]
    hdr = os.path.join(cocos_root, "cocos2dx", "platform", "CCFileUtils.h")
    cpp = os.path.join(cocos_root, "cocos2dx", "platform", "CCFileUtils.cpp")
    win_cpp = os.path.join(cocos_root, "cocos2dx", "platform", "win32", "CCFileUtilsWin32.cpp")
    pthread_h = os.path.join(cocos_root, "cocos2dx", "platform", "third_party", "win32", "pthread", "pthread.h")
    stdc_cpp = os.path.join(cocos_root, "cocos2dx", "platform", "win32", "CCStdC.cpp")
    stdc_h = os.path.join(cocos_root, "cocos2dx", "platform", "win32", "CCStdC.h")
    for p in (hdr, cpp):
        if not os.path.exists(p):
            print(f"[error] Missing expected Cocos2d-x file: {p}")
            return 2
    patch_header(hdr)
    patch_cpp(cpp)
    if os.path.exists(win_cpp):
        patch_cpp(win_cpp)
    patch_pthread_header(pthread_h)
    patch_stdc_iob(stdc_cpp)
    patch_stdc_h(stdc_h)
    patch_chipmunk(os.path.join(cocos_root, "external", "chipmunk", "src", "chipmunk.c"))
    patch_image_common_and_legacy_dlls(cocos_root)
    patch_lua_loader(cocos_root)
    patch_lua_stack_and_tolua(cocos_root)
    patch_etc1_and_textures(cocos_root)
    patch_clipping_node(cocos_root)
    patch_spine_and_gui(cocos_root)
    patch_spine_2x_mesh_and_ffd(cocos_root)
    patch_spine_skeleton_ndebug(cocos_root)
    patch_node_sprite_actions_particles(cocos_root)
    patch_armature_and_richtext(cocos_root)
    patch_audio_win32(cocos_root)
    patch_null_texture_guards(cocos_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
