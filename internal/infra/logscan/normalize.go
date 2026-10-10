package logscan

import (
	"encoding/base64"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Transform 是单个变换函数：输入输出都是字符串，不得修改入参语义（Go 字符串本就不可变）。
type Transform func(string) string

// TransformRegistry 是变换表。名字与规则文件里的写法保持一致，
// 这样从 WAF 规则搬过来的 transforms 链可以直接用。
var TransformRegistry = map[string]Transform{
	"none":               func(s string) string { return s },
	"trim":               strings.TrimSpace,
	"lowercase":          strings.ToLower,
	"uppercase":          strings.ToUpper,
	"urlDecode":          urlDecodeOnce,
	"urlDecodeUni":       urlDecodeUni,
	"htmlEntityDecode":   htmlDecode,
	"jsDecode":           jsDecode,
	"cssDecode":          cssDecode,
	"sqlHexDecode":       sqlHexDecode,
	"replaceComments":    commentsToSpace,
	"removeComments":     commentsRemove,
	"compressWhitespace": compressWhitespace,
	"normalizeIFS":       ifsToSpace,
	"expandShellVars":    expandShellVars,
	"removeShellQuotes":  removeShellQuotes,
	"removeShellEscapes": removeShellEscapes,
	"removeNulls":        removeNulls,
	"normalizePath":      normalizePath,
	"base64Decode":       base64Decode,
	"hexDecode":          hexDecode,
}

// UnknownTransforms 记录从规则里读到但本版本没实现的变换名（供启动时提示）。
var UnknownTransforms = map[string]bool{}

// ChainFromNames 把变换名列表解析成函数链，同时返回实际生效的变换名
// （与返回的链一一对应）。未实现的变换会被跳过并记进 UnknownTransforms ——
// 跳过会导致漏检，所以调用方应当把这份清单暴露出来，让人知道哪些规则打了折扣。
func ChainFromNames(names []string) ([]Transform, []string) {
	chain := make([]Transform, 0, len(names))
	used := make([]string, 0, len(names))
	for _, n := range names {
		name := strings.TrimSpace(n)
		if name == "" {
			continue
		}
		if fn, ok := TransformRegistry[name]; ok {
			chain = append(chain, fn)
			used = append(used, name)
			continue
		}
		UnknownTransforms[name] = true
	}
	return chain, used
}

// ApplyChain 依次应用变换链。
func ApplyChain(s string, chain []Transform) string {
	out := s
	for _, fn := range chain {
		out = fn(out)
	}
	return out
}

// DefaultTransformNames 是内置规则使用的默认变换链，等价于早期版本里写死的那一套。
var DefaultTransformNames = []string{
	"urlDecode", "urlDecode", "htmlEntityDecode", "jsDecode",
	"normalizeIFS", "replaceComments", "compressWhitespace", "lowercase",
}

// DefaultChain 是上面这套名字编译出来的链。
var DefaultChain, _ = ChainFromNames(DefaultTransformNames)

// Normalize 用默认链归一化，并返回实际改动过的变换名（用于标记"解码后才命中"）。
func Normalize(line string) (string, []string) {
	names := []string{"urlDecode", "urlDecode", "htmlEntityDecode", "jsDecode",
		"normalizeIFS", "replaceComments", "compressWhitespace", "lowercase"}
	steps := []Transform{urlDecodeOnce, urlDecodeOnce, htmlDecode, jsDecode,
		ifsToSpace, commentsToSpace, compressWhitespace, strings.ToLower}

	used := make([]string, 0, 4)
	out := line
	for i, fn := range steps {
		v := fn(out)
		if v != out {
			out = v
			used = append(used, names[i])
		}
	}
	return out, used
}

// ---------- 编码解码 ----------

// urlDecodeOnce 做一次 URL 解码。用 PathUnescape 而不是 QueryUnescape：
// 后者会把 + 当空格，而日志里 + 很常见。
func urlDecodeOnce(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	if decoded, err := url.PathUnescape(s); err == nil {
		return decoded
	}
	return partialURLDecode(s)
}

var pctRe = regexp.MustCompile(`%[0-9a-fA-F]{2}`)

func partialURLDecode(s string) string {
	return pctRe.ReplaceAllStringFunc(s, func(m string) string {
		hi, ok1 := unhexByte(m[1])
		lo, ok2 := unhexByte(m[2])
		if !ok1 || !ok2 {
			return m
		}
		return string([]byte{hi<<4 | lo})
	})
}

// urlDecodeUni 处理 IIS 风格的 %u0041。
var uniPctRe = regexp.MustCompile(`%u([0-9a-fA-F]{4})`)

func urlDecodeUni(s string) string {
	if !strings.Contains(s, "%u") && !strings.Contains(s, "%U") {
		s = urlDecodeOnce(s)
		return s
	}
	return uniPctRe.ReplaceAllStringFunc(s, func(m string) string {
		hi, ok1 := unhexByte(m[2])
		h2, ok2 := unhexByte(m[3])
		l1, ok3 := unhexByte(m[4])
		l2, ok4 := unhexByte(m[5])
		if !ok1 || !ok2 || !ok3 || !ok4 {
			return m
		}
		return string(rune(hi)<<12 | rune(h2)<<8 | rune(l1)<<4 | rune(l2))
	})
}

func unhexByte(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

var htmlEntityReplacer = strings.NewReplacer(
	"&lt;", "<", "&gt;", ">", "&quot;", "\"", "&apos;", "'", "&#39;", "'", "&#x27;", "'",
	"&sol;", "/", "&#x2f;", "/", "&#47;", "/", "&colon;", ":", "&num;", "#", "&percnt;", "%",
	"&equals;", "=", "&quest;", "?", "&semi;", ";", "&plus;", "+", "&comma;", ",",
	"&period;", ".", "&lpar;", "(", "&rpar;", ")", "&commat;", "@", "&nbsp;", " ",
	"&amp;", "&",
)

// numericEntityRe 处理 &#9; / &#x27; 这类数字实体。
// 少了这一步，像 java&#9;script: 这种靠制表符拆开伪协议的写法就漏了。
var numericEntityRe = regexp.MustCompile(`&#(x?)([0-9a-fA-F]{1,7});?`)

func htmlDecode(s string) string {
	if !strings.Contains(s, "&") {
		return s
	}
	s = htmlEntityReplacer.Replace(s)
	if !strings.Contains(s, "&#") {
		return s
	}
	return numericEntityRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := numericEntityRe.FindStringSubmatch(m)
		if sub == nil {
			return m
		}
		base := 10
		if sub[1] != "" {
			base = 16
		}
		v, err := strconv.ParseUint(sub[2], base, 32)
		if err != nil || v == 0 || v > 0x10FFFF {
			return m
		}
		return string(rune(v))
	})
}

var (
	jsHexRe  = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	jsUniRe  = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
	cssHexRe = regexp.MustCompile(`\\([0-9a-fA-F]{1,6})\s?`)
)

func jsDecode(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	if strings.Contains(s, `\x`) {
		s = jsHexRe.ReplaceAllStringFunc(s, func(m string) string {
			hi, ok1 := unhexByte(m[2])
			lo, ok2 := unhexByte(m[3])
			if !ok1 || !ok2 {
				return m
			}
			return string([]byte{hi<<4 | lo})
		})
	}
	if strings.Contains(s, `\u`) {
		s = jsUniRe.ReplaceAllStringFunc(s, func(m string) string {
			hi, _ := unhexByte(m[2])
			h2, _ := unhexByte(m[3])
			l1, _ := unhexByte(m[4])
			l2, _ := unhexByte(m[5])
			return string(rune(hi)<<12 | rune(h2)<<8 | rune(l1)<<4 | rune(l2))
		})
	}
	return s
}

// cssDecode 处理 \41 这类 CSS 转义。
func cssDecode(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	return cssHexRe.ReplaceAllStringFunc(s, func(m string) string {
		hex := strings.TrimLeft(m[1:], " ")
		hex = strings.TrimSuffix(hex, " ")
		if len(hex) > 6 {
			hex = hex[len(hex)-6:]
		}
		v, err := parseHexUint(hex)
		if err != nil || v == 0 || v > 0x10FFFF {
			return m
		}
		return string(rune(v))
	})
}

// sqlHexDecode 解 0x414243 与 X'414243' 这类十六进制字面量。
var (
	sqlHexLitRe = regexp.MustCompile(`(?i)\b0x([0-9a-f]{2,})\b`)
	sqlXHexRe   = regexp.MustCompile(`(?i)\bX'([0-9a-f]+)'`)
)

func sqlHexDecode(s string) string {
	if !strings.Contains(s, "0x") && !strings.Contains(s, "0X") &&
		!strings.Contains(s, "X'") && !strings.Contains(s, "x'") {
		return s
	}
	s = sqlHexLitRe.ReplaceAllStringFunc(s, func(m string) string {
		if dec, ok := hexToASCII(m[2:]); ok {
			return dec
		}
		return m
	})
	s = sqlXHexRe.ReplaceAllStringFunc(s, func(m string) string {
		start := strings.IndexByte(m, '\'')
		if start < 0 || !strings.HasSuffix(m, "'") {
			return m
		}
		if dec, ok := hexToASCII(m[start+1 : len(m)-1]); ok {
			return dec
		}
		return m
	})
	return s
}

// hexDecode 处理纯十六进制串（尽量保守：长度偶数且全部是十六进制字符）。
func hexDecode(s string) string {
	trimmed := strings.TrimSpace(s)
	if len(trimmed) < 4 || len(trimmed)%2 != 0 || len(trimmed) > 4096 {
		return s
	}
	for i := 0; i < len(trimmed); i++ {
		if _, ok := unhexByte(trimmed[i]); !ok {
			return s
		}
	}
	if dec, ok := hexToASCII(trimmed); ok {
		return dec
	}
	return s
}

func hexToASCII(h string) (string, bool) {
	if len(h) == 0 || len(h)%2 != 0 {
		return "", false
	}
	out := make([]byte, 0, len(h)/2)
	for i := 0; i+1 < len(h); i += 2 {
		hi, ok1 := unhexByte(h[i])
		lo, ok2 := unhexByte(h[i+1])
		if !ok1 || !ok2 {
			return "", false
		}
		out = append(out, hi<<4|lo)
	}
	// 全不可打印就不还原，避免把普通文本搅乱
	printable := 0
	for _, b := range out {
		if b >= 0x20 && b < 0x7f {
			printable++
		}
	}
	if printable*2 < len(out) {
		return "", false
	}
	return string(out), true
}

func parseHexUint(h string) (uint32, error) {
	var v uint32
	for i := 0; i < len(h); i++ {
		b, ok := unhexByte(h[i])
		if !ok {
			return 0, errInvalid
		}
		v = v<<4 | uint32(b)
	}
	return v, nil
}

type constError string

func (e constError) Error() string { return string(e) }

const errInvalid = constError("invalid hex")

// ---------- 结构化清洗 ----------

// expandShellVars 展开常见 shell 变量（命令注入里用来绕过空白与关键字过滤）。
var shellVarReplacer = strings.NewReplacer(
	"${IFS}", " ", "$IFS", " ", "${IFS%}", " ",
	"${PATH:0:1}", "/", "$PATH", "/usr/bin:/bin",
	"${HOME}", "/root", "$HOME", "/root",
	"${PWD}", "/", "$PWD", "/",
	"$9", "", "${9}", "",
)

func expandShellVars(s string) string {
	if !strings.Contains(s, "$") {
		return s
	}
	s = shellVarReplacer.Replace(s)
	s = ifsToSpace(s)
	return s
}

var ifsRe = regexp.MustCompile(`\$\{?IFS\}?[0-9]?`)

func ifsToSpace(s string) string {
	if !strings.Contains(s, "IFS") {
		return s
	}
	return ifsRe.ReplaceAllString(s, " ")
}

var blockCommentRe = regexp.MustCompile(`/\*[\s\S]*?\*/`)

// commentsToSpace 把块注释换成空格（不是删除）：union/**/select 要变成 "union select"。
func commentsToSpace(s string) string {
	if !strings.Contains(s, "/*") {
		return s
	}
	return blockCommentRe.ReplaceAllString(s, " ")
}

// commentsRemove 直接删掉块注释（少数规则要的是这个语义）。
func commentsRemove(s string) string {
	if !strings.Contains(s, "/*") {
		return s
	}
	return blockCommentRe.ReplaceAllString(s, "")
}

var wsRe = regexp.MustCompile(`[\s\x00]+`)

func compressWhitespace(s string) string {
	return wsRe.ReplaceAllString(strings.TrimSpace(s), " ")
}

func removeNulls(s string) string {
	if !strings.ContainsRune(s, 0) {
		return s
	}
	return strings.ReplaceAll(s, "\x00", "")
}

var shellQuoteRe = regexp.MustCompile(`["']`)

// removeShellQuotes 去掉引号：cat "/etc/passwd" 与 cat /etc/passwd 等价。
func removeShellQuotes(s string) string {
	if !strings.ContainsAny(s, `"'`) {
		return s
	}
	return shellQuoteRe.ReplaceAllString(s, "")
}

// Go 的 RE2 不支持前瞻，所以不用 \\(?=x) 写法，改成捕获后回填。
var shellEscapeRe = regexp.MustCompile(`\\([A-Za-z/.\-_])`)

// removeShellEscapes 去掉反斜杠转义：c\at /et\c/passwd 还原成 cat /etc/passwd。
func removeShellEscapes(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	return shellEscapeRe.ReplaceAllString(s, "$1")
}

// normalizePath 归一化路径：压掉重复斜杠、消掉 ./ 与 foo/.. 。
func normalizePath(s string) string {
	if !strings.Contains(s, "/") {
		return s
	}
	out := strings.ReplaceAll(s, "//", "/")
	for strings.Contains(out, "/./") {
		out = strings.ReplaceAll(out, "/./", "/")
	}
	for i := 0; i < 16; i++ {
		idx := strings.Index(out, "/../")
		if idx < 0 {
			break
		}
		// 往前找上一段
		prev := strings.LastIndex(out[:idx], "/")
		if prev < 0 {
			out = strings.Replace(out, "/../", "/", 1)
			continue
		}
		out = out[:prev] + out[idx+3:]
	}
	return out
}

func base64Decode(s string) string {
	trimmed := strings.TrimSpace(s)
	if len(trimmed) < 8 {
		return s
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		dec, err := enc.DecodeString(trimmed)
		if err != nil || len(dec) == 0 {
			continue
		}
		printable := 0
		for _, b := range dec {
			if (b >= 0x20 && b < 0x7f) || b == '\n' || b == '\t' {
				printable++
			}
		}
		if printable*2 >= len(dec) {
			return string(dec)
		}
	}
	return s
}
