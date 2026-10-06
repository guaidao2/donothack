package parser

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"

	"donothack/internal/tx"
)

// ReadBodyForInspection 读取请求体用于检测，同时**保住转发所需的原始字节**。
//
// 这里有个容易做错的地方：如果为了检测而解压了 body，就**不能**把解压后的内容
// 转发给上游 —— 上游要的是原始的压缩字节。所以本函数返回两份：
//   - raw：原始（未解压）前缀，会被重新接到 r.Body 前面，保证代理转发语义不变
//   - inspect：真正参与检测的字节（必要时解压后的）
//
// 只缓冲到 maxRaw 字节；超出部分标记 truncated，但不影响转发（剩余部分照常流式转发）。
func ReadBodyForInspection(r *http.Request, sc *Scratch, maxRaw int) (raw, inspect []byte, truncated bool, errs []string) {
	if r.Body == nil || maxRaw <= 0 {
		return nil, nil, false, nil
	}

	sc.Body = sc.Body[:0]
	if cap(sc.Body) < maxRaw+1 {
		sc.Body = make([]byte, 0, maxRaw+1)
	}
	buf := sc.Body

	// 最多读 maxRaw+1 字节：多读的那一个字节用来判断"是否被截断"。
	limited := io.LimitReader(r.Body, int64(maxRaw)+1)
	n, err := io.Copy(appendWriter{&buf}, limited)
	if err != nil && !errors.Is(err, io.EOF) {
		errs = append(errs, "读取请求体失败："+err.Error())
	}
	buf = buf[:n]
	truncated = n > int64(maxRaw)

	// 注意：**已读出来的字节一个都不能丢**。转发用的 MultiReader 里放全部 buf，
	// 只有参与检测的那一份才截断到 maxRaw —— 否则会少转发一个字节，上游拿到坏 body。
	sc.Body = buf
	r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), r.Body))

	inspectSrc := buf
	if truncated {
		inspectSrc = buf[:maxRaw]
	}

	inspect = inspectSrc
	if enc := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))); enc != "" && enc != "identity" {
		dec, decErr := decompress(enc, inspectSrc, sc, maxRaw)
		if decErr != nil {
			errs = append(errs, "解压请求体失败("+enc+")："+decErr.Error())
			// 解压失败就用原始字节继续检测 —— 绝不因为解压失败就放弃检查。
		} else {
			inspect = dec
		}
	}
	return buf, inspect, truncated, errs
}

// appendWriter 让 io.Copy 直接写进切片，省掉一次 bytes.Buffer 分配。
type appendWriter struct{ dst *[]byte }

func (w appendWriter) Write(p []byte) (int, error) {
	*w.dst = append(*w.dst, p...)
	return len(p), nil
}

// decompress 按 Content-Encoding 解压，输出上限同样是 maxOut。
//
// 解压炸弹的防护靠"只读出需要的量"：LimitReader 让 CPU 与内存都只花在
// 我们真正会检查的字节上。
func decompress(enc string, src []byte, sc *Scratch, maxOut int) ([]byte, error) {
	var r io.Reader
	switch enc {
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(src))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		r = zr
	case "deflate":
		fr := flate.NewReader(bytes.NewReader(src))
		defer fr.Close()
		r = fr
	default:
		// br / zstd 等需要额外依赖。**不假装能检查**：
		// 返回错误，让上层记录 parse_error 并计分（P3），而不是静默漏检。
		return nil, errors.New("不支持的 Content-Encoding：" + enc)
	}

	sc.Inspect = sc.Inspect[:0]
	buf := sc.Inspect
	if cap(buf) < maxOut {
		buf = make([]byte, 0, maxOut)
	}
	n, err := io.Copy(appendWriter{&buf}, io.LimitReader(r, int64(maxOut)))
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	buf = buf[:n]
	sc.Inspect = buf
	return buf, nil
}

// jsonWalker 复用路径栈，避免每个节点都分配一条路径。
type jsonWalker struct {
	sc    *Scratch
	nodes int
	lim   Limits
}

// ParseJSONInto 把 JSON 文档递归展开成 <路径> = <叶子值> 的参数集合。
//
// 键路径用点号连接（数组用 [i]），例如 user.name、items[0].id。
// 这样规则不需要知道嵌套结构，对着扁平命名空间匹配即可 ——
// 攻击者把 payload 塞进三层嵌套数组也逃不掉。
func ParseJSONInto(dst *tx.Params, sc *Scratch, body []byte, lim Limits) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()

	w := &jsonWalker{sc: sc, lim: lim}
	sc.Path = sc.Path[:0]
	return w.walk(dec, dst, 0)
}

func (w *jsonWalker) walk(dec *json.Decoder, dst *tx.Params, depth int) error {
	if depth > w.lim.MaxJSONDepth {
		return skipValue(dec)
	}
	tok, err := dec.Token()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}

	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return err
				}
				key, _ := keyTok.(string)
				restore := w.push(key)
				if err := w.walk(dec, dst, depth+1); err != nil {
					return err
				}
				w.pop(restore)
			}
			_, err := dec.Token() // 吃掉 '}'
			return err
		case '[':
			idx := 0
			for dec.More() {
				restore := w.pushIndex(idx)
				if err := w.walk(dec, dst, depth+1); err != nil {
					return err
				}
				w.pop(restore)
				idx++
			}
			_, err := dec.Token() // 吃掉 ']'
			return err
		}
	case string:
		w.addLeaf(dst, t)
	case json.Number:
		w.addLeaf(dst, t.String())
	case bool:
		if t {
			w.addLeaf(dst, "true")
		} else {
			w.addLeaf(dst, "false")
		}
	case nil:
		w.addLeaf(dst, "")
	}
	return nil
}

func (w *jsonWalker) addLeaf(dst *tx.Params, val string) {
	w.nodes++
	if w.nodes > w.lim.MaxJSONNodes {
		dst.MarkTruncated()
		return
	}
	if len(val) > w.lim.MaxParamValLen {
		val = val[:w.lim.MaxParamValLen]
		dst.MarkTooLong()
	}
	dst.AddKeyBytes(w.sc.Path, val)
}

func (w *jsonWalker) push(key string) int {
	restore := len(w.sc.Path)
	if restore > 0 {
		w.sc.Path = append(w.sc.Path, '.')
	}
	w.sc.Path = append(w.sc.Path, key...)
	return restore
}

func (w *jsonWalker) pushIndex(i int) int {
	restore := len(w.sc.Path)
	w.sc.Path = append(w.sc.Path, '[')
	w.sc.Path = strconv.AppendInt(w.sc.Path, int64(i), 10)
	w.sc.Path = append(w.sc.Path, ']')
	return restore
}

func (w *jsonWalker) pop(restore int) { w.sc.Path = w.sc.Path[:restore] }

// skipValue 丢弃一个完整的值（用于超深度时保持解析器位置正确）。
func skipValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); ok && (d == '{' || d == '[') {
		depth := 1
		for depth > 0 {
			t, err := dec.Token()
			if err != nil {
				return err
			}
			if dd, ok := t.(json.Delim); ok {
				switch dd {
				case '{', '[':
					depth++
				case '}', ']':
					depth--
				}
			}
		}
	}
	return nil
}

// ParseXMLInto 把 XML 的文本节点与属性展开成参数（路径形如 root.item、root.item@id）。
//
// 返回值 hasDTD 表示文档里出现了 DOCTYPE / ENTITY 声明 —— 标准库的
// encoding/xml 不会去解析外部实体（不会真的去读文件或发请求），
// 但 DTD 声明本身正是 XXE 的载荷特征，所以如实报出来，交给规则记分。
func ParseXMLInto(dst *tx.Params, sc *Scratch, body []byte, lim Limits) (hasDTD bool, err error) {
	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.Strict = true

	sc.Path = sc.Path[:0]
	depth := 0
	nodes := 0

	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return hasDTD, nil
			}
			return hasDTD, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth > lim.MaxJSONDepth {
				if err := dec.Skip(); err != nil {
					return hasDTD, err
				}
				depth--
				continue
			}
			// 先把元素名压进路径，再处理属性 —— 这样属性键是
			// "root.user@id"（元素自己的路径），而不是父元素的路径。
			if len(sc.Path) > 0 {
				sc.Path = append(sc.Path, '.')
			}
			sc.Path = append(sc.Path, t.Name.Local...)

			for _, a := range t.Attr {
				key := make([]byte, 0, len(sc.Path)+1+len(a.Name.Local))
				key = append(key, sc.Path...)
				key = append(key, '@')
				key = append(key, a.Name.Local...)
				val := a.Value
				if len(val) > lim.MaxParamValLen {
					val = val[:lim.MaxParamValLen]
					dst.MarkTooLong()
				}
				dst.AddString(string(key), val)
			}
		case xml.EndElement:
			depth--
			if i := lastIndexByte(sc.Path, '.'); i >= 0 {
				sc.Path = sc.Path[:i]
			} else {
				sc.Path = sc.Path[:0]
			}
		case xml.CharData:
			v := bytes.TrimSpace(t)
			if len(v) == 0 {
				continue
			}
			nodes++
			if nodes > lim.MaxJSONNodes {
				dst.MarkTruncated()
				continue
			}
			if len(v) > lim.MaxParamValLen {
				v = v[:lim.MaxParamValLen]
				dst.MarkTooLong()
			}
			dst.Add(sc.Path, v)
		case xml.Directive:
			up := bytes.ToUpper(t)
			if bytes.Contains(up, []byte("DOCTYPE")) || bytes.Contains(up, []byte("ENTITY")) {
				hasDTD = true
			}
		case xml.ProcInst, xml.Comment:
			// 忽略
		}
	}
}

// lastIndexByte 从右往左找字节（避免为了这一步引入 strings 之外的语义）。
func lastIndexByte(b []byte, c byte) int {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// ParseBase64DocInto 处理"参数值本身是一段文档"的情况。
//
// 这是 crackweb 的"编码后的参数文档"手法：外层参数看起来是一串 base64，
// 解开之后是个 JSON，payload 藏在 JSON 的某个字段里。只检查外层值会漏掉。
func ParseBase64DocInto(dst *tx.Params, sc *Scratch, key string, val []byte, lim Limits, depth int) bool {
	if depth > lim.MaxNestedDecode || len(val) == 0 || len(val) > 32<<10 {
		return false
	}
	if !looksBase64(val) {
		return false
	}
	sc.Aux = sc.Aux[:0]
	decoded, err := base64.StdEncoding.AppendDecode(sc.Aux, val)
	if err != nil {
		decoded, err = base64.RawStdEncoding.AppendDecode(sc.Aux, val)
		if err != nil {
			return false
		}
	}
	sc.Aux = decoded
	trimmed := bytes.TrimSpace(decoded)
	if len(trimmed) == 0 {
		return false
	}
	// 解开后是 JSON：按 <外层键>.<内层路径> 展开
	if trimmed[0] == '{' || trimmed[0] == '[' {
		sub := tx.Params{}
		subScratch := &Scratch{Path: append([]byte(nil), key...)}
		if err := ParseJSONInto(&sub, subScratch, trimmed, lim); err != nil {
			return false
		}
		for i := 0; i < sub.Len(); i++ {
			dst.Add(sub.KeyAt(i), sub.ValueAt(i))
		}
		return true
	}
	// 解开后是普通文本：作为派生值加进去（键名带 ~b64 后缀，规则可识别）
	if isMostlyPrintable(trimmed) {
		if len(trimmed) > lim.MaxParamValLen {
			trimmed = trimmed[:lim.MaxParamValLen]
			dst.MarkTooLong()
		}
		derived := append(append([]byte(nil), key...), "~b64"...)
		dst.Add(derived, trimmed)
		return true
	}
	return false
}

// looksBase64 做轻量判断：只接受 base64 字符集且长度合理。
func looksBase64(b []byte) bool {
	if len(b) < 8 {
		return false
	}
	for _, c := range b {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '+', c == '/', c == '=', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

func isMostlyPrintable(b []byte) bool {
	printable := 0
	for _, c := range b {
		if c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c < 0x7f) || c >= 0x80 {
			printable++
		}
	}
	return printable*10 >= len(b)*9
}

// ParseMultipartInto 解析 multipart/form-data。
//
// 普通字段进 params；文件部分**只读头部 16 字节与大小**，不落盘、不整份读入内存 ——
// 低配机器上一个 100MB 的上传就能把内存吃穿。
func ParseMultipartInto(params *tx.Params, files *tx.FileSet, contentType string, body []byte, lim Limits) error {
	_, ps, err := mime.ParseMediaType(contentType)
	if err != nil {
		return err
	}
	boundary := ps["boundary"]
	if boundary == "" {
		return errors.New("multipart 缺少 boundary")
	}

	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	for i := 0; i < lim.MaxParams; i++ {
		part, err := mr.NextPart()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		name := part.FormName()
		filename := part.FileName()
		// Go 的 FileName() 会把目录部分剥掉（filepath.Base）。对 WAF 来说
		// **原始文件名本身就是要检测的输入** —— "../../shell.php.jpg" 里的
		// 穿越与双扩展名都得能被规则看到，所以另外从 Content-Disposition 取原值。
		rawFilename := filename
		if _, cdp, err := mime.ParseMediaType(part.Header.Get("Content-Disposition")); err == nil {
			if v, ok := cdp["filename"]; ok && v != "" {
				rawFilename = v
			}
		}
		if rawFilename == "" {
			val, err := io.ReadAll(io.LimitReader(part, int64(lim.MaxParamValLen)+1))
			_ = part.Close()
			if err != nil {
				return err
			}
			if len(val) > lim.MaxParamValLen {
				val = val[:lim.MaxParamValLen]
				params.MarkTooLong()
			}
			params.AddString(name, string(val))
			continue
		}

		// 文件：只取魔数 + 统计大小
		meta := tx.FileMeta{
			FieldName:   name,
			FileName:    rawFilename,
			ContentType: part.Header.Get("Content-Type"),
		}
		if _, err := io.ReadFull(part, meta.Magic[:]); err == nil {
			meta.MagicLen = len(meta.Magic)
		} else {
			meta.MagicLen = 0
		}
		n, _ := io.Copy(io.Discard, io.LimitReader(part, int64(lim.MaxParamValLen)*8))
		meta.Size = n
		_ = part.Close()
		if *files == nil {
			*files = tx.FileSet{}
		}
		(*files)[name] = append((*files)[name], meta)
	}
	params.MarkTruncated()
	return nil
}
