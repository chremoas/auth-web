// Code generated by easyjson for marshaling/unmarshaling. DO NOT EDIT.

package meta

import (
	json "encoding/json"

	easyjson "github.com/mailru/easyjson"
	jlexer "github.com/mailru/easyjson/jlexer"
	jwriter "github.com/mailru/easyjson/jwriter"
)

// suppress unused package warning
var (
	_ *json.RawMessage
	_ *jlexer.Lexer
	_ *jwriter.Writer
	_ easyjson.Marshaler
)

func easyjsonAdaad56dDecodeGithubComAntihaxGoesiMeta(in *jlexer.Lexer, out *GetVerifyNotFoundList) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		in.Skip()
		*out = nil
	} else {
		in.Delim('[')
		if *out == nil {
			if !in.IsDelim(']') {
				*out = make(GetVerifyNotFoundList, 0, 4)
			} else {
				*out = GetVerifyNotFoundList{}
			}
		} else {
			*out = (*out)[:0]
		}
		for !in.IsDelim(']') {
			var v1 GetVerifyNotFound
			(v1).UnmarshalEasyJSON(in)
			*out = append(*out, v1)
			in.WantComma()
		}
		in.Delim(']')
	}
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonAdaad56dEncodeGithubComAntihaxGoesiMeta(out *jwriter.Writer, in GetVerifyNotFoundList) {
	if in == nil && (out.Flags&jwriter.NilSliceAsEmpty) == 0 {
		out.RawString("null")
	} else {
		out.RawByte('[')
		for v2, v3 := range in {
			if v2 > 0 {
				out.RawByte(',')
			}
			(v3).MarshalEasyJSON(out)
		}
		out.RawByte(']')
	}
}

// MarshalJSON supports json.Marshaler interface
func (v GetVerifyNotFoundList) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjsonAdaad56dEncodeGithubComAntihaxGoesiMeta(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v GetVerifyNotFoundList) MarshalEasyJSON(w *jwriter.Writer) {
	easyjsonAdaad56dEncodeGithubComAntihaxGoesiMeta(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *GetVerifyNotFoundList) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjsonAdaad56dDecodeGithubComAntihaxGoesiMeta(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *GetVerifyNotFoundList) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjsonAdaad56dDecodeGithubComAntihaxGoesiMeta(l, v)
}
func easyjsonAdaad56dDecodeGithubComAntihaxGoesiMeta1(in *jlexer.Lexer, out *GetVerifyNotFound) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeString()
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "error":
			out.Error_ = string(in.String())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonAdaad56dEncodeGithubComAntihaxGoesiMeta1(out *jwriter.Writer, in GetVerifyNotFound) {
	out.RawByte('{')
	first := true
	_ = first
	if in.Error_ != "" {
		const prefix string = ",\"error\":"
		first = false
		out.RawString(prefix[1:])
		out.String(string(in.Error_))
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v GetVerifyNotFound) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjsonAdaad56dEncodeGithubComAntihaxGoesiMeta1(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v GetVerifyNotFound) MarshalEasyJSON(w *jwriter.Writer) {
	easyjsonAdaad56dEncodeGithubComAntihaxGoesiMeta1(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *GetVerifyNotFound) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjsonAdaad56dDecodeGithubComAntihaxGoesiMeta1(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *GetVerifyNotFound) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjsonAdaad56dDecodeGithubComAntihaxGoesiMeta1(l, v)
}
