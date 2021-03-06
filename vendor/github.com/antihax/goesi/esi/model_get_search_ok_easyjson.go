// Code generated by easyjson for marshaling/unmarshaling. DO NOT EDIT.

package esi

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

func easyjsonE70f86d0DecodeGithubComAntihaxGoesiEsi(in *jlexer.Lexer, out *GetSearchOkList) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		in.Skip()
		*out = nil
	} else {
		in.Delim('[')
		if *out == nil {
			if !in.IsDelim(']') {
				*out = make(GetSearchOkList, 0, 1)
			} else {
				*out = GetSearchOkList{}
			}
		} else {
			*out = (*out)[:0]
		}
		for !in.IsDelim(']') {
			var v1 GetSearchOk
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
func easyjsonE70f86d0EncodeGithubComAntihaxGoesiEsi(out *jwriter.Writer, in GetSearchOkList) {
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
func (v GetSearchOkList) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjsonE70f86d0EncodeGithubComAntihaxGoesiEsi(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v GetSearchOkList) MarshalEasyJSON(w *jwriter.Writer) {
	easyjsonE70f86d0EncodeGithubComAntihaxGoesiEsi(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *GetSearchOkList) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjsonE70f86d0DecodeGithubComAntihaxGoesiEsi(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *GetSearchOkList) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjsonE70f86d0DecodeGithubComAntihaxGoesiEsi(l, v)
}
func easyjsonE70f86d0DecodeGithubComAntihaxGoesiEsi1(in *jlexer.Lexer, out *GetSearchOk) {
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
		case "agent":
			if in.IsNull() {
				in.Skip()
				out.Agent = nil
			} else {
				in.Delim('[')
				if out.Agent == nil {
					if !in.IsDelim(']') {
						out.Agent = make([]int32, 0, 16)
					} else {
						out.Agent = []int32{}
					}
				} else {
					out.Agent = (out.Agent)[:0]
				}
				for !in.IsDelim(']') {
					var v4 int32
					v4 = int32(in.Int32())
					out.Agent = append(out.Agent, v4)
					in.WantComma()
				}
				in.Delim(']')
			}
		case "alliance":
			if in.IsNull() {
				in.Skip()
				out.Alliance = nil
			} else {
				in.Delim('[')
				if out.Alliance == nil {
					if !in.IsDelim(']') {
						out.Alliance = make([]int32, 0, 16)
					} else {
						out.Alliance = []int32{}
					}
				} else {
					out.Alliance = (out.Alliance)[:0]
				}
				for !in.IsDelim(']') {
					var v5 int32
					v5 = int32(in.Int32())
					out.Alliance = append(out.Alliance, v5)
					in.WantComma()
				}
				in.Delim(']')
			}
		case "character":
			if in.IsNull() {
				in.Skip()
				out.Character = nil
			} else {
				in.Delim('[')
				if out.Character == nil {
					if !in.IsDelim(']') {
						out.Character = make([]int32, 0, 16)
					} else {
						out.Character = []int32{}
					}
				} else {
					out.Character = (out.Character)[:0]
				}
				for !in.IsDelim(']') {
					var v6 int32
					v6 = int32(in.Int32())
					out.Character = append(out.Character, v6)
					in.WantComma()
				}
				in.Delim(']')
			}
		case "constellation":
			if in.IsNull() {
				in.Skip()
				out.Constellation = nil
			} else {
				in.Delim('[')
				if out.Constellation == nil {
					if !in.IsDelim(']') {
						out.Constellation = make([]int32, 0, 16)
					} else {
						out.Constellation = []int32{}
					}
				} else {
					out.Constellation = (out.Constellation)[:0]
				}
				for !in.IsDelim(']') {
					var v7 int32
					v7 = int32(in.Int32())
					out.Constellation = append(out.Constellation, v7)
					in.WantComma()
				}
				in.Delim(']')
			}
		case "corporation":
			if in.IsNull() {
				in.Skip()
				out.Corporation = nil
			} else {
				in.Delim('[')
				if out.Corporation == nil {
					if !in.IsDelim(']') {
						out.Corporation = make([]int32, 0, 16)
					} else {
						out.Corporation = []int32{}
					}
				} else {
					out.Corporation = (out.Corporation)[:0]
				}
				for !in.IsDelim(']') {
					var v8 int32
					v8 = int32(in.Int32())
					out.Corporation = append(out.Corporation, v8)
					in.WantComma()
				}
				in.Delim(']')
			}
		case "faction":
			if in.IsNull() {
				in.Skip()
				out.Faction = nil
			} else {
				in.Delim('[')
				if out.Faction == nil {
					if !in.IsDelim(']') {
						out.Faction = make([]int32, 0, 16)
					} else {
						out.Faction = []int32{}
					}
				} else {
					out.Faction = (out.Faction)[:0]
				}
				for !in.IsDelim(']') {
					var v9 int32
					v9 = int32(in.Int32())
					out.Faction = append(out.Faction, v9)
					in.WantComma()
				}
				in.Delim(']')
			}
		case "inventory_type":
			if in.IsNull() {
				in.Skip()
				out.InventoryType = nil
			} else {
				in.Delim('[')
				if out.InventoryType == nil {
					if !in.IsDelim(']') {
						out.InventoryType = make([]int32, 0, 16)
					} else {
						out.InventoryType = []int32{}
					}
				} else {
					out.InventoryType = (out.InventoryType)[:0]
				}
				for !in.IsDelim(']') {
					var v10 int32
					v10 = int32(in.Int32())
					out.InventoryType = append(out.InventoryType, v10)
					in.WantComma()
				}
				in.Delim(']')
			}
		case "region":
			if in.IsNull() {
				in.Skip()
				out.Region = nil
			} else {
				in.Delim('[')
				if out.Region == nil {
					if !in.IsDelim(']') {
						out.Region = make([]int32, 0, 16)
					} else {
						out.Region = []int32{}
					}
				} else {
					out.Region = (out.Region)[:0]
				}
				for !in.IsDelim(']') {
					var v11 int32
					v11 = int32(in.Int32())
					out.Region = append(out.Region, v11)
					in.WantComma()
				}
				in.Delim(']')
			}
		case "solar_system":
			if in.IsNull() {
				in.Skip()
				out.SolarSystem = nil
			} else {
				in.Delim('[')
				if out.SolarSystem == nil {
					if !in.IsDelim(']') {
						out.SolarSystem = make([]int32, 0, 16)
					} else {
						out.SolarSystem = []int32{}
					}
				} else {
					out.SolarSystem = (out.SolarSystem)[:0]
				}
				for !in.IsDelim(']') {
					var v12 int32
					v12 = int32(in.Int32())
					out.SolarSystem = append(out.SolarSystem, v12)
					in.WantComma()
				}
				in.Delim(']')
			}
		case "station":
			if in.IsNull() {
				in.Skip()
				out.Station = nil
			} else {
				in.Delim('[')
				if out.Station == nil {
					if !in.IsDelim(']') {
						out.Station = make([]int32, 0, 16)
					} else {
						out.Station = []int32{}
					}
				} else {
					out.Station = (out.Station)[:0]
				}
				for !in.IsDelim(']') {
					var v13 int32
					v13 = int32(in.Int32())
					out.Station = append(out.Station, v13)
					in.WantComma()
				}
				in.Delim(']')
			}
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
func easyjsonE70f86d0EncodeGithubComAntihaxGoesiEsi1(out *jwriter.Writer, in GetSearchOk) {
	out.RawByte('{')
	first := true
	_ = first
	if len(in.Agent) != 0 {
		const prefix string = ",\"agent\":"
		first = false
		out.RawString(prefix[1:])
		{
			out.RawByte('[')
			for v14, v15 := range in.Agent {
				if v14 > 0 {
					out.RawByte(',')
				}
				out.Int32(int32(v15))
			}
			out.RawByte(']')
		}
	}
	if len(in.Alliance) != 0 {
		const prefix string = ",\"alliance\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		{
			out.RawByte('[')
			for v16, v17 := range in.Alliance {
				if v16 > 0 {
					out.RawByte(',')
				}
				out.Int32(int32(v17))
			}
			out.RawByte(']')
		}
	}
	if len(in.Character) != 0 {
		const prefix string = ",\"character\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		{
			out.RawByte('[')
			for v18, v19 := range in.Character {
				if v18 > 0 {
					out.RawByte(',')
				}
				out.Int32(int32(v19))
			}
			out.RawByte(']')
		}
	}
	if len(in.Constellation) != 0 {
		const prefix string = ",\"constellation\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		{
			out.RawByte('[')
			for v20, v21 := range in.Constellation {
				if v20 > 0 {
					out.RawByte(',')
				}
				out.Int32(int32(v21))
			}
			out.RawByte(']')
		}
	}
	if len(in.Corporation) != 0 {
		const prefix string = ",\"corporation\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		{
			out.RawByte('[')
			for v22, v23 := range in.Corporation {
				if v22 > 0 {
					out.RawByte(',')
				}
				out.Int32(int32(v23))
			}
			out.RawByte(']')
		}
	}
	if len(in.Faction) != 0 {
		const prefix string = ",\"faction\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		{
			out.RawByte('[')
			for v24, v25 := range in.Faction {
				if v24 > 0 {
					out.RawByte(',')
				}
				out.Int32(int32(v25))
			}
			out.RawByte(']')
		}
	}
	if len(in.InventoryType) != 0 {
		const prefix string = ",\"inventory_type\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		{
			out.RawByte('[')
			for v26, v27 := range in.InventoryType {
				if v26 > 0 {
					out.RawByte(',')
				}
				out.Int32(int32(v27))
			}
			out.RawByte(']')
		}
	}
	if len(in.Region) != 0 {
		const prefix string = ",\"region\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		{
			out.RawByte('[')
			for v28, v29 := range in.Region {
				if v28 > 0 {
					out.RawByte(',')
				}
				out.Int32(int32(v29))
			}
			out.RawByte(']')
		}
	}
	if len(in.SolarSystem) != 0 {
		const prefix string = ",\"solar_system\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		{
			out.RawByte('[')
			for v30, v31 := range in.SolarSystem {
				if v30 > 0 {
					out.RawByte(',')
				}
				out.Int32(int32(v31))
			}
			out.RawByte(']')
		}
	}
	if len(in.Station) != 0 {
		const prefix string = ",\"station\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		{
			out.RawByte('[')
			for v32, v33 := range in.Station {
				if v32 > 0 {
					out.RawByte(',')
				}
				out.Int32(int32(v33))
			}
			out.RawByte(']')
		}
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v GetSearchOk) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjsonE70f86d0EncodeGithubComAntihaxGoesiEsi1(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v GetSearchOk) MarshalEasyJSON(w *jwriter.Writer) {
	easyjsonE70f86d0EncodeGithubComAntihaxGoesiEsi1(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *GetSearchOk) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjsonE70f86d0DecodeGithubComAntihaxGoesiEsi1(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *GetSearchOk) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjsonE70f86d0DecodeGithubComAntihaxGoesiEsi1(l, v)
}
