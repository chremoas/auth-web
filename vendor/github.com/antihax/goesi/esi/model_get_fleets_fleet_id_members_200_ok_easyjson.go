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

func easyjson3a1ded9fDecodeGithubComAntihaxGoesiEsi(in *jlexer.Lexer, out *GetFleetsFleetIdMembers200OkList) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		in.Skip()
		*out = nil
	} else {
		in.Delim('[')
		if *out == nil {
			if !in.IsDelim(']') {
				*out = make(GetFleetsFleetIdMembers200OkList, 0, 1)
			} else {
				*out = GetFleetsFleetIdMembers200OkList{}
			}
		} else {
			*out = (*out)[:0]
		}
		for !in.IsDelim(']') {
			var v1 GetFleetsFleetIdMembers200Ok
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
func easyjson3a1ded9fEncodeGithubComAntihaxGoesiEsi(out *jwriter.Writer, in GetFleetsFleetIdMembers200OkList) {
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
func (v GetFleetsFleetIdMembers200OkList) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjson3a1ded9fEncodeGithubComAntihaxGoesiEsi(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v GetFleetsFleetIdMembers200OkList) MarshalEasyJSON(w *jwriter.Writer) {
	easyjson3a1ded9fEncodeGithubComAntihaxGoesiEsi(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *GetFleetsFleetIdMembers200OkList) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjson3a1ded9fDecodeGithubComAntihaxGoesiEsi(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *GetFleetsFleetIdMembers200OkList) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjson3a1ded9fDecodeGithubComAntihaxGoesiEsi(l, v)
}
func easyjson3a1ded9fDecodeGithubComAntihaxGoesiEsi1(in *jlexer.Lexer, out *GetFleetsFleetIdMembers200Ok) {
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
		case "character_id":
			out.CharacterId = int32(in.Int32())
		case "join_time":
			if data := in.Raw(); in.Ok() {
				in.AddError((out.JoinTime).UnmarshalJSON(data))
			}
		case "role":
			out.Role = string(in.String())
		case "role_name":
			out.RoleName = string(in.String())
		case "ship_type_id":
			out.ShipTypeId = int32(in.Int32())
		case "solar_system_id":
			out.SolarSystemId = int32(in.Int32())
		case "squad_id":
			out.SquadId = int64(in.Int64())
		case "station_id":
			out.StationId = int64(in.Int64())
		case "takes_fleet_warp":
			out.TakesFleetWarp = bool(in.Bool())
		case "wing_id":
			out.WingId = int64(in.Int64())
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
func easyjson3a1ded9fEncodeGithubComAntihaxGoesiEsi1(out *jwriter.Writer, in GetFleetsFleetIdMembers200Ok) {
	out.RawByte('{')
	first := true
	_ = first
	if in.CharacterId != 0 {
		const prefix string = ",\"character_id\":"
		first = false
		out.RawString(prefix[1:])
		out.Int32(int32(in.CharacterId))
	}
	if true {
		const prefix string = ",\"join_time\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Raw((in.JoinTime).MarshalJSON())
	}
	if in.Role != "" {
		const prefix string = ",\"role\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Role))
	}
	if in.RoleName != "" {
		const prefix string = ",\"role_name\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.RoleName))
	}
	if in.ShipTypeId != 0 {
		const prefix string = ",\"ship_type_id\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Int32(int32(in.ShipTypeId))
	}
	if in.SolarSystemId != 0 {
		const prefix string = ",\"solar_system_id\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Int32(int32(in.SolarSystemId))
	}
	if in.SquadId != 0 {
		const prefix string = ",\"squad_id\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Int64(int64(in.SquadId))
	}
	if in.StationId != 0 {
		const prefix string = ",\"station_id\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Int64(int64(in.StationId))
	}
	if in.TakesFleetWarp {
		const prefix string = ",\"takes_fleet_warp\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Bool(bool(in.TakesFleetWarp))
	}
	if in.WingId != 0 {
		const prefix string = ",\"wing_id\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Int64(int64(in.WingId))
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v GetFleetsFleetIdMembers200Ok) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjson3a1ded9fEncodeGithubComAntihaxGoesiEsi1(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v GetFleetsFleetIdMembers200Ok) MarshalEasyJSON(w *jwriter.Writer) {
	easyjson3a1ded9fEncodeGithubComAntihaxGoesiEsi1(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *GetFleetsFleetIdMembers200Ok) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjson3a1ded9fDecodeGithubComAntihaxGoesiEsi1(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *GetFleetsFleetIdMembers200Ok) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjson3a1ded9fDecodeGithubComAntihaxGoesiEsi1(l, v)
}
