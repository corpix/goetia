package encoding

import (
	"encoding/base64"
)

type (
	EncodeDecoder interface {
		Encode([]byte) ([]byte, error)
		Decode([]byte) ([]byte, error)
	}
	EncodeDecoderBase64 struct {
		*base64.Encoding
	}
)

var (
	_ EncodeDecoder = &EncodeDecoderBase64{}
)

//

func (e *EncodeDecoderBase64) Encode(buf []byte) ([]byte, error) {
	dst := make([]byte, e.Encoding.EncodedLen(len(buf)))
	e.Encoding.Encode(dst, buf)
	return dst, nil
}

func (e *EncodeDecoderBase64) Decode(buf []byte) ([]byte, error) {
	dst := make([]byte, e.Encoding.DecodedLen(len(buf)))
	n, err := e.Encoding.Decode(dst, buf)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

func NewEncodeDecoderBase64() *EncodeDecoderBase64 {
	return &EncodeDecoderBase64{Encoding: base64.StdEncoding}
}
