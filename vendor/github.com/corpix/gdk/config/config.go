package config

import (
	"github.com/corpix/revip"
)

type (
	Config              = revip.Config
	Defaultable         = revip.Defaultable
	ErrFileNotFound     = revip.ErrFileNotFound
	ErrMarshal          = revip.ErrMarshal
	ErrPathNotFound     = revip.ErrPathNotFound
	ErrPostprocess      = revip.ErrPostprocess
	ErrUnexpectedKind   = revip.ErrUnexpectedKind
	ErrUnexpectedScheme = revip.ErrUnexpectedScheme
	ErrUnmarshal        = revip.ErrUnmarshal
	Expandable          = revip.Expandable
	Marshaler           = revip.Marshaler
	Unmarshaler         = revip.Unmarshaler
	SourceOption        = revip.SourceOption
	DestinationOption   = revip.DestinationOption
	PostprocessOption   = revip.PostprocessOption
	Container           = revip.Container
	Validatable         = revip.Validatable
)

var (
	FromEnviron = revip.FromEnviron
	FromFile    = revip.FromFile
	FromReader  = revip.FromReader
	FromURL     = revip.FromURL
	Load        = revip.Load
	New         = revip.New
	Postprocess = revip.Postprocess

	ToFile   = revip.ToFile
	ToURL    = revip.ToURL
	ToWriter = revip.ToWriter

	WithNoNilPointers = revip.WithNoNilPointers
	WithDefaults      = revip.WithDefaults
	WithExpansion     = revip.WithExpansion
	WithValidation    = revip.WithValidation

	JsonMarshaler   = revip.JsonMarshaler
	JsonUnmarshaler = revip.JsonUnmarshaler
	YamlMarshaler   = revip.YamlMarshaler
	YamlUnmarshaler = revip.YamlUnmarshaler
	TomlMarshaler   = revip.TomlMarshaler
	TomlUnmarshaler = revip.TomlUnmarshaler
)
