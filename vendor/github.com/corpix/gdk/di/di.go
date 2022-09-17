package di

import (
	"go.uber.org/dig"
)

type (
	Container       = dig.Container
	DecorateInfo    = dig.DecorateInfo
	DecorateOption  = dig.DecorateOption
	Id              = dig.ID
	In              = dig.In
	Input           = dig.Input
	InvokeOption    = dig.InvokeOption
	Option          = dig.Option
	Out             = dig.Out
	Output          = dig.Output
	ProvideInfo     = dig.ProvideInfo
	ProvideOption   = dig.ProvideOption
	Scope           = dig.Scope
	ScopeOption     = dig.ScopeOption
	VisualizeOption = dig.VisualizeOption

	Constructor interface{}
	Function    interface{}
	Decorator   interface{}
)

var (
	IsCycleDetected          = dig.IsCycleDetected
	IsIn                     = dig.IsIn
	IsOut                    = dig.IsOut
	As                       = dig.As
	RootCause                = dig.RootCause
	Visualize                = dig.Visualize
	CanVisualizeError        = dig.CanVisualizeError
	VisualizeError           = dig.VisualizeError
	DeferAcyclicVerification = dig.DeferAcyclicVerification
	FillDecorateInfo         = dig.FillDecorateInfo
	DryRun                   = dig.DryRun
	Export                   = dig.Export
	FillProvideInfo          = dig.FillProvideInfo
	Group                    = dig.Group
	LocationForPC            = dig.LocationForPC
	Name                     = dig.Name
	New                      = dig.New

	Default = New()
)

//

func Provide(cont *Container, c Constructor, opts ...ProvideOption) error {
	return cont.Provide(c, opts...)
}

func MustProvide(cont *Container, c Constructor, opts ...ProvideOption) {
	err := Provide(cont, c, opts...)
	if err != nil {
		panic(err)
	}
}

func Invoke(cont *Container, f Function, opts ...InvokeOption) error {
	return cont.Invoke(f, opts...)
}

func MustInvoke(cont *Container, f Function, opts ...InvokeOption) {
	err := Invoke(cont, f, opts...)
	if err != nil {
		panic(err)
	}
}
