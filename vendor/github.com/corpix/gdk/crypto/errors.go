package crypto

type ErrDecrypt struct {
	Msg string
}

func (e ErrDecrypt) Error() string {
	return e.Msg
}

//

type ErrFormat struct {
	Msg string
}

func (e ErrFormat) Error() string {
	return e.Msg
}
