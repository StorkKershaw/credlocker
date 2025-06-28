package credlocker

import (
	"syscall"
	"unsafe"

	"github.com/go-ole/go-ole"
)

const (
	PasswordCredentialClass = "Windows.Security.Credentials.PasswordCredential"
)

var (
	IID_IPasswordCredential = ole.NewGUID("6AB18989-C720-41A7-A6C1-FEADB36329A0")
)

type IPasswordCredential struct {
	ole.IInspectable
}

type IPasswordCredentialVtbl struct {
	ole.IInspectableVtbl
	Resource         uintptr
	SetResource      uintptr
	Username         uintptr
	SetUsername      uintptr
	Password         uintptr
	SetPassword      uintptr
	RetrievePassword uintptr
	Properties       uintptr
}

func (i *IPasswordCredential) VTable() *IPasswordCredentialVtbl {
	return (*IPasswordCredentialVtbl)(unsafe.Pointer(i.RawVTable))
}

type PasswordCredential struct {
	credential *IPasswordCredential
}

func ToPasswordCredential(ins *ole.IInspectable) (*PasswordCredential, error) {
	return &PasswordCredential{
		credential: (*IPasswordCredential)(unsafe.Pointer(ins)),
	}, nil
}

func NewPasswordCredential(resource, username, password string) (*PasswordCredential, error) {
	ins, err := ole.RoGetActivationFactory(PasswordCredentialClass, IID_ICredentialFactory)
	if err != nil {
		return nil, err
	}

	factory, err := ToCredentialFactory(ins)
	if err != nil {
		return nil, err
	}

	return factory.CreatePasswordCredential(resource, username, password)
}

func (p *PasswordCredential) Release() {
	if p.credential != nil {
		p.credential.Release()
		p.credential = nil
	}
}

func (p *PasswordCredential) Resource() (string, error) {
	var hResource ole.HString
	hr, _, _ := syscall.SyscallN(
		p.credential.VTable().Resource,
		uintptr(unsafe.Pointer(p.credential)),
		uintptr(unsafe.Pointer(&hResource)),
	)
	if hr != 0 {
		return "", ole.NewError(hr)
	}
	defer ole.DeleteHString(hResource)

	return hResource.String(), nil
}

func (p *PasswordCredential) Username() (string, error) {
	var hUsername ole.HString
	hr, _, _ := syscall.SyscallN(
		p.credential.VTable().Username,
		uintptr(unsafe.Pointer(p.credential)),
		uintptr(unsafe.Pointer(&hUsername)),
	)
	if hr != 0 {
		return "", ole.NewError(hr)
	}
	defer ole.DeleteHString(hUsername)

	return hUsername.String(), nil
}

func (p *PasswordCredential) Password() (string, error) {
	var hPassword ole.HString
	hr, _, _ := syscall.SyscallN(
		p.credential.VTable().Password,
		uintptr(unsafe.Pointer(p.credential)),
		uintptr(unsafe.Pointer(&hPassword)),
	)
	if hr != 0 {
		return "", ole.NewError(hr)
	}
	defer ole.DeleteHString(hPassword)

	return hPassword.String(), nil
}

func (p *PasswordCredential) RetrievePassword() error {
	hr, _, _ := syscall.SyscallN(
		p.credential.VTable().RetrievePassword,
		uintptr(unsafe.Pointer(p.credential)),
	)
	if hr != 0 {
		return ole.NewError(hr)
	}
	return nil
}
