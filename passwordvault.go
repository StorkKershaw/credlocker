package credlocker

import (
	"syscall"
	"unsafe"

	"github.com/go-ole/go-ole"
)

const (
	PasswordVaultClass = "Windows.Security.Credentials.PasswordVault"
)

var (
	IID_IPasswordVault = ole.NewGUID("61FD2C0B-C8D4-48C1-A54F-BC5A64205AF2")
)

type IPasswordVault struct {
	ole.IInspectable
}

type IPasswordVaultVtbl struct {
	ole.IInspectableVtbl
	Add               uintptr
	Remove            uintptr
	Retrieve          uintptr
	FindAllByResource uintptr
	FindAllByUsername uintptr
	RetrieveAll       uintptr
}

func (i *IPasswordVault) VTable() *IPasswordVaultVtbl {
	return (*IPasswordVaultVtbl)(unsafe.Pointer(i.RawVTable))
}

type PasswordVault struct {
	vault *IPasswordVault
}

func ToPasswordVault(ins *ole.IInspectable) (*PasswordVault, error) {
	return &PasswordVault{
		vault: (*IPasswordVault)(unsafe.Pointer(ins)),
	}, nil
}

func NewPasswordVault() (*PasswordVault, error) {
	ins, err := ole.RoActivateInstance(PasswordVaultClass)
	if err != nil {
		return nil, err
	}

	return ToPasswordVault(ins)
}

func (p *PasswordVault) Release() {
	if p.vault != nil {
		p.vault.Release()
		p.vault = nil
	}
}

func (p *PasswordVault) Add(credential *PasswordCredential) error {
	hr, _, _ := syscall.SyscallN(
		p.vault.VTable().Add,
		uintptr(unsafe.Pointer(p.vault)),
		uintptr(unsafe.Pointer(credential.credential)),
	)
	if hr != 0 {
		return ole.NewError(hr)
	}
	return nil
}

func (p *PasswordVault) Remove(credential *PasswordCredential) error {
	hr, _, _ := syscall.SyscallN(
		p.vault.VTable().Remove,
		uintptr(unsafe.Pointer(p.vault)),
		uintptr(unsafe.Pointer(credential.credential)),
	)
	if hr != 0 {
		return ole.NewError(hr)
	}
	return nil
}

func (p *PasswordVault) Retrieve(resource, username string) (*PasswordCredential, error) {
	hResource, err := ole.NewHString(resource)
	if err != nil {
		return nil, err
	}
	defer ole.DeleteHString(hResource)

	hUsername, err := ole.NewHString(username)
	if err != nil {
		return nil, err
	}
	defer ole.DeleteHString(hUsername)

	var ins *ole.IInspectable
	hr, _, _ := syscall.SyscallN(
		p.vault.VTable().Retrieve,
		uintptr(unsafe.Pointer(p.vault)),
		uintptr(unsafe.Pointer(hResource)),
		uintptr(unsafe.Pointer(hUsername)),
		uintptr(unsafe.Pointer(&ins)),
	)
	if hr != 0 {
		return nil, ole.NewError(hr)
	}

	return ToPasswordCredential(ins)
}

func (p *PasswordVault) FindAllByResource(resource string) (*VectorView, error) {
	hResource, err := ole.NewHString(resource)
	if err != nil {
		return nil, err
	}
	defer ole.DeleteHString(hResource)

	var ins *ole.IInspectable
	hr, _, _ := syscall.SyscallN(
		p.vault.VTable().FindAllByResource,
		uintptr(unsafe.Pointer(p.vault)),
		uintptr(unsafe.Pointer(hResource)),
		uintptr(unsafe.Pointer(&ins)),
	)
	if hr != 0 {
		return nil, ole.NewError(hr)
	}

	return ToVectorView(ins)
}

func (p *PasswordVault) FindAllByUsername(username string) (*VectorView, error) {
	hUsername, err := ole.NewHString(username)
	if err != nil {
		return nil, err
	}
	defer ole.DeleteHString(hUsername)

	var ins *ole.IInspectable
	hr, _, _ := syscall.SyscallN(
		p.vault.VTable().FindAllByUsername,
		uintptr(unsafe.Pointer(p.vault)),
		uintptr(unsafe.Pointer(hUsername)),
		uintptr(unsafe.Pointer(&ins)),
	)
	if hr != 0 {
		return nil, ole.NewError(hr)
	}

	return ToVectorView(ins)
}

func (p *PasswordVault) RetrieveAll() (*VectorView, error) {
	var ins *ole.IInspectable
	hr, _, _ := syscall.SyscallN(
		p.vault.VTable().RetrieveAll,
		uintptr(unsafe.Pointer(p.vault)),
		uintptr(unsafe.Pointer(&ins)),
	)
	if hr != 0 {
		return nil, ole.NewError(hr)
	}

	return ToVectorView(ins)
}
