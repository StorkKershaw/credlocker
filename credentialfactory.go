package credlocker

import (
	"syscall"
	"unsafe"

	"github.com/go-ole/go-ole"
)

var (
	IID_ICredentialFactory = ole.NewGUID("54EF13A1-BF26-47B5-97DD-DE779B7CAD58")
)

type ICredentialFactory struct {
	ole.IInspectable
}

type ICredentialFactoryVtbl struct {
	ole.IInspectableVtbl
	CreatePasswordCredential uintptr
}

func (i *ICredentialFactory) VTable() *ICredentialFactoryVtbl {
	return (*ICredentialFactoryVtbl)(unsafe.Pointer(i.RawVTable))
}

type CredentialFactory struct {
	factory *ICredentialFactory
}

func ToCredentialFactory(ins *ole.IInspectable) (*CredentialFactory, error) {
	return &CredentialFactory{
		factory: (*ICredentialFactory)(unsafe.Pointer(ins)),
	}, nil
}

func (p *CredentialFactory) Release() {
	if p.factory != nil {
		p.factory.Release()
		p.factory = nil
	}
}

func (p *CredentialFactory) CreatePasswordCredential(resource, username, password string) (*PasswordCredential, error) {
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

	hPassword, err := ole.NewHString(password)
	if err != nil {
		return nil, err
	}
	defer ole.DeleteHString(hPassword)

	var ins *ole.IInspectable
	hr, _, _ := syscall.SyscallN(
		p.factory.VTable().CreatePasswordCredential,
		uintptr(unsafe.Pointer(p.factory)),
		uintptr(unsafe.Pointer(hResource)),
		uintptr(unsafe.Pointer(hUsername)),
		uintptr(unsafe.Pointer(hPassword)),
		uintptr(unsafe.Pointer(&ins)),
	)

	if hr != 0 {
		return nil, ole.NewError(hr)
	}

	return ToPasswordCredential(ins)
}
