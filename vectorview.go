package credlocker

import (
	"syscall"
	"unsafe"

	"github.com/go-ole/go-ole"
)

var (
	IID_IVectorView = ole.NewGUID("77E5B300-6A88-4F63-B490-E25B414BED4E")
)

type IVectorView struct {
	ole.IInspectable
}

type IVectorViewVtbl struct {
	ole.IInspectableVtbl
	GetAt   uintptr
	Size    uintptr
	IndexOf uintptr
	GetMany uintptr
}

func (i *IVectorView) VTable() *IVectorViewVtbl {
	return (*IVectorViewVtbl)(unsafe.Pointer(i.RawVTable))
}

type VectorView struct {
	vectorView *IVectorView
}

func ToVectorView(ins *ole.IInspectable) (*VectorView, error) {
	return &VectorView{
		vectorView: (*IVectorView)(unsafe.Pointer(ins)),
	}, nil
}

func (p *VectorView) Release() {
	if p.vectorView != nil {
		p.vectorView.Release()
		p.vectorView = nil
	}
}

func (p *VectorView) GetAt(index uint32) (*ole.IInspectable, error) {
	var ins *ole.IInspectable
	hr, _, _ := syscall.SyscallN(
		p.vectorView.VTable().GetAt,
		uintptr(unsafe.Pointer(p.vectorView)),
		uintptr(index),
		uintptr(unsafe.Pointer(&ins)),
	)

	if hr != 0 {
		return nil, ole.NewError(hr)
	}
	return ins, nil
}

func (p *VectorView) Size() (uint32, error) {
	var size uint32
	hr, _, _ := syscall.SyscallN(
		p.vectorView.VTable().Size,
		uintptr(unsafe.Pointer(p.vectorView)),
		uintptr(unsafe.Pointer(&size)),
	)

	if hr != 0 {
		return 0, ole.NewError(hr)
	}

	return size, nil
}
